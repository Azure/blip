package blipfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/lease"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/pageblob"
)

// Store is a thin wrapper around one Azure blob container (one volume).
type Store struct {
	cc *container.Client
}

// NewStore connects with a connection string, or with an account URL and
// the default Azure credential chain (managed identity, CLI, env).
func NewStore(conn, accountURL, name string) (*Store, error) {
	opts := &container.ClientOptions{ClientOptions: azcore.ClientOptions{
		Retry: policy.RetryOptions{MaxRetries: 5, TryTimeout: 60 * time.Second, RetryDelay: 50 * time.Millisecond, MaxRetryDelay: 2 * time.Second},
	}}
	if conn != "" {
		cc, err := container.NewClientFromConnectionString(conn, name, opts)
		if err != nil {
			return nil, err
		}
		return &Store{cc: cc}, nil
	}
	if accountURL == "" {
		return nil, errors.New("need --conn or --account-url")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	cc, err := container.NewClient(strings.TrimRight(accountURL, "/")+"/"+name, cred, opts)
	if err != nil {
		return nil, err
	}
	return &Store{cc: cc}, nil
}

func isCode(err error, codes ...bloberror.Code) bool {
	return err != nil && bloberror.HasCode(err, codes...)
}

func isNotFound(err error) bool {
	var re *azcore.ResponseError
	return errors.As(err, &re) && re.StatusCode == http.StatusNotFound
}

// isFenced reports a 412 caused by a stale epoch (sequence number) or lost lease.
func isFenced(err error) bool {
	var re *azcore.ResponseError
	return errors.As(err, &re) && (re.StatusCode == http.StatusPreconditionFailed || re.StatusCode == http.StatusConflict && isCode(err, bloberror.LeaseIDMismatchWithBlobOperation, bloberror.LeaseIDMissing))
}

func (s *Store) CreateContainer(ctx context.Context) error {
	_, err := s.cc.Create(ctx, nil)
	if isCode(err, bloberror.ContainerAlreadyExists) {
		return nil
	}
	return err
}

func (s *Store) page(name string) *pageblob.Client   { return s.cc.NewPageBlobClient(name) }
func (s *Store) block(name string) *blockblob.Client { return s.cc.NewBlockBlobClient(name) }
func (s *Store) blob(name string) *blob.Client       { return s.cc.NewBlobClient(name) }

// CreatePage creates a sparse page blob unless it exists. Returns true if created.
func (s *Store) CreatePage(ctx context.Context, name string, size int64, seq int64, meta map[string]*string) (bool, error) {
	_, err := s.page(name).Create(ctx, size, &pageblob.CreateOptions{
		SequenceNumber:   to.Ptr(seq),
		Metadata:         meta,
		AccessConditions: &blob.AccessConditions{ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfNoneMatch: to.Ptr(azcore.ETagAny)}},
	})
	if isCode(err, bloberror.BlobAlreadyExists) || isFenced(err) {
		return false, nil // exists (412 LeaseIdMissing when it is leased)
	}
	return err == nil, err
}

func pad512(b []byte) []byte {
	if n := len(b) % 512; n != 0 {
		b = append(b, make([]byte, 512-n)...)
	}
	return b
}

// WritePages writes data (padded to 512 bytes) at off. If seq >= 0 the write
// is fenced on the blob sequence number; leaseID fences on a lease.
func (s *Store) WritePages(ctx context.Context, name string, off int64, data []byte, seq int64, leaseID string) error {
	data = pad512(data)
	for len(data) > 0 {
		n := min(len(data), 4<<20)
		o := &pageblob.UploadPagesOptions{}
		if seq >= 0 {
			o.SequenceNumberAccessConditions = &pageblob.SequenceNumberAccessConditions{IfSequenceNumberEqualTo: to.Ptr(seq)}
		}
		if leaseID != "" {
			o.AccessConditions = &blob.AccessConditions{LeaseAccessConditions: &blob.LeaseAccessConditions{LeaseID: to.Ptr(leaseID)}}
		}
		_, err := s.page(name).UploadPages(ctx, streaming.NopCloser(bytes.NewReader(data[:n])), blob.HTTPRange{Offset: off, Count: int64(n)}, o)
		if err != nil {
			return err
		}
		data, off = data[n:], off+int64(n)
	}
	return nil
}

func (s *Store) ClearPages(ctx context.Context, name string, off, n int64, leaseID string) error {
	o := &pageblob.ClearPagesOptions{}
	if leaseID != "" {
		o.AccessConditions = &blob.AccessConditions{LeaseAccessConditions: &blob.LeaseAccessConditions{LeaseID: to.Ptr(leaseID)}}
	}
	_, err := s.page(name).ClearPages(ctx, blob.HTTPRange{Offset: off, Count: n}, o)
	return err
}

// PageRanges returns the written (non-clear) ranges [start, end) of a page
// blob within [off, off+n).
func (s *Store) PageRanges(ctx context.Context, name string, off, n int64) ([][2]int64, error) {
	var out [][2]int64
	p := s.page(name).NewGetPageRangesPager(&pageblob.GetPageRangesOptions{Range: blob.HTTPRange{Offset: off, Count: n}})
	for p.More() {
		r, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, pr := range r.PageRange {
			out = append(out, [2]int64{*pr.Start, *pr.End + 1})
		}
	}
	return out, nil
}

// Seal raises a page blob's sequence number to at least epoch.
func (s *Store) Seal(ctx context.Context, name string, epoch int64) error {
	_, err := s.page(name).UpdateSequenceNumber(ctx, &pageblob.UpdateSequenceNumberOptions{
		ActionType:     to.Ptr(pageblob.SequenceNumberActionTypeMax),
		SequenceNumber: to.Ptr(epoch),
	})
	return err
}

// Read reads n bytes at off from any blob.
func (s *Store) Read(ctx context.Context, name string, off, n int64) ([]byte, error) {
	buf := make([]byte, n)
	got, err := s.blob(name).DownloadBuffer(ctx, buf, &blob.DownloadBufferOptions{
		Range: blob.HTTPRange{Offset: off, Count: n}, BlockSize: 8 << 20, Concurrency: 8,
	})
	if err != nil {
		return nil, err
	}
	return buf[:got], nil
}

type Props struct {
	Meta     map[string]string
	ETag     azcore.ETag
	Leased   bool
	Size     int64
	Seq      int64
	Modified time.Time
}

func (s *Store) Props(ctx context.Context, name string) (*Props, error) {
	r, err := s.blob(name).GetProperties(ctx, nil)
	if err != nil {
		return nil, err
	}
	p := &Props{Meta: map[string]string{}}
	for k, v := range r.Metadata {
		if v != nil {
			p.Meta[strings.ToLower(k)] = *v
		}
	}
	if r.ETag != nil {
		p.ETag = *r.ETag
	}
	p.Leased = r.LeaseState != nil && *r.LeaseState == lease.StateTypeLeased
	if r.ContentLength != nil {
		p.Size = *r.ContentLength
	}
	if r.BlobSequenceNumber != nil {
		p.Seq = *r.BlobSequenceNumber
	}
	if r.LastModified != nil {
		p.Modified = *r.LastModified
	}
	return p, nil
}

func (s *Store) SetMeta(ctx context.Context, name string, meta map[string]string, leaseID string) error {
	m := map[string]*string{}
	for k, v := range meta {
		m[k] = to.Ptr(v)
	}
	o := &blob.SetMetadataOptions{}
	if leaseID != "" {
		o.AccessConditions = &blob.AccessConditions{LeaseAccessConditions: &blob.LeaseAccessConditions{LeaseID: to.Ptr(leaseID)}}
	}
	_, err := s.blob(name).SetMetadata(ctx, m, o)
	return err
}

// Lease is a renewable 60s blob lease.
type Lease struct {
	c  *lease.BlobClient
	ID string
}

// AcquireLease tries to take the lease on a blob. Returns nil, nil when held by someone else.
func (s *Store) AcquireLease(ctx context.Context, name, id string, seconds int32) (*Lease, error) {
	c, err := lease.NewBlobClient(s.page(name), &lease.BlobClientOptions{LeaseID: to.Ptr(id)})
	if err != nil {
		return nil, err
	}
	_, err = c.AcquireLease(ctx, seconds, nil)
	if isCode(err, bloberror.LeaseAlreadyPresent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &Lease{c: c, ID: id}, nil
}

func (l *Lease) Renew(ctx context.Context) error {
	_, err := l.c.RenewLease(ctx, nil)
	return err
}

func (l *Lease) Release(ctx context.Context) error {
	_, err := l.c.ReleaseLease(ctx, nil)
	return err
}

func (s *Store) StageBlock(ctx context.Context, name, id string, data []byte) error {
	_, err := s.block(name).StageBlock(ctx, id, streaming.NopCloser(bytes.NewReader(data)), nil)
	return err
}

func (s *Store) CommitBlocks(ctx context.Context, name string, ids []string) error {
	_, err := s.block(name).CommitBlockList(ctx, ids, nil)
	return err
}

func (s *Store) PutBlob(ctx context.Context, name string, data []byte) error {
	_, err := s.block(name).Upload(ctx, streaming.NopCloser(bytes.NewReader(data)), nil)
	return err
}

func (s *Store) ReadAll(ctx context.Context, name string) ([]byte, error) {
	r, err := s.blob(name).DownloadStream(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func (s *Store) Delete(ctx context.Context, name string) error {
	_, err := s.blob(name).Delete(ctx, nil)
	if isNotFound(err) {
		return nil
	}
	return err
}

type BlobInfo struct {
	Name     string
	Size     int64
	Modified time.Time
}

func (s *Store) List(ctx context.Context, prefix string) ([]BlobInfo, error) {
	var out []BlobInfo
	p := s.cc.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{Prefix: to.Ptr(prefix)})
	for p.More() {
		r, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, b := range r.Segment.BlobItems {
			bi := BlobInfo{Name: *b.Name}
			if b.Properties != nil {
				if b.Properties.ContentLength != nil {
					bi.Size = *b.Properties.ContentLength
				}
				if b.Properties.LastModified != nil {
					bi.Modified = *b.Properties.LastModified
				}
			}
			out = append(out, bi)
		}
	}
	return out, nil
}

// DeleteContainer removes the whole volume (tests only).
func (s *Store) DeleteContainer(ctx context.Context) error {
	_, err := s.cc.Delete(ctx, nil)
	return err
}

func (s *Store) String() string { return fmt.Sprint(s.cc.URL()) }
