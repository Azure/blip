package session

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/Azure/blip/internal/wire"
)

// Container is the VM pod container that runs blip-runtime.
const Container = "vm"

// NewClient returns a Client that reaches guests through pod exec.
func NewClient(cfg *rest.Config) (*Client, error) {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{Connect: podExec(cfg, cs)}, nil
}

// podExec runs `blip-runtime bridge 1025` in the vm container without a TTY
// and returns its stdin/stdout. It prefers the websocket protocol and falls
// back to SPDY for older API servers.
func podExec(cfg *rest.Config, cs kubernetes.Interface) Connector {
	return func(ctx context.Context, namespace, pod string) (io.ReadWriteCloser, error) {
		req := cs.CoreV1().RESTClient().Post().
			Resource("pods").Namespace(namespace).Name(pod).SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: Container,
				Command:   []string{"blip-runtime", "bridge", strconv.Itoa(wire.SessionPort)},
				Stdin:     true,
				Stdout:    true,
				Stderr:    true,
			}, scheme.ParameterCodec)
		ws, err := remotecommand.NewWebSocketExecutor(cfg, "GET", req.URL().String())
		if err != nil {
			return nil, err
		}
		spdy, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
		if err != nil {
			return nil, err
		}
		exec, err := remotecommand.NewFallbackExecutor(ws, spdy, func(err error) bool {
			return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
		})
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithCancel(ctx)
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		stderr := &tail{}
		go func() {
			err := exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: inR, Stdout: outW, Stderr: stderr})
			if err != nil && ctx.Err() == nil {
				msg := strings.TrimSpace(stderr.String())
				if msg != "" {
					err = fmt.Errorf("pod %s exec: %v: %s", pod, err, msg)
				} else {
					err = fmt.Errorf("pod %s exec: %w", pod, err)
				}
			}
			outW.CloseWithError(err)
			inR.Close()
		}()
		return &execStream{r: outR, w: inW, cancel: cancel}, nil
	}
}

type execStream struct {
	r      *io.PipeReader
	w      *io.PipeWriter
	cancel context.CancelFunc
}

func (e *execStream) Read(p []byte) (int, error)  { return e.r.Read(p) }
func (e *execStream) Write(p []byte) (int, error) { return e.w.Write(p) }
func (e *execStream) Close() error {
	e.cancel()
	e.w.Close()
	e.r.Close()
	return nil
}

// tail keeps the first and last few KiB written to it. The first line is
// often the root cause (for example an upgrade failure) while the last line
// says where it surfaced.
type tail struct {
	mu   sync.Mutex
	head []byte
	tail bytes.Buffer
}

const tailKeep = 4096

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(p)
	if room := tailKeep - len(t.head); room > 0 {
		if room > len(p) {
			room = len(p)
		}
		t.head = append(t.head, p[:room]...)
		p = p[room:]
	}
	if len(p) > 0 {
		t.tail.Write(p)
		if t.tail.Len() > tailKeep {
			t.tail.Next(t.tail.Len() - tailKeep)
		}
	}
	return n, nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tail.Len() == 0 {
		return string(t.head)
	}
	return string(t.head) + "\n...\n" + t.tail.String()
}
