package gateway

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// UsersConfigMap maps owners to authorized_keys lines.
const UsersConfigMap = "blip-ssh-users"

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// Users maps public keys to owners.
type Users struct {
	mu   sync.RWMutex
	keys map[string]string // ssh wire-format key -> owner
}

// Owner returns the owner of key.
func (u *Users) Owner(key ssh.PublicKey) (string, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	owner, ok := u.keys[string(key.Marshal())]
	return owner, ok
}

// Set replaces the users with the ConfigMap data. Invalid owners and lines
// are skipped and returned as errors. Owners starting with "u-" are reserved
// for certificate identities. A key listed by two owners belongs to the first
// owner in sorted order. Lines with authorized_keys options are rejected: the
// gateway cannot enforce from=, command=, restrict, or other restrictions.
func (u *Users) Set(data map[string]string) []error {
	var errs []error
	keys := map[string]string{}
	owners := make([]string, 0, len(data))
	for owner := range data {
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	for _, owner := range owners {
		if !dnsLabel.MatchString(owner) || len(owner) > 40 || strings.HasPrefix(owner, "u-") {
			errs = append(errs, fmt.Errorf("owner %q: must be a lowercase DNS label of at most 40 characters without the reserved u- prefix", owner))
			continue
		}
		sc := bufio.NewScanner(strings.NewReader(data[owner]))
		for n := 1; sc.Scan(); n++ {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, _, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				errs = append(errs, fmt.Errorf("owner %q line %d: %v", owner, n, err))
				continue
			}
			if len(options) > 0 {
				errs = append(errs, fmt.Errorf("owner %q line %d: authorized_keys options are not supported (%s); the gateway cannot enforce from=, command= or restrict", owner, n, strings.Join(options, ",")))
				continue
			}
			k := string(key.Marshal())
			if prev, ok := keys[k]; ok {
				errs = append(errs, fmt.Errorf("owner %q line %d: key already belongs to %q", owner, n, prev))
				continue
			}
			keys[k] = owner
		}
	}
	u.mu.Lock()
	u.keys = keys
	u.mu.Unlock()
	return errs
}

// Watch keeps the users in sync with the ConfigMap until ctx is done. It
// returns after the initial sync.
func (u *Users) Watch(ctx context.Context, cs kubernetes.Interface, namespace string, log *slog.Logger) {
	factory := informers.NewSharedInformerFactoryWithOptions(cs, 0, informers.WithNamespace(namespace),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.FieldSelector = "metadata.name=" + UsersConfigMap }))
	load := func(obj any) {
		cm, ok := obj.(*corev1.ConfigMap)
		if !ok || cm.Name != UsersConfigMap {
			return
		}
		for _, err := range u.Set(cm.Data) {
			log.Warn("ignoring user entry", "configmap", UsersConfigMap, "error", err)
		}
		u.mu.RLock()
		log.Info("loaded users", "keys", len(u.keys))
		u.mu.RUnlock()
	}
	inf := factory.Core().V1().ConfigMaps().Informer()
	inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    load,
		UpdateFunc: func(_, obj any) { load(obj) },
		DeleteFunc: func(obj any) {
			if cm, ok := deletedConfigMap(obj); ok && cm.Name == UsersConfigMap {
				u.Set(nil)
				log.Info("users ConfigMap deleted; no keys accepted")
			}
		},
	})
	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())
}

// deletedConfigMap unwraps the DeletedFinalStateUnknown tombstone that the
// informer delivers when it sees a delete without the object, for example
// after a missed watch.
func deletedConfigMap(obj any) (*corev1.ConfigMap, bool) {
	if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tomb.Obj
	}
	cm, ok := obj.(*corev1.ConfigMap)
	return cm, ok
}
