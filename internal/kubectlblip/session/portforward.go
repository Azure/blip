package session

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// Forward is a running port-forward to a pod port on 127.0.0.1.
type Forward struct {
	LocalPort int
	stop      chan struct{}
	done      chan error
}

// Close stops the forward and waits for it to finish.
func (f *Forward) Close() {
	close(f.stop)
	<-f.done
}

// Done is closed (with the forward's error, if any) when the forward ends.
func (f *Forward) Done() <-chan error { return f.done }

// PortForward forwards a random local port on 127.0.0.1 to port of the pod.
// Diagnostics go to errOut.
func PortForward(ctx context.Context, cfg *rest.Config, ns, pod string, port int, errOut io.Writer) (*Forward, error) {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	u := cs.CoreV1().RESTClient().Post().Resource("pods").Namespace(ns).Name(pod).SubResource("portforward").URL()

	transport, upgrader, err := spdy.RoundTripperFor(cfg)
	if err != nil {
		return nil, err
	}
	var dialer httpstream.Dialer = spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, u)
	// Prefer websockets (Kubernetes >= 1.30) and fall back to SPDY.
	if ws, err := portforward.NewSPDYOverWebsocketDialer(u, cfg); err == nil {
		dialer = portforward.NewFallbackDialer(ws, dialer, func(err error) bool {
			return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
		})
	}

	stop, ready := make(chan struct{}), make(chan struct{})
	pf, err := portforward.NewOnAddresses(dialer, []string{"127.0.0.1"}, []string{fmt.Sprintf("0:%d", port)}, stop, ready, io.Discard, errOut)
	if err != nil {
		return nil, err
	}
	f := &Forward{stop: stop, done: make(chan error, 1)}
	go func() { f.done <- pf.ForwardPorts(); close(f.done) }()
	select {
	case <-ready:
	case err := <-f.done:
		if err == nil {
			err = fmt.Errorf("port-forward to %s/%s ended", ns, pod)
		}
		return nil, fmt.Errorf("port-forward to pod %s/%s: %w", ns, pod, err)
	case <-ctx.Done():
		close(stop)
		<-f.done
		return nil, ctx.Err()
	}
	ports, err := pf.GetPorts()
	if err != nil || len(ports) == 0 {
		f.Close()
		return nil, fmt.Errorf("port-forward: no local port: %v", err)
	}
	f.LocalPort = int(ports[0].Local)
	return f, nil
}
