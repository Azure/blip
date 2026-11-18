package runtime

import (
	"io"
	"net"
	"os"
	"time"

	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/wire"
)

// Bridge relays stdin and stdout to a guest vsock port. It returns when the
// guest side closes; stdin EOF only half-closes the connection.
func Bridge(o Options, port uint32) error {
	conn, err := wire.DialVsock(o.path(podapi.VsockSocket), port, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	go func() {
		_, _ = io.Copy(conn, os.Stdin)
		if uc, ok := conn.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
	}()
	_, err = io.Copy(os.Stdout, conn)
	return err
}
