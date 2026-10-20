// Command blipfsd is the per-host blipfs daemon. It opens one volume and
// serves mounts that the blipfs CLI requests over a unix socket.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/blipfs/blipfs/internal/blipfs"
)

func main() {
	var cfg blipfs.Config
	var slot sizeFlag = 64 << 10
	flag.StringVar(&cfg.Conn, "conn", os.Getenv("BLIPFS_CONN"), "Azure storage connection string (default $BLIPFS_CONN)")
	flag.StringVar(&cfg.AccountURL, "account-url", os.Getenv("BLIPFS_ACCOUNT_URL"), "blob endpoint used with Azure AD credentials (managed identity, az login, ...) when no connection string is given (default $BLIPFS_ACCOUNT_URL)")
	flag.StringVar(&cfg.Container, "container", "", "container holding the volume (required)")
	flag.IntVar(&cfg.Stripes, "wal-stripes", 16, "WAL stripes (new volumes only)")
	flag.IntVar(&cfg.Shards, "snap-shards", 4, "snapshot shards (new volumes only)")
	flag.Var(&slot, "slot-size", "WAL slot size, e.g. 64KiB (new volumes only)")
	flag.IntVar(&cfg.Slots, "wal-slots", 16384, "slots per WAL stripe (new volumes only)")
	flag.StringVar(&cfg.TmpDir, "tmp-dir", os.TempDir()+"/blipfs", "scratch space for dirty data of open files")
	flag.BoolVar(&cfg.Standalone, "standalone", false, "run the sequencer in-process and keep other hosts out")
	flag.StringVar(&cfg.Listen, "listen", ":7070", "sequencer listen address (cluster mode)")
	flag.StringVar(&cfg.Advertise, "advertise", "", "sequencer address other hosts dial (default <host>:<port>)")
	flag.StringVar(&cfg.Socket, "socket", "/run/blipfs.sock", "control socket for the blipfs CLI")
	flag.StringVar(&cfg.Host, "host", "", "host name recorded in the log (default hostname)")
	flag.Parse()
	cfg.SlotSize = int(slot)
	if cfg.Container == "" || cfg.Conn == "" && cfg.AccountURL == "" {
		flag.Usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	v, err := blipfs.Open(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("blipfsd: volume %s ready; control socket %s", cfg.Container, cfg.Socket)
	<-ctx.Done()
	log.Print("blipfsd: shutting down")
	if err := v.Close(); err != nil {
		log.Fatal(err)
	}
}
