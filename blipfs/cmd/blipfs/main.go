// Command blipfs is the CLI. It forwards its arguments to the local blipfsd
// over the control socket; all commands run inside the daemon.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/blipfs/blipfs/proto"
)

func main() {
	sock := os.Getenv("BLIPFS_SOCKET")
	if sock == "" {
		sock = "/run/blipfs.sock"
	}
	args := os.Args[1:]
	if len(args) >= 2 && args[0] == "--socket" {
		sock, args = args[1], args[2:]
	}
	cwd, _ := os.Getwd()
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "blipfs:", err)
		os.Exit(1)
	}
	defer conn.Close()
	r, err := pb.NewControlClient(conn).Run(context.Background(), &pb.CmdReq{Args: args, Cwd: cwd})
	if err != nil {
		fmt.Fprintf(os.Stderr, "blipfs: cannot reach blipfsd at %s: %v\n", sock, err)
		os.Exit(1)
	}
	out := r.Output
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	if r.Code == 0 {
		fmt.Print(out)
	} else {
		fmt.Fprint(os.Stderr, out)
	}
	os.Exit(int(r.Code))
}
