//go:build linux

// Command blip-meta reads the blip metadata disk from inside the guest.
//
//	blip-meta [--device PATH] creds --dir D [--watch] [--interval 10s]
//	blip-meta identity
//	blip-meta get <field>
//	blip-meta exit <code>
//	blip-meta wait [--timeout D]
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/example/blip/internal/meta"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage: blip-meta [--device PATH] <command>
commands:
  creds --dir D [--watch] [--interval 10s]   write service account credentials
  identity                                   print identity JSON
  get <field>                                allocationID|name|namespace|uid|hostname|rootSerial|init|network|volumes|credentials|host
  exit <code>                                record the workload exit code
  wait [--timeout D]                         block until an allocation is present`)
	os.Exit(2)
}

func main() {
	fs := flag.NewFlagSet("blip-meta", flag.ExitOnError)
	fs.Usage = usage
	device := fs.String("device", "", "metadata device (default: find by serial "+meta.Serial+")")
	fs.Parse(os.Args[1:])
	if fs.NArg() < 1 {
		usage()
	}
	if err := run(*device, fs.Arg(0), fs.Args()[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "blip-meta:", err)
		os.Exit(1)
	}
}

func openDevice(path string) (*meta.Device, error) {
	if path == "" {
		if path = meta.FindDevice(); path == "" {
			return nil, errors.New("metadata disk not found")
		}
	}
	return meta.Open(path)
}

func run(device, cmd string, args []string) error {
	dev, err := openDevice(device)
	if err != nil {
		return err
	}
	defer dev.Close()
	switch cmd {
	case "creds":
		fs := flag.NewFlagSet("creds", flag.ExitOnError)
		dir := fs.String("dir", "", "output directory")
		watch := fs.Bool("watch", false, "keep updating")
		interval := fs.Duration("interval", 10*time.Second, "watch interval")
		fs.Parse(args)
		if *dir == "" {
			return errors.New("creds: --dir required")
		}
		return credsLoop(dev, *dir, *watch, *interval)
	case "identity":
		h, err := readAlloc(dev)
		if err != nil {
			return err
		}
		return printJSON(map[string]string{
			"name": h.Identity.Name, "namespace": h.Identity.Namespace,
			"uid": h.Identity.UID, "allocationID": h.AllocationID,
		})
	case "get":
		if len(args) != 1 {
			usage()
		}
		h, _, err := dev.ReadHost()
		if err != nil {
			return err
		}
		return getField(h, args[0])
	case "exit":
		if len(args) != 1 {
			usage()
		}
		code, err := strconv.Atoi(args[0])
		if err != nil {
			return err
		}
		return dev.UpdateGuest(func(g *meta.GuestData) { g.ExitCode = &code })
	case "wait":
		fs := flag.NewFlagSet("wait", flag.ExitOnError)
		timeout := fs.Duration("timeout", 0, "give up after this long (0 = forever)")
		fs.Parse(args)
		deadline := time.Now().Add(*timeout)
		for {
			if h, _, err := dev.ReadHost(); err == nil && h.AllocationID != "" {
				return nil
			}
			if *timeout > 0 && time.Now().After(deadline) {
				return errors.New("timed out waiting for allocation")
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	usage()
	return nil
}

func readAlloc(dev *meta.Device) (*meta.HostData, error) {
	h, _, err := dev.ReadHost()
	if err != nil {
		return nil, err
	}
	if h.AllocationID == "" {
		return nil, errors.New("no allocation")
	}
	return h, nil
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Printf("%s\n", b)
	return err
}

func getField(h *meta.HostData, field string) error {
	str := map[string]string{
		"allocationID": h.AllocationID, "name": h.Identity.Name, "namespace": h.Identity.Namespace,
		"uid": h.Identity.UID, "hostname": h.Hostname, "rootSerial": h.Boot.RootSerial,
	}
	if s, ok := str[field]; ok {
		fmt.Println(s)
		return nil
	}
	switch field {
	case "init":
		return printJSON(h.Boot.Init)
	case "network":
		return printJSON(h.Network)
	case "volumes":
		return printJSON(h.Volumes)
	case "credentials":
		return printJSON(h.Credentials)
	case "host":
		return printJSON(h)
	}
	return fmt.Errorf("unknown field %q", field)
}

func credsLoop(dev *meta.Device, dir string, watch bool, interval time.Duration) error {
	for {
		h, _, err := dev.ReadHost()
		if err == nil && h.Credentials != nil {
			changed, werr := WriteCreds(dir, h.Credentials)
			if werr != nil {
				if !watch {
					return werr
				}
				fmt.Fprintln(os.Stderr, "blip-meta:", werr)
			} else if changed {
				fmt.Fprintln(os.Stderr, "blip-meta: credentials updated in", dir)
			}
		} else if !watch {
			if err == nil {
				err = errors.New("no credentials")
			}
			return err
		}
		if !watch {
			return nil
		}
		time.Sleep(interval)
	}
}
