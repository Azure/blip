// Command mkinitramfs writes a gzip newc initramfs with blip-boot as
// /init. It needs no root, because device nodes are written directly.
//
//	go run ./hack/guest/mkinitramfs -init _output/guest/blip-boot -o _output/guest/initramfs.cpio.gz
package main

import (
	"bufio"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

type entry struct {
	name         string
	mode         uint32
	major, minor uint32 // device numbers, for char devices
	data         []byte
}

const (
	sIFDIR = 0o040000
	sIFREG = 0o100000
	sIFCHR = 0o020000
)

func writeEntry(w io.Writer, ino int, e entry) error {
	nlink := 1
	if e.mode&0o170000 == sIFDIR {
		nlink = 2
	}
	name := e.name + "\x00"
	hdr := fmt.Sprintf("070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
		ino, e.mode, 0, 0, nlink, 0, len(e.data), 0, 0, e.major, e.minor, len(name), 0)
	if _, err := io.WriteString(w, hdr+name); err != nil {
		return err
	}
	if err := pad(w, len(hdr)+len(name)); err != nil {
		return err
	}
	if _, err := w.Write(e.data); err != nil {
		return err
	}
	return pad(w, len(e.data))
}

func pad(w io.Writer, n int) error {
	if r := n % 4; r != 0 {
		_, err := w.Write(make([]byte, 4-r))
		return err
	}
	return nil
}

func main() {
	initBin := flag.String("init", "_output/guest/blip-boot", "/init binary (blip-boot)")
	out := flag.String("o", "_output/guest/initramfs.cpio.gz", "output file")
	flag.Parse()
	bin, err := os.ReadFile(*initBin)
	if err != nil {
		log.Fatal(err)
	}
	entries := []entry{
		{name: "dev", mode: sIFDIR | 0o755},
		{name: "dev/console", mode: sIFCHR | 0o600, major: 5, minor: 1},
		{name: "dev/null", mode: sIFCHR | 0o666, major: 1, minor: 3},
		{name: "proc", mode: sIFDIR | 0o755},
		{name: "sys", mode: sIFDIR | 0o755},
		{name: "newroot", mode: sIFDIR | 0o755},
		{name: "run", mode: sIFDIR | 0o755},
		{name: "tmp", mode: sIFDIR | 0o1777},
		{name: "init", mode: sIFREG | 0o755, data: bin},
		{name: "TRAILER!!!"},
	}
	f, err := os.Create(*out + ".tmp")
	if err != nil {
		log.Fatal(err)
	}
	bw := bufio.NewWriter(f)
	zw, _ := gzip.NewWriterLevel(bw, gzip.BestSpeed)
	for i, e := range entries {
		if err := writeEntry(zw, i+1, e); err != nil {
			log.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		log.Fatal(err)
	}
	if err := bw.Flush(); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	if err := os.Rename(*out+".tmp", *out); err != nil {
		log.Fatal(err)
	}
}
