// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// proxyInitUID is the Envoy sidecar's user. The credentials directory and its
// files are shared with it read-only.
const proxyInitUID = 65532

// placeholderCredential is a valid Envoy file-SDS generic secret with no
// usable token. The node agent replaces it once the pod is claimed; until then
// Envoy injects it and the upstream answers 401.
const placeholderCredential = `resources:
- "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret
  name: %s
  generic_secret:
    secret:
      inline_string: "Bearer -"
`

// runProxyInit seeds the credential directory before the Envoy sidecar starts.
// Envoy fails to start if an SDS path is missing, and the node agent may not
// have written real tokens yet, so every configured upstream gets a valid
// placeholder. Existing files are left alone: a restarted init container must
// not clobber tokens the node agent already minted.
func runProxyInit(dir string, names []string) error {
	if dir == "" {
		return errors.New("--dir is required")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		path := filepath.Join(dir, name+".yaml")
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o440)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			return err
		}
		_, err = fmt.Fprintf(f, placeholderCredential, name)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	// Root owns the directory until here; hand it to the sidecar's user so it
	// can read the files the node agent rotates in.
	if os.Geteuid() == 0 {
		for _, path := range append([]string{dir}, credentialPaths(dir, names)...) {
			if err := os.Chown(path, proxyInitUID, proxyInitUID); err != nil {
				return err
			}
		}
	}
	return nil
}

func credentialPaths(dir string, names []string) []string {
	var paths []string
	for _, name := range names {
		if name = strings.TrimSpace(name); name != "" {
			paths = append(paths, filepath.Join(dir, name+".yaml"))
		}
	}
	return paths
}

func proxyInit(args []string) error {
	fs := flag.NewFlagSet("proxy-init", flag.ContinueOnError)
	dir := fs.String("dir", "", "credential directory to seed")
	credentials := fs.String("credentials", "", "comma-separated upstream names")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var names []string
	for _, name := range strings.Split(*credentials, ",") {
		names = append(names, strings.TrimSpace(name))
	}
	return runProxyInit(*dir, names)
}
