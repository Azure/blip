package guest

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// account is a resolved user for a process in the root filesystem.
type account struct {
	name   string
	uid    uint32
	gid    uint32
	groups []uint32
	home   string
	shell  string
}

// lookupAccount resolves spec ("", "name", "uid", "name:group", "uid:gid")
// against root's /etc/passwd and /etc/group. The empty spec is root.
func lookupAccount(root, spec string) (*account, error) {
	if spec == "" {
		spec = "root"
	}
	userPart, groupPart, hasGroup := strings.Cut(spec, ":")
	passwd := readColonFile(filepath.Join(root, "etc/passwd"))
	groups := readColonFile(filepath.Join(root, "etc/group"))

	a := &account{home: "/", shell: "/bin/sh"}
	var entry []string
	if uid, err := strconv.ParseUint(userPart, 10, 32); err == nil {
		a.uid = uint32(uid)
		for _, f := range passwd {
			if len(f) >= 7 && f[2] == userPart {
				entry = f
				break
			}
		}
	} else {
		for _, f := range passwd {
			if len(f) >= 7 && f[0] == userPart {
				entry = f
				break
			}
		}
		if entry == nil {
			if userPart != "root" {
				return nil, fmt.Errorf("user %q not found in /etc/passwd", userPart)
			}
			entry = []string{"root", "x", "0", "0", "", "/root", "/bin/sh"}
		}
	}
	if entry != nil {
		uid, err := strconv.ParseUint(entry[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bad uid for %q", entry[0])
		}
		gid, err := strconv.ParseUint(entry[3], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bad gid for %q", entry[0])
		}
		a.name, a.uid, a.gid = entry[0], uint32(uid), uint32(gid)
		if entry[5] != "" {
			a.home = entry[5]
		}
		if entry[6] != "" {
			a.shell = entry[6]
		}
	}
	if hasGroup {
		if gid, err := strconv.ParseUint(groupPart, 10, 32); err == nil {
			a.gid = uint32(gid)
		} else {
			found := false
			for _, f := range groups {
				if len(f) >= 3 && f[0] == groupPart {
					if gid, err := strconv.ParseUint(f[2], 10, 32); err == nil {
						a.gid, found = uint32(gid), true
						break
					}
				}
			}
			if !found {
				return nil, fmt.Errorf("group %q not found in /etc/group", groupPart)
			}
		}
	}
	a.groups = []uint32{a.gid}
	if a.name != "" && !hasGroup {
		for _, f := range groups {
			if len(f) < 4 {
				continue
			}
			for _, m := range strings.Split(f[3], ",") {
				if m != a.name {
					continue
				}
				if gid, err := strconv.ParseUint(f[2], 10, 32); err == nil && uint32(gid) != a.gid {
					a.groups = append(a.groups, uint32(gid))
				}
			}
		}
	}
	return a, nil
}

func readColonFile(path string) [][]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out [][]string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Split(line, ":"))
	}
	return out
}

// mergeEnv returns base with every KEY=VALUE of each later list applied in
// order; later values win.
func mergeEnv(lists ...[]string) []string {
	var out []string
	index := map[string]int{}
	for _, l := range lists {
		for _, kv := range l {
			k, _, _ := strings.Cut(kv, "=")
			if i, ok := index[k]; ok {
				out[i] = kv
				continue
			}
			index[k] = len(out)
			out = append(out, kv)
		}
	}
	return out
}

const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// lookPath finds name in the PATH of env, inside root. It returns the path as
// seen from inside root.
func lookPath(root, name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	path := defaultPath
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			path = v
		}
	}
	for _, dir := range filepath.SplitList(path) {
		if !strings.HasPrefix(dir, "/") {
			continue
		}
		p := filepath.Join(dir, name)
		// Resolve inside root so absolute symlinks (e.g. /bin -> usr/bin)
		// point at the root's files.
		if fi, err := statInRoot(root, p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", startFail(127, fmt.Errorf("%s: command not found", name))
}
