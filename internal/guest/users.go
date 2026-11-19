package guest

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
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
	if uid, numeric, err := parseID(userPart); err != nil {
		return nil, err
	} else if numeric {
		a.uid = uid
		// Compare by value, not text: "01000" is uid 1000 and must find the
		// same passwd entry (and therefore gid, name and home) as "1000".
		for _, f := range passwd {
			if len(f) < 7 {
				continue
			}
			if fid, err := strconv.ParseUint(f[2], 10, 32); err == nil && uint32(fid) == uid {
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
		if gid, numeric, err := parseID(groupPart); err != nil {
			return nil, err
		} else if numeric {
			a.gid = gid
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

// parseID parses a decimal user or group ID. numeric is false for a name.
// Leading zeros are accepted (01000 is 1000). Values the kernel cannot hold,
// including (uid_t)-1 = 4294967295, are rejected instead of failing later with
// "invalid argument" from exec.
func parseID(s string) (id uint32, numeric bool, err error) {
	if s == "" {
		return 0, false, nil
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false, nil
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v >= math.MaxUint32 {
		return 0, true, fmt.Errorf("id %q is out of range", s)
	}
	return uint32(v), true, nil
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

// lookPath finds name in the PATH of env, inside root and relative to the
// command's working directory dir. It follows execvp semantics: an empty or
// relative PATH entry is relative to dir, a candidate the account cannot
// execute is reported as permission denied (126) rather than not found (127),
// and a later executable candidate still wins. An empty name is ENOENT
// (127): there is no file to execute.
func lookPath(root, dir, name string, env []string, acct *account) (string, error) {
	if name == "" {
		// execve("") is ENOENT. Every PATH candidate would otherwise be
		// the directory itself, whose "not regular" check reads as 126.
		return "", startFail(127, fmt.Errorf("%s: command not found", name))
	}
	if strings.Contains(name, "/") {
		return name, nil
	}
	pathVar := defaultPath
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			pathVar = v
		}
	}
	denied := false
	entries := filepath.SplitList(pathVar)
	if pathVar == "" {
		// execvp treats PATH="" as one empty component: the current
		// directory. filepath.SplitList returns no entries for "", which
		// would make the command unfindable.
		entries = []string{""}
	}
	for _, entry := range entries {
		var p string
		switch {
		case entry == "" || entry == ".":
			// An empty component is the current directory.
			p = joinPath(dir, name)
		case strings.HasPrefix(entry, "/"):
			p = joinPath(entry, name)
		default:
			p = joinPath(joinPath(dir, entry), name)
		}
		// Resolve inside root so absolute symlinks (e.g. /bin -> usr/bin)
		// point at the root's files.
		fi, err := statInRoot(root, p)
		if err != nil {
			if errors.Is(err, unix.EACCES) {
				denied = true
			}
			continue
		}
		if !fi.Mode().IsRegular() {
			// execve on a directory (or other non-regular file) is EACCES.
			denied = true
			continue
		}
		if canExecFile(fi, acct) {
			return p, nil
		}
		denied = true
	}
	if denied {
		return "", startFail(126, fmt.Errorf("%s: permission denied", name))
	}
	return "", startFail(127, fmt.Errorf("%s: command not found", name))
}

// joinPath appends name to dir without lexical cleaning: the kernel resolves
// ".." and symlinks, and cleaning here would change what it finds.
func joinPath(dir, name string) string {
	if strings.HasSuffix(dir, "/") {
		return dir + name
	}
	return dir + "/" + name
}
