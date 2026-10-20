package blipfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pmezard/go-difflib/difflib"
)

const maxPatch = 1 << 20

const usage = `usage: blipfs <command> [args]
  mount <branch> <path>               mount a branch
  umount <path>                       unmount
  branches [-a]                       list branches (-a: include closed and merge workspaces)
  fork <src>[@rev] <new>              create a branch
  log [<branch>] [-n N] [-- <path>]   list revisions
  show <rev>                          show one revision
  diff <a> <b>                        compare two revisions
  merge <src> [--into <dst>]          merge src into dst
  merge --continue|--abort [--into <dst>]
  resolve <path>...                   mark merge conflicts resolved
  cherry-pick <rev>[..<rev>] [--onto <dst>]
  revert <rev> [--onto <dst>]
  gc                                  collect garbage now
revisions: <branch>, <branch>@<lsn> or <lsn> (on the current branch)
`

type cmdArgs struct {
	pos   []string
	flags map[string]string
	rest  []string // after --
}

func parseArgs(args []string, valued ...string) (cmdArgs, error) {
	a := cmdArgs{flags: map[string]string{}}
	for i := 0; i < len(args); i++ {
		s := args[i]
		switch {
		case s == "--":
			a.rest = args[i+1:]
			return a, nil
		case strings.HasPrefix(s, "-") && len(s) > 1:
			if slices.Contains(valued, s) {
				if i+1 == len(args) {
					return a, fmt.Errorf("%s needs a value", s)
				}
				a.flags[s] = args[i+1]
				i++
			} else {
				a.flags[s] = "1"
			}
		default:
			a.pos = append(a.pos, s)
		}
	}
	return a, nil
}

// cwdBranch returns the branch mounted at cwd and cwd's path inside it.
func (v *Vol) cwdBranch(cwd string) (string, string) {
	m := v.mountAt(cwd)
	if m == nil {
		return "", ""
	}
	rel, err := filepath.Rel(m.path, cwd)
	if err != nil {
		return m.b.name, "/"
	}
	return m.b.name, filepath.Clean("/" + rel)
}

// runCmd executes one CLI command for the control socket.
func (v *Vol) runCmd(ctx context.Context, args []string, cwd string) (string, int) {
	if len(args) == 0 {
		return usage, 2
	}
	out, err := v.cmd(ctx, args[0], args[1:], cwd)
	if err != nil {
		return out + "blipfs: " + err.Error() + "\n", 1
	}
	return out, 0
}

func (v *Vol) cmd(ctx context.Context, name string, args []string, cwd string) (string, error) {
	cur, _ := v.cwdBranch(cwd)
	abs := func(p string) string {
		if filepath.IsAbs(p) {
			return filepath.Clean(p)
		}
		return filepath.Join(cwd, p)
	}
	a, err := parseArgs(args, "--into", "--onto", "-n")
	if err != nil {
		return "", err
	}
	need := func(n int) error {
		if len(a.pos) != n {
			return fmt.Errorf("%s: wrong number of arguments\n%s", name, usage)
		}
		return nil
	}
	switch name {
	case "help", "-h", "--help":
		return usage, nil
	case "mount":
		if err := need(2); err != nil {
			return "", err
		}
		return "", v.Mount(a.pos[0], abs(a.pos[1]))
	case "umount", "unmount":
		if err := need(1); err != nil {
			return "", err
		}
		return "", v.Unmount(abs(a.pos[0]))
	case "branches":
		return v.cmdBranches(ctx, a.flags["-a"] != "")
	case "fork":
		if err := need(2); err != nil {
			return "", err
		}
		return v.cmdFork(ctx, a.pos[0], a.pos[1], cur)
	case "log":
		br := cur
		if len(a.pos) > 0 {
			br = a.pos[0]
		}
		n := 0
		if s := a.flags["-n"]; s != "" {
			if n, err = strconv.Atoi(s); err != nil {
				return "", fmt.Errorf("bad -n %q", s)
			}
		}
		path := ""
		if len(a.rest) > 0 {
			path = a.rest[0]
		}
		return v.cmdLog(ctx, br, n, v.volPath(cwd, path))
	case "show":
		if err := need(1); err != nil {
			return "", err
		}
		return v.cmdShow(ctx, a.pos[0], cur)
	case "diff":
		if err := need(2); err != nil {
			return "", err
		}
		ra, err := v.parseRev(ctx, a.pos[0], cur)
		if err != nil {
			return "", err
		}
		rb, err := v.parseRev(ctx, a.pos[1], cur)
		if err != nil {
			return "", err
		}
		ta, err := v.treeAt(ctx, ra)
		if err != nil {
			return "", err
		}
		tb, err := v.treeAt(ctx, rb)
		if err != nil {
			return "", err
		}
		var sb strings.Builder
		err = v.writeDiff(ctx, &sb, ta, tb)
		return sb.String(), err
	case "merge":
		dst := cur
		if d := a.flags["--into"]; d != "" {
			dst = d
		}
		if dst == "" {
			return "", errors.New("merge: no destination; use --into or run inside a mount")
		}
		switch {
		case a.flags["--continue"] != "":
			return v.mergeContinue(ctx, dst)
		case a.flags["--abort"] != "":
			return v.mergeAbort(ctx, dst)
		}
		if err := need(1); err != nil {
			return "", err
		}
		src, err := v.parseRev(ctx, a.pos[0], "")
		if err != nil {
			return "", err
		}
		dstRev, err := v.parseRev(ctx, dst, "")
		if err != nil {
			return "", err
		}
		base, err := v.lca(ctx, dstRev, src)
		if err != nil {
			return "", err
		}
		if base == src || base.Branch == src.Branch && base.LSN >= src.LSN {
			return "already up to date\n", nil
		}
		return v.apply3(ctx, mergeReq{kind: "merge", dst: dst, base: base, theirs: src, edge: true,
			info: fmt.Sprintf("merge %s into %s (base %s)", src, dst, base)})
	case "resolve":
		if len(a.pos) == 0 {
			return "", errors.New("resolve: no paths")
		}
		return v.cmdResolve(ctx, a.pos, cwd, a.flags["--into"])
	case "cherry-pick", "revert":
		if err := need(1); err != nil {
			return "", err
		}
		return v.cmdPick(ctx, name, a.pos[0], a.flags["--onto"], cur)
	case "gc":
		return v.gc(ctx)
	}
	return "", fmt.Errorf("unknown command %q\n%s", name, usage)
}

// volPath maps a CLI path argument to a path inside the branch: paths under
// a mount are taken relative to it, others as volume paths.
func (v *Vol) volPath(cwd, p string) string {
	if p == "" {
		return ""
	}
	full := p
	if !filepath.IsAbs(p) {
		full = filepath.Join(cwd, p)
	}
	if m := v.mountAt(full); m != nil {
		rel, _ := filepath.Rel(m.path, full)
		return filepath.Clean("/" + rel)
	}
	return filepath.Clean("/" + p)
}

func (v *Vol) cmdBranches(ctx context.Context, all bool) (string, error) {
	if err := v.table.s.catchUp(ctx, 0); err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, n := range v.table.list(all) {
		if !all && strings.HasPrefix(n, mergePrefix) {
			continue
		}
		b, err := v.branch(n)
		if err != nil {
			return "", err
		}
		if _, _, err := b.head(ctx); err != nil {
			continue
		}
		m := b.Meta()
		line := fmt.Sprintf("%s\t@%d", n, b.s.last.Load())
		if m.Closed {
			line += "\tclosed"
		}
		if m.Src.Branch != "" {
			line += "\tfrom " + m.Src.String()
		}
		if m.Active != "" {
			line += "\tmerging (" + m.Active + ")"
		}
		if ps := v.mountsOf(n); len(ps) > 0 {
			line += "\tmounted at " + strings.Join(ps, ", ")
		}
		sb.WriteString(line + "\n")
	}
	return sb.String(), nil
}

func (v *Vol) cmdFork(ctx context.Context, src, name, cur string) (string, error) {
	if err := validBranchName(name); err != nil {
		return "", err
	}
	r, err := v.parseRev(ctx, src, cur)
	if err != nil {
		return "", err
	}
	b, err := v.branch(name)
	if err != nil {
		return "", err
	}
	lsn, res, err := v.write(ctx, RecBranch, b, []Op{{Kind: OpBranchCreate, Branch: name, Src: r, Time: time.Now().UnixNano(), Node: v.node}})
	if err != nil {
		return "", err
	}
	if e := res[0].Errno; e == syscall.EEXIST {
		return "", fmt.Errorf("branch %q already exists", name)
	} else if e != 0 {
		return "", e
	}
	return fmt.Sprintf("%s@%d forked from %s\n", name, lsn, r), nil
}

// opSummary describes a commit's ops; t (usually a later tree) names inodes.
func opSummary(c commitInfo, t Tree) string {
	name := func(ino uint64) string {
		if p, err := pathOf(t, ino); err == nil && p != "" {
			return p
		}
		return fmt.Sprintf("#%d", ino)
	}
	var parts []string
	for _, op := range c.Ops {
		s := opNames[op.Kind]
		switch op.Kind {
		case OpCreate, OpLink, OpUnlink, OpRmdir, OpSetXattr, OpRmXattr:
			s += " " + op.Name
		case OpRename:
			s += " " + op.Name + " -> " + op.NewName
		case OpBranchCreate:
			if op.Src.Branch != "" {
				s = "fork of " + op.Src.String()
			} else {
				s = "create"
			}
		case OpMergeDone, OpMergeStart:
			s = op.Info
		case OpWrite, OpSetAttr:
			s += " " + name(op.Ino)
		}
		parts = append(parts, s)
	}
	if len(parts) > 4 {
		parts = append(parts[:4], fmt.Sprintf("... (%d ops)", len(c.Ops)))
	}
	return strings.Join(parts, "; ")
}

func (v *Vol) cmdLog(ctx context.Context, name string, limit int, path string) (string, error) {
	if name == "" {
		return "", errors.New("log: no branch; give one or run inside a mount")
	}
	b, err := v.existing(ctx, name)
	if err != nil {
		return "", err
	}
	var ino uint64
	if path != "" {
		_, t, err := b.head(ctx)
		if err != nil {
			return "", err
		}
		if ino, err = resolvePath(t, path); err != nil {
			return "", fmt.Errorf("%s: %w", path, err)
		}
	}
	var sb strings.Builder
	n := 0
	upto := uint64(1<<64 - 1)
	for b != nil {
		h, err := b.history(ctx)
		if err != nil {
			return "", err
		}
		var hit map[uint64]bool
		if ino != 0 {
			if hit, err = b.touched(ctx, ino); err != nil {
				return "", err
			}
		}
		head, _, _ := b.local()
		for i := len(h) - 1; i >= 0; i-- {
			c := h[i]
			if c.LSN > upto || c.Type == RecStage || hit != nil && !hit[c.LSN] {
				continue
			}
			flags := ""
			if c.Concurrent {
				flags = " [concurrent-writer]"
			}
			fmt.Fprintf(&sb, "%s@%d  %s  %-6s %s  %s%s\n", b.name, c.LSN, time.Unix(0, c.Time).Format("2006-01-02 15:04:05"),
				recTypeNames[c.Type], c.Node, opSummary(c, head), flags)
			if n++; limit > 0 && n >= limit {
				return sb.String(), nil
			}
		}
		src := b.Meta().Src
		if src.Branch == "" {
			break
		}
		upto = src.LSN
		if b, err = v.branch(src.Branch); err != nil {
			return "", err
		}
	}
	return sb.String(), nil
}

func (v *Vol) cmdShow(ctx context.Context, s, cur string) (string, error) {
	r, err := v.parseRev(ctx, s, cur)
	if err != nil {
		return "", err
	}
	b, err := v.branch(r.Branch)
	if err != nil {
		return "", err
	}
	c, err := b.findCommit(ctx, r.LSN)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "revision %s@%d\ntype:  %s\nnode:  %s\ndate:  %s\n", b.name, c.LSN, recTypeNames[c.Type], c.Node,
		time.Unix(0, c.Time).Format(time.RFC3339))
	if c.Concurrent {
		sb.WriteString("flags: concurrent-writer\n")
	}
	after, err := b.TreeAt(ctx, c.LSN)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&sb, "ops:   %s\n\n", opSummary(c, after))
	var before Tree
	if c.LSN > b.Meta().Created {
		if before, err = b.TreeAt(ctx, c.LSN-1); err != nil {
			return "", err
		}
	} else if src := b.Meta().Src; src.Branch != "" {
		if before, err = v.treeAt(ctx, src); err != nil {
			return "", err
		}
	}
	err = v.writeDiff(ctx, &sb, before, after)
	return sb.String(), err
}

func (v *Vol) cmdResolve(ctx context.Context, paths []string, cwd, into string) (string, error) {
	// inside <mount>/.blipfs/merge/<id>/work the workspace is explicit
	var ws string
	var root string
	if m := v.mountAt(cwd); m != nil {
		rel, _ := filepath.Rel(m.path, cwd)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) >= 4 && parts[0] == ".blipfs" && parts[1] == "merge" && parts[3] == "work" {
			ws, root = mergeBranch(parts[2]), filepath.Join(m.path, ".blipfs/merge", parts[2], "work")
		}
		if ws == "" {
			dst := m.b.name
			if into != "" {
				dst = into
			}
			_, wb, _, err := v.activeMerge(ctx, dst)
			if err != nil {
				return "", err
			}
			ws, root = wb.name, m.path
		}
	} else if into != "" {
		_, wb, _, err := v.activeMerge(ctx, into)
		if err != nil {
			return "", err
		}
		ws = wb.name
	} else {
		return "", errors.New("resolve: run inside a mount or use --into")
	}
	wb, err := v.existing(ctx, ws)
	if err != nil {
		return "", err
	}
	if _, _, err := wb.head(ctx); err != nil {
		return "", err
	}
	ms := wb.Meta().Merge
	if ms == nil {
		return "", fmt.Errorf("%s is not a merge workspace", ws)
	}
	var ps []string
	for _, p := range paths {
		rel := "/" + p
		if root != "" {
			full := p
			if !filepath.IsAbs(p) {
				full = filepath.Join(cwd, p)
			}
			r, err := filepath.Rel(root, full)
			if err != nil || strings.HasPrefix(r, "..") {
				return "", fmt.Errorf("%s is outside the merge workspace", p)
			}
			rel = "/" + r
		}
		rel = filepath.Clean(rel)
		if !slices.Contains(ms.Conflicts, rel) {
			return "", fmt.Errorf("%s is not in conflict", rel)
		}
		ps = append(ps, rel)
	}
	_, res, err := v.write(ctx, RecCommit, wb, []Op{{Kind: OpResolve, Branch: ws, Paths: ps, Time: time.Now().UnixNano()}})
	if err != nil {
		return "", err
	}
	if e := res[0].Errno; e != 0 {
		return "", e
	}
	left := len(ms.Conflicts) - len(ps)
	if left <= 0 {
		return "all conflicts resolved; run `blipfs merge --continue`\n", nil
	}
	return fmt.Sprintf("%d conflicts left\n", left), nil
}

// cmdPick runs cherry-pick (rev or a..b, squashed) and revert.
func (v *Vol) cmdPick(ctx context.Context, kind, spec, onto, cur string) (string, error) {
	var base, theirs Rev
	if lo, hi, ok := strings.Cut(spec, ".."); ok {
		if kind == "revert" {
			return "", errors.New("revert takes a single revision")
		}
		a, err := v.parseRev(ctx, lo, cur)
		if err != nil {
			return "", err
		}
		b, err := v.parseRev(ctx, hi, a.Branch)
		if err != nil {
			return "", err
		}
		if a.Branch != b.Branch || a.LSN >= b.LSN {
			return "", fmt.Errorf("%s: range must be on one branch, oldest first", spec)
		}
		base, theirs = a, b
	} else {
		r, err := v.parseRev(ctx, spec, cur)
		if err != nil {
			return "", err
		}
		b, err := v.branch(r.Branch)
		if err != nil {
			return "", err
		}
		c, err := b.findCommit(ctx, r.LSN)
		if err != nil {
			return "", err
		}
		if c.LSN <= b.Meta().Created {
			return "", fmt.Errorf("%s@%d creates the branch; nothing to %s", r.Branch, c.LSN, kind)
		}
		base, theirs = Rev{Branch: r.Branch, LSN: c.LSN - 1}, Rev{Branch: r.Branch, LSN: c.LSN}
		if kind == "revert" {
			base, theirs = theirs, base
		}
	}
	dst := onto
	if dst == "" {
		dst = cur
	}
	if dst == "" && kind == "revert" {
		dst = base.Branch
	}
	if dst == "" {
		return "", fmt.Errorf("%s: no destination; use --onto or run inside a mount", kind)
	}
	info := fmt.Sprintf("%s of %s", kind, spec)
	if kind == "revert" {
		info = fmt.Sprintf("revert of %s", base)
	} else if !strings.Contains(spec, "..") {
		info = fmt.Sprintf("cherry-pick of %s", theirs)
	} else {
		info = fmt.Sprintf("cherry-pick of %s..%d", base, theirs.LSN)
	}
	return v.apply3(ctx, mergeReq{kind: kind, dst: dst, base: base, theirs: theirs, info: info})
}

// --- diffs ---

type change struct {
	status byte
	path   string
	dir    bool
	a, b   uint64 // inode on each side
}

// treeChanges lists path-level changes from a to b.
func treeChanges(a, b Tree) ([]change, error) {
	byPath := map[string]*change{}
	inos := map[uint64]bool{}
	add := func(st byte, p string, dir bool, ai, bi uint64) {
		if c := byPath[p]; c != nil {
			if c.status != st {
				c.status = 'M'
			}
			c.a, c.b = max(c.a, ai), max(c.b, bi)
			return
		}
		byPath[p] = &change{st, p, dir, ai, bi}
	}
	join := func(t Tree, parent uint64, name string) string {
		p, _ := pathOf(t, parent)
		if p == "" {
			return ""
		}
		return strings.TrimSuffix(p, "/") + "/" + name
	}
	isDir := func(t Tree, ino uint64) bool {
		at, err := treeAttrOf(t, ino)
		return err == nil && at != nil && at.IsDir()
	}
	var err error
	derr := Diff(a, b, func(k, av, bv []byte) error {
		if len(k) < 9 {
			return nil
		}
		switch k[0] {
		case kDirent:
			parent, name := keyIno(k), string(k[9:])
			switch {
			case av == nil:
				ino := binary.BigEndian.Uint64(bv)
				if p := join(b, parent, name); p != "" {
					add('A', p, isDir(b, ino), 0, ino)
				}
			case bv == nil:
				ino := binary.BigEndian.Uint64(av)
				if p := join(a, parent, name); p != "" {
					add('D', p, isDir(a, ino), ino, 0)
				}
			default:
				ai, bi := binary.BigEndian.Uint64(av), binary.BigEndian.Uint64(bv)
				if p := join(b, parent, name); p != "" {
					add('M', p, isDir(b, bi), ai, bi)
				}
			}
		case kInode, kExtent, kXattr:
			inos[keyIno(k)] = true
		}
		return nil
	})
	if derr != nil {
		return nil, derr
	}
	for ino := range inos {
		aa, e1 := treeAttrOf(a, ino)
		ba, e2 := treeAttrOf(b, ino)
		if err = errors.Join(e1, e2); err != nil {
			return nil, err
		}
		if aa == nil || ba == nil || ba.IsDir() {
			continue
		}
		p, err := pathOf(b, ino)
		if err != nil {
			return nil, err
		}
		if p != "" && byPath[p] == nil {
			add('M', p, false, ino, ino)
		}
	}
	out := make([]change, 0, len(byPath))
	for _, c := range byPath {
		out = append(out, *c)
	}
	slices.SortFunc(out, func(x, y change) int { return strings.Compare(x.path, y.path) })
	return out, nil
}

func (v *Vol) fileText(ctx context.Context, t Tree, ino uint64) (string, bool, error) {
	if ino == 0 {
		return "", true, nil
	}
	at, err := treeAttrOf(t, ino)
	if err != nil || at == nil {
		return "", false, err
	}
	if !at.IsReg() {
		if at.Mode&syscall.S_IFMT == syscall.S_IFLNK {
			return at.Target + "\n", true, nil
		}
		return "", false, nil
	}
	if at.Size > maxPatch {
		return "", false, nil
	}
	buf := make([]byte, at.Size)
	if err := readExtents(ctx, v.chunks, t, ino, 0, buf); err != nil {
		return "", false, err
	}
	if isBinary(buf) {
		return "", false, nil
	}
	return string(buf), true, nil
}

// splitLines splits text into newline-terminated lines for difflib.
func splitLines(s string) []string {
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		return lines[:len(lines)-1]
	}
	lines[len(lines)-1] += "\n\\ No newline at end of file\n"
	return lines
}

func (v *Vol) writeDiff(ctx context.Context, sb *strings.Builder, a, b Tree) error {
	cs, err := treeChanges(a, b)
	if err != nil {
		return err
	}
	for _, c := range cs {
		suffix := ""
		if c.dir {
			suffix = "/"
		}
		fmt.Fprintf(sb, "%c %s%s\n", c.status, c.path, suffix)
	}
	for _, c := range cs {
		if c.dir {
			continue
		}
		at, okA, err := v.fileText(ctx, a, c.a)
		if err != nil {
			return err
		}
		bt, okB, err := v.fileText(ctx, b, c.b)
		if err != nil {
			return err
		}
		if !okA || !okB {
			if c.status == 'M' {
				fmt.Fprintf(sb, "\nbinary files a%s and b%s differ\n", c.path, c.path)
			}
			continue
		}
		if at == bt {
			continue
		}
		from, to := "a"+c.path, "b"+c.path
		if c.a == 0 {
			from = "/dev/null"
		}
		if c.b == 0 {
			to = "/dev/null"
		}
		d, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
			A: splitLines(at), B: splitLines(bt), FromFile: from, ToFile: to, Context: 3})
		if err != nil {
			return err
		}
		sb.WriteString("\n" + d)
		if !bytes.HasSuffix([]byte(d), []byte("\n")) {
			sb.WriteString("\n")
		}
	}
	return nil
}
