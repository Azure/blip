package sim

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
)

// Catch accidental platform access in the production decision cores. This is
// a direct dependency guard, not a proof of transitive purity: helpers called
// by a core must obey the same explicit-input discipline during review.
func TestProductionCoreBoundaries(t *testing.T) {
	for _, name := range []string{
		"atomicfile/atomicfile.go",
		"node/scheduler.go",
		"node/scheduler_snapshot.go",
		"node/plan.go",
		"node/planner.go",
		"runtime/machine.go",
		"runtime/snapshot.go",
		"stream/stream.go",
		"workspace/fork.go",
		// guest stdio is exercised by internal/guest tests.
	} {
		t.Run(name, func(t *testing.T) {
			set := token.NewFileSet()
			file, err := parser.ParseFile(set, filepath.Join("..", name), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			timeName := "time"
			for _, spec := range file.Imports {
				path, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				switch path {
				case "os", "os/exec", "net", "net/http", "syscall", "golang.org/x/sys/unix", "math/rand", "math/rand/v2", "crypto/rand":
					t.Errorf("%s: platform dependency %q belongs in the effect adapter", set.Position(spec.Pos()), path)
				case "time":
					if spec.Name != nil {
						timeName = spec.Name.Name
						if timeName == "." {
							t.Error("dot-imported time bypasses the explicit-clock guard")
						}
					}
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				if _, ok := n.(*ast.GoStmt); ok {
					t.Errorf("%s: goroutine belongs in the effect adapter", set.Position(n.Pos()))
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := selector.X.(*ast.Ident)
				if !ok || pkg.Name != timeName {
					return true
				}
				switch selector.Sel.Name {
				case "Now", "Since", "Until", "Sleep", "After", "AfterFunc", "Tick", "NewTimer", "NewTicker":
					t.Errorf("%s: %s requires an explicit time input or effect", set.Position(call.Pos()), selector.Sel.Name)
				}
				return true
			})
		})
	}
}
