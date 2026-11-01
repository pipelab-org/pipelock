// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package testexec_test

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// execWriteBaseline lists, per test file, how many executable fixtures are
// still written without this package. The count may only go down: a new
// site, or a site in a file that is not listed, fails the guard.
const execWriteBaseline = "testdata/exec-write-baseline.txt"

// TestNoNewExecutableFixtureWrites keeps new tests from writing a file with
// an execute bit through os.WriteFile or os.OpenFile, or making a file they
// just wrote executable with os.Chmod. Such a file can fail to run with
// "text file busy" when a parallel test forks while it is still open; use
// WriteExecutable or Write instead.
func TestNoNewExecutableFixtureWrites(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)
	got, err := scanExecWrites(root)
	if err != nil {
		t.Fatal(err)
	}
	want := readExecWriteBaseline(t)
	for _, path := range sortedKeys(got, want) {
		switch g, w := got[path], want[path]; {
		case g > w:
			t.Errorf("%s writes %d executable fixture(s) without internal/testexec (baseline %d); use testexec.WriteExecutable or testexec.Write", path, g, w)
		case g < w:
			t.Errorf("%s now writes %d executable fixture(s) without internal/testexec; lower its baseline from %d in internal/testexec/%s", path, g, w, execWriteBaseline)
		}
	}
}

// TestExecWriteScanFindsEachShape checks the scanner on the shapes it must
// report and on writes it must leave alone.
func TestExecWriteScanFindsEachShape(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `package p

import (
	"os"
	osx "os"
)

func flagged(p string) {
	_ = os.WriteFile(p, nil, 0o755)
	_ = osx.WriteFile(p, nil, 0700)
	f, _ := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o700)
	_ = f
	_ = os.WriteFile(p+".sh", nil, 0o600)
	_ = os.Chmod(p+".sh", 0o700)
}

func ignored(p, dir string) {
	_ = os.WriteFile(p, nil, 0o600)
	_ = os.Chmod(dir, 0o700)
	_ = os.MkdirAll(dir, 0o755)
}
`
	if err := os.WriteFile(filepath.Join(dir, "shapes_test.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plain.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := scanExecWrites(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]int{"shapes_test.go": 4}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("scan = %v, want %v", got, want)
	}
}

// scanExecWrites returns, per slash-separated path under root, the number of
// executable fixture writes in _test.go files outside this package.
func scanExecWrites(root string) (map[string]int, error) {
	out := map[string]int{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" || d.Name() == "vendor" || d.Name() == "node_modules" || rel == "internal/testexec") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		if n := countExecWrites(f); n > 0 {
			out[rel] = n
		}
		return nil
	})
	return out, err
}

func countExecWrites(f *ast.File) int {
	osNames := map[string]bool{}
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == "os" {
			name := "os"
			if imp.Name != nil {
				name = imp.Name.Name
			}
			osNames[name] = true
		}
	}
	if len(osNames) == 0 {
		return 0
	}
	osCall := func(call *ast.CallExpr) string {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		if id, ok := sel.X.(*ast.Ident); ok && osNames[id.Name] {
			return sel.Sel.Name
		}
		return ""
	}
	n := 0
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		written := map[string]bool{}
		ast.Inspect(fd.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch name := osCall(call); {
			case (name == "WriteFile" || name == "OpenFile") && len(call.Args) == 3:
				if execBits(call.Args[2]) {
					n++
				} else {
					written[types.ExprString(call.Args[0])] = true
				}
			case name == "Create" && len(call.Args) == 1:
				written[types.ExprString(call.Args[0])] = true
			case name == "Chmod" && len(call.Args) == 2:
				if execBits(call.Args[1]) && written[types.ExprString(call.Args[0])] {
					n++
				}
			}
			return true
		})
	}
	return n
}

// execBits reports whether a literal file mode sets any execute bit.
func execBits(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return false
	}
	v, err := strconv.ParseUint(strings.ReplaceAll(lit.Value, "_", ""), 0, 32)
	if err != nil {
		v, err = strconv.ParseUint(strings.ReplaceAll(lit.Value, "_", ""), 8, 32)
	}
	return err == nil && v&0o111 != 0
}

func readExecWriteBaseline(t *testing.T) map[string]int {
	t.Helper()
	f, err := os.Open(execWriteBaseline)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]int{}
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		path, count, ok := strings.Cut(text, " ")
		n, err := strconv.Atoi(strings.TrimSpace(count))
		if !ok || err != nil || n < 1 {
			t.Fatalf("%s:%d: want \"path count\", got %q", execWriteBaseline, line, text)
		}
		out[path] = n
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}

func sortedKeys(a, b map[string]int) []string {
	seen := map[string]bool{}
	var keys []string
	for _, m := range []map[string]int{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	return keys
}
