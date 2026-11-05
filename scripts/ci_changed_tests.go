//go:build ignore

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Select added or changed top-level tests from two Git revisions. This uses
// go/parser rather than diff hunks so body-only edits and multiline declarations
// have the same meaning. Build constraints are resolved by go list in the runner.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type test struct {
	File    string `json:"file"`
	Package string `json:"package"`
	Name    string `json:"name"`
	// New is false when the package already declared this test name at the
	// base, even in another file. Partial package weights add only new tests.
	New    bool   `json:"new"`
	Source string `json:"-"`
	ident  string
}

func git(args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %v: %w: %s", args, err, stderr.String())
	}
	return out, nil
}

// Match cmd/go/internal/load's isTestFunc shape: *T or *something.T.
// The compiler resolves aliases; TestMain(*testing.M) isn't a runnable test.
func isTest(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") ||
		fn.Type.TypeParams != nil || fn.Type.Results != nil && len(fn.Type.Results.List) > 0 || len(fn.Type.Params.List) != 1 {
		return false
	}
	param := fn.Type.Params.List[0]
	if len(param.Names) > 1 {
		return false
	}
	ptr, ok := param.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	if name, ok := ptr.X.(*ast.Ident); ok && name.Name == "T" {
		return true
	}
	if sel, ok := ptr.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "T" {
		return true
	}
	return false
}

func inventory(ref string, files []string) (map[string]test, error) {
	tests := make(map[string]test)
	for _, file := range files {
		source, err := git("show", ref+":"+file)
		if err != nil {
			return nil, err
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, source, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s:%s: %w", ref, file, err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !isTest(fn) {
				continue
			}
			tail := strings.TrimPrefix(fn.Name.Name, "Test")
			first, _ := utf8.DecodeRuneInString(tail)
			// cmd/go's test-name rule: Test followed by a non-lowercase rune.
			if tail != "" && unicode.IsLower(first) {
				continue
			}
			var formatted bytes.Buffer
			if err := format.Node(&formatted, fset, fn); err != nil {
				return nil, err
			}
			item := test{
				File: file, Package: "./" + path.Dir(file), Name: fn.Name.Name, Source: formatted.String(),
				ident: path.Dir(file) + "/" + parsed.Name.Name + "/" + fn.Name.Name,
			}
			// Include the file: mutually exclusive build-tagged files may declare
			// the same test name with different bodies.
			key := file + "/" + parsed.Name.Name + "/" + fn.Name.Name
			tests[key] = item
		}
	}
	return tests, nil
}

// cmd/go ignores dot/underscore directories and testdata during ./... walks.
func testSource(file string) bool {
	if !strings.HasSuffix(file, "_test.go") || strings.HasPrefix(path.Base(file), "_") || strings.HasPrefix(path.Base(file), ".") {
		return false
	}
	for _, part := range strings.Split(path.Dir(file), "/") {
		if part == "testdata" || part == "vendor" || strings.HasPrefix(part, ".") && part != "." || strings.HasPrefix(part, "_") {
			return false
		}
	}
	return true
}

func selectTests(base, head string) ([]test, error) {
	// Parse every test file in directories touched by a test-source change. This
	// keeps moves/deletions correct without parsing the entire repository twice.
	diff, err := git("diff", "--name-only", "--no-renames", "-z", base, head, "--", "*_test.go")
	if err != nil {
		return nil, err
	}
	dirs := make(map[string]bool)
	for _, file := range strings.Split(string(diff), "\x00") {
		if testSource(file) {
			dirs[path.Dir(file)] = true
		}
	}
	inventories := make([]map[string]test, 0, 2)
	for _, ref := range []string{base, head} {
		files := []string{}
		if len(dirs) > 0 {
			tree, err := git("ls-tree", "-r", "--name-only", "-z", ref)
			if err != nil {
				return nil, err
			}
			for _, file := range strings.Split(string(tree), "\x00") {
				if testSource(file) && dirs[path.Dir(file)] {
					files = append(files, file)
				}
			}
		}
		tests, err := inventory(ref, files)
		if err != nil {
			return nil, err
		}
		inventories = append(inventories, tests)
	}
	declared := make(map[string]bool, len(inventories[0]))
	for _, item := range inventories[0] {
		declared[item.ident] = true
	}
	changed := []test{}
	for key, item := range inventories[1] {
		old, exists := inventories[0][key]
		if !exists || old.Source != item.Source {
			item.New = !declared[item.ident]
			changed = append(changed, item)
		}
	}
	sort.Slice(changed, func(i, j int) bool {
		if changed[i].File == changed[j].File {
			return changed[i].Name < changed[j].Name
		}
		return changed[i].File < changed[j].File
	})
	return changed, nil
}

func main() {
	base := flag.String("base", "", "base Git revision (normally the merge base)")
	head := flag.String("head", "HEAD", "head Git revision")
	flag.Parse()
	if *base == "" {
		fmt.Fprintln(os.Stderr, "--base is required")
		os.Exit(2)
	}
	tests, err := selectTests(*base, *head)
	if err == nil {
		err = json.NewEncoder(os.Stdout).Encode(tests)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
