// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package readerinventory

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestMixedReceiptProfileOptIns(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	// Entries bind the caller as well as the opted-in function. Allow internal
	// mode propagation only in the recorder's own implementation.
	want := map[string]int{
		"internal/receipt/v3/legacy.go:verifyLegacy:VerifyReceiptGroups":                       1,
		"internal/receipt/v3/legacy.go:verifyLegacy:ResolveBaseSessionsExcludingReceiptGroups": 1,
		"internal/receipt/v3/legacy.go:verifyLegacy:EvidenceLocation":                          1,
		"internal/receipt/v3/legacy.go:verifyLegacyContinuity:VerifyBase":                      1,
	}
	got := make(map[string]int)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "internal/recorder/discovery.go" {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		var references int
		ast.Inspect(file, func(node ast.Node) bool {
			if id, ok := node.(*ast.Ident); ok && id.Name == "MixedReceiptProfiles" {
				references++
			}
			return true
		})
		var expected int
		for call, count := range want {
			if strings.HasPrefix(call, relative+":") {
				expected += count
			}
		}
		if references != expected {
			t.Errorf("%s has %d mixed-profile references, want %d", relative, references, expected)
		}
		countProfileOptIns(file, relative, got)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for call, count := range got {
		if count != want[call] {
			t.Errorf("%s opts in %d times, want %d", call, count, want[call])
		}
	}
	for call, count := range want {
		if got[call] == 0 {
			t.Errorf("%s opts in 0 times, want %d", call, count)
		}
	}
}

func countProfileOptIns(file *ast.File, path string, counts map[string]int) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.CallExpr:
				for _, arg := range n.Args {
					if isMixedProfileMode(arg) {
						counts[path+":"+fn.Name.Name+":"+expressionName(n.Fun)]++
					}
				}
			case *ast.CompositeLit:
				for _, elt := range n.Elts {
					if field, ok := elt.(*ast.KeyValueExpr); ok && isMixedProfileMode(field.Value) {
						counts[path+":"+fn.Name.Name+":"+expressionName(n.Type)]++
					}
				}
			}
			return true
		})
	}
}

func isMixedProfileMode(expr ast.Expr) bool {
	return expressionName(expr) == "MixedReceiptProfiles"
}

func expressionName(expr ast.Expr) string {
	switch x := expr.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	default:
		return ""
	}
}
