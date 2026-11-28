// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package readerinventory

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestMixedReceiptProfileOptIns(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	// Entries bind the caller as well as the opted-in function. Allow internal
	// mode propagation only in the recorder's own implementation.
	want := map[string]int{
		"internal/receipt/group_inventory.go:walkLegacySessionHistory:ResolveEvidenceLocation":                1,
		"internal/receipt/group_legacy_index_wasm.go:indexRecorderFilesExcludingGroupsSpill:EvidenceLocation": 1,
		"internal/receipt/group_verify.go:verifyReceiptGroupScoped:append":                                    1,
		"internal/receipt/v3/legacy.go:verifyLegacy:EvidenceLocation":                                         1,
		"internal/receipt/v3/legacy.go:legacyContinuityLabel:VerifyBase":                                      1,
		"internal/receipt/v3/command/command.go:ResolveDirectory:ResolveEvidenceLocation":                     1,
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
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		references, raw := profileModeReferences(file)
		if raw != 0 {
			t.Errorf("%s has %d raw EvidenceReadMode literal conversions; use named modes", relative, raw)
		}
		if relative == "internal/recorder/discovery.go" {
			return nil
		}
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

func profileModeReferences(file *ast.File) (named, raw int) {
	recorderNames := make(map[string]bool)
	if file.Name.Name == "recorder" {
		recorderNames["."] = true
	}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != "github.com/luckyPipewrench/pipelock/internal/recorder" {
			continue
		}
		name := "recorder"
		if spec.Name != nil {
			name = spec.Name.Name
		}
		recorderNames[name] = true
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.Ident:
			if n.Name == "MixedReceiptProfiles" {
				named++
			}
		case *ast.CallExpr:
			if len(n.Args) == 1 && isRecorderReadMode(n.Fun, recorderNames) && isModeLiteral(n.Args[0]) {
				raw++
			}
		}
		return true
	})
	return named, raw
}

func isRecorderReadMode(expr ast.Expr, names map[string]bool) bool {
	switch expr := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return expr.Name == "EvidenceReadMode" && names["."]
	case *ast.SelectorExpr:
		qualifier, ok := expr.X.(*ast.Ident)
		return ok && expr.Sel.Name == "EvidenceReadMode" && names[qualifier.Name]
	default:
		return false
	}
}

func isModeLiteral(expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if unary, ok := expr.(*ast.UnaryExpr); ok {
		expr = ast.Unparen(unary.X)
	}
	_, literal := expr.(*ast.BasicLit)
	return literal
}

func TestProfileModeReferencesRejectLiteralConversions(t *testing.T) {
	source := `package sample
import r "github.com/luckyPipewrench/pipelock/internal/recorder"
var _ = r.EvidenceReadMode(1)
var _ = r.EvidenceReadMode((+1))
var _ = r.EvidenceReadMode(0)
var _ = r.MixedReceiptProfiles
var _ = other.EvidenceReadMode(1)
`
	file, err := parser.ParseFile(token.NewFileSet(), "sample.go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	named, raw := profileModeReferences(file)
	if named != 1 || raw != 3 {
		t.Fatalf("mode references = %d named, %d raw; want 1 named, 3 raw", named, raw)
	}
}

// An untyped constant converts to any integer-based mode silently, so a call
// such as DiscoverEvidenceLocations(dir, 1) would opt in without naming
// MixedReceiptProfiles. The mode must be a struct that only the recorder can
// build as mixed.
func TestEvidenceReadModeCannotBeForged(t *testing.T) {
	path := filepath.Join("..", "..", "recorder", "discovery.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.TypeSpec)
		if !ok || spec.Name.Name != "EvidenceReadMode" {
			return true
		}
		found = true
		structure, isStruct := spec.Type.(*ast.StructType)
		if !isStruct {
			t.Errorf("EvidenceReadMode is %T; a numeric type lets a literal opt in", spec.Type)
			return false
		}
		for _, field := range structure.Fields.List {
			for _, name := range field.Names {
				if name.IsExported() {
					t.Errorf("EvidenceReadMode field %s is exported and can be set outside the recorder", name.Name)
				}
			}
		}
		return false
	})
	if !found {
		t.Fatal("recorder.EvidenceReadMode is missing")
	}
}
