// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestMCPReceiptCallsitesStayV2Paired guards the maintenance invariant behind
// MCP receipt parity: production call sites that emit an authoritative v1 MCP
// receipt must also pass the v2 proxy_decision emitter into the same emission
// helper. Runtime tests cover representative stdio, HTTP listener, and A2A
// paths; this catches future v1-only receipt emit sites before they ship.
func TestMCPReceiptCallsitesStayV2Paired(t *testing.T) {
	t.Parallel()

	dir := mcpPackageDir(t)
	fset, files := parseMCPProductionFiles(t, dir)
	for _, file := range files {
		ast.Inspect(file.file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if callName(node.Fun) == "EmitMCPDecision" {
					assertEmitMCPDecisionV2Paired(t, fset, node)
				}
			case *ast.CompositeLit:
				if typeName(node.Type) == "mcpToolReceiptOpts" {
					assertToolReceiptOptsV2Paired(t, fset, node)
				}
			}
			return true
		})
	}
}

func TestMCPV1ReceiptEmissionStaysFunnelled(t *testing.T) {
	t.Parallel()

	dir := mcpPackageDir(t)
	fset, files := parseMCPProductionFiles(t, dir)
	for _, file := range files {
		ast.Inspect(file.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Emit" && sel.Sel.Name != "EmitDurable") {
				return true
			}
			if file.name != "pipeline_decision.go" {
				t.Fatalf("%s: MCP emitter calls must stay funnelled through EmitMCPDecision", fset.Position(call.Pos()))
			}
			return true
		})
	}
}

type mcpProductionFile struct {
	name string
	file *ast.File
}

func parseMCPProductionFiles(t *testing.T, dir string) (*token.FileSet, []mcpProductionFile) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	fset := token.NewFileSet()
	var files []mcpProductionFile
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", path, err)
		}
		files = append(files, mcpProductionFile{
			name: entry.Name(),
			file: file,
		})
	}
	return fset, files
}

func assertEmitMCPDecisionV2Paired(t *testing.T, fset *token.FileSet, call *ast.CallExpr) {
	t.Helper()
	if len(call.Args) < 2 {
		t.Fatalf("%s: EmitMCPDecision call has %d args, want at least 2", fset.Position(call.Pos()), len(call.Args))
	}
	if exprIsNil(call.Args[0]) {
		return
	}
	if exprIsNil(call.Args[1]) {
		t.Fatalf("%s: EmitMCPDecision emits v1 receipt without paired v2 emitter", fset.Position(call.Pos()))
	}
}

func assertToolReceiptOptsV2Paired(t *testing.T, fset *token.FileSet, lit *ast.CompositeLit) {
	t.Helper()
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "ProxyOpts" {
			continue
		}
		// The snapshot-aware funnel obtains both emitters from these options.
		// Explicit literals must retain the pairing; normal callers carry the
		// admission snapshot rather than reconstructing a subset of its fields.
		if proxy, ok := kv.Value.(*ast.CompositeLit); ok {
			var hasV1, hasV2 bool
			for _, e := range proxy.Elts {
				field, ok := e.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				switch callName(field.Key) {
				case "ReceiptEmitter":
					hasV1 = !exprIsNil(field.Value)
				case "V2ReceiptEmitter":
					hasV2 = !exprIsNil(field.Value)
				}
			}
			if hasV1 && !hasV2 {
				t.Errorf("%s: MCP snapshot sets v1 without paired v2 emitter", fset.Position(proxy.Pos()))
			}
		}
		return
	}
	t.Errorf("%s: tool receipt omits scanner policy snapshot", fset.Position(lit.Pos()))
}

func mcpPackageDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(file)
}

func callName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	default:
		return ""
	}
}

func typeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.StarExpr:
		return typeName(e.X)
	default:
		return ""
	}
}

func exprIsNil(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "nil"
}

// Outcomes inherit their intent's bound options. Envelope-only emission has no
// signed emitters. Other callers must use the snapshot-aware opts funnel.
func TestMCPReceiptPolicyBindingStaysFunnelled(t *testing.T) {
	fset, files := parseMCPProductionFiles(t, mcpPackageDir(t))
	allowed := map[string]bool{
		"opts.go:emitMCPReceiptDecision":                      true,
		"pipeline_decision.go:emitMCPOutcome":                 true,
		"pipeline_decision.go:emitMCPStandaloneStreamReceipt": true,
		"pipeline_decision.go:emitMCPEnvelopeDecision":        true,
		"pipeline_decision.go:EmitMCPDecision":                true,
		"pipeline_decision.go:EmitMCPGroupDecision":           true,
	}
	var checked int
	for _, file := range files {
		for _, decl := range file.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := callName(call.Fun)
				if name != "EmitMCPDecision" && name != "EmitMCPGroupDecision" && name != "emitMCPDecision" {
					return true
				}
				checked++
				if !allowed[file.name+":"+fn.Name.Name] {
					t.Errorf("%s: direct %s bypasses receipt policy binding", fset.Position(call.Pos()), name)
				}
				return true
			})
		}
	}
	if checked == 0 {
		t.Fatal("guard did not find the known emission funnel")
	}
}
