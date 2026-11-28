// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package readerinventory

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Match evidence operands rather than generic operands called dir or path.
// The recorder API check also catches reads of evidence passed opaquely.
var evidencePath = regexp.MustCompile(`(?i)(receipt[-_]?v[0-9]|deferred-actions\.jsonl|evidence-|(?:receipt|evidence|recorder)(?:dir|root|file|path))`)

func receiptReads(t *testing.T, root, pkg string, files []string) []string {
	t.Helper()
	var reads []string
	for _, name := range files {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(root, pkg, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		imports := make(map[string]string)
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			alias := filepath.Base(path)
			if spec.Name != nil {
				alias = spec.Name.Name
			}
			imports[alias] = path
		}
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			inspectReceiptReads(fn, imports, func(pos token.Pos) {
				reads = append(reads, name+":"+strconv.Itoa(fset.Position(pos).Line))
			})
		}
	}
	return reads
}

func inspectReceiptReads(fn *ast.FuncDecl, imports map[string]string, found func(token.Pos)) {
	paths := make(map[string]bool)
	// Resolve local aliases like dir := cfg.FlightRecorder.Dir before
	// inspecting the reader; retain the original lexical operand too.
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if assign, ok := node.(*ast.AssignStmt); ok && len(assign.Lhs) == len(assign.Rhs) {
			for i, lhs := range assign.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && isEvidenceOperand(assign.Rhs[i], paths) {
					paths[id.Name] = true
				}
			}
		}
		return true
	})
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		switch imports[recv.Name] {
		case "os", "io/fs", "path/filepath":
			if slices.Contains([]string{"Open", "ReadFile", "ReadDir", "Glob", "Walk", "WalkDir"}, sel.Sel.Name) &&
				slices.ContainsFunc(call.Args, func(arg ast.Expr) bool { return isEvidenceOperand(arg, paths) }) {
				found(call.Pos())
			}
		case module + "internal/recorder":
			if sel.Sel.Name == "OpenEvidenceFile" && isEvidenceOperand(call.Args[0], paths) {
				found(call.Pos())
			}
			if slices.Contains([]string{"ReadEntries", "DiscoverEvidenceLocations", "ResolveEvidenceLocation", "ListSessions", "ListSessionsBounded", "Query"}, sel.Sel.Name) ||
				strings.HasPrefix(sel.Sel.Name, "ReadEvidenceLocation") {
				found(call.Pos())
			}
		case module + "internal/deferred":
			if sel.Sel.Name == "PendingJournal" {
				found(call.Pos())
			}
		case module + "internal/evidence/receiptinput":
			if slices.Contains([]string{"Claims", "ClaimsInput", "ClaimsDirectory", "Refuse", "RefuseTree", "RefuseLocation", "RefusePayload"}, sel.Sel.Name) {
				found(call.Pos())
			}
		}
		return true
	})
}

func isEvidenceOperand(expr ast.Expr, paths map[string]bool) bool {
	match := false
	ast.Inspect(expr, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.Ident:
			match = match || paths[node.Name] || evidencePath.MatchString(node.Name)
		case *ast.SelectorExpr:
			base, ok := node.X.(*ast.SelectorExpr)
			match = match || ok && base.Sel.Name == "FlightRecorder" && node.Sel.Name == "Dir"
		case *ast.BasicLit:
			match = match || node.Kind == token.STRING && evidencePath.MatchString(node.Value)
		}
		return !match
	})
	return match
}
