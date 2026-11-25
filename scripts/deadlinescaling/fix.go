// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// applyFixes rewrites each finding's duration to testwait.Deadline(duration).
// A file is left unchanged, and each of its findings reported, when rewriting
// would pick the wrong name or wrap a duration that already contains Deadline.
func applyFixes(findings []finding, stdout, stderr io.Writer) int {
	if len(findings) == 0 {
		return 0
	}
	byFile := map[string][]finding{}
	var order []string
	for _, f := range findings {
		if _, ok := byFile[f.path]; !ok {
			order = append(order, f.path)
		}
		byFile[f.path] = append(byFile[f.path], f)
	}
	skipped := 0
	for _, path := range order {
		n, err := fixFile(path, byFile[path], stdout, stderr)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "deadlinescaling: %v\n", err)
			return 2
		}
		skipped += n
	}
	if skipped > 0 {
		return 1
	}
	return 0
}

func fixFile(path string, findings []finding, stdout, stderr io.Writer) (int, error) {
	// #nosec G304 -- path is a test file the gate already enumerated, not request input.
	src, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	if reason := fileSkipReason(file); reason != "" {
		for _, f := range findings {
			_, _ = fmt.Fprintf(stderr, "skip %s:%d:%d: %s\n", f.path, f.line, f.col, reason)
		}
		return len(findings), nil
	}
	name, ok := testwaitLocalName(file)
	if !ok {
		for _, f := range findings {
			_, _ = fmt.Fprintf(stderr, "skip %s:%d:%d: testwait import cannot be named\n", f.path, f.line, f.col)
		}
		return len(findings), nil
	}
	edits := make([]finding, 0, len(findings))
	seen := map[[2]int]bool{}
	skipped := 0
	for _, f := range findings {
		key := [2]int{f.start, f.end}
		if seen[key] {
			continue
		}
		seen[key] = true
		if f.start < 0 || f.end > len(src) || f.start > f.end {
			return 0, fmt.Errorf("rewrite %s: duration offsets %d:%d outside the file", path, f.start, f.end)
		}
		exprSrc := src[f.start:f.end]
		expr, err := parser.ParseExpr(string(exprSrc))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "skip %s:%d:%d: duration expression did not reparse: %v\n", f.path, f.line, f.col, err)
			skipped++
			continue
		}
		if containsDeadline(expr) {
			_, _ = fmt.Fprintf(stderr, "skip %s:%d:%d: duration already contains Deadline\n", f.path, f.line, f.col)
			skipped++
			continue
		}
		edits = append(edits, f)
	}
	if len(edits) == 0 {
		return skipped, nil
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	for _, f := range edits {
		wrapped := name + ".Deadline(" + string(src[f.start:f.end]) + ")"
		src = splice(src, f.start, f.end, wrapped)
	}
	if !hasImport(file, testwaitPath) {
		src, err = insertImport(src, testwaitPath, importSpec(name))
		if err != nil {
			return 0, err
		}
	}
	fset = token.NewFileSet()
	if _, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution); err != nil {
		return 0, fmt.Errorf("rewritten %s does not parse: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	mode := info.Mode().Perm()
	if mode == 0 {
		mode = 0o600
	}
	if err := os.WriteFile(path, src, mode); err != nil {
		return 0, fmt.Errorf("write %s: %w", path, err)
	}
	_, _ = fmt.Fprintf(stdout, "fixed %s (%d)\n", path, len(edits))
	return skipped, nil
}

func importSpec(localName string) string {
	if localName == "" || localName == "testwait" {
		return strconv.Quote(testwaitPath)
	}
	return localName + " " + strconv.Quote(testwaitPath)
}

func testwaitLocalName(f *ast.File) (string, bool) {
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != testwaitPath {
			continue
		}
		if imp.Name == nil {
			return "testwait", true
		}
		if imp.Name.Name == "." || imp.Name.Name == "_" {
			return "", false
		}
		return imp.Name.Name, true
	}
	return "testwait", true
}

func hasImport(f *ast.File, path string) bool {
	for _, imp := range f.Imports {
		got, err := strconv.Unquote(imp.Path.Value)
		if err == nil && got == path {
			return true
		}
	}
	return false
}

func fileSkipReason(f *ast.File) string {
	if f.Name != nil && f.Name.Name == "testwait" {
		return "package testwait"
	}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		local := ""
		if imp.Name != nil {
			local = imp.Name.Name
		}
		if local == "." && path == testwaitPath {
			return "dot-import of testwait"
		}
		if local == "testwait" && path != testwaitPath {
			return "import name testwait is not " + testwaitPath
		}
	}
	if declares(f, "testwait") {
		return "local identifier named testwait"
	}
	return ""
}

func declares(f *ast.File, name string) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.FuncDecl:
			found = x.Name != nil && x.Name.Name == name
		case *ast.TypeSpec:
			found = x.Name != nil && x.Name.Name == name
		case *ast.ValueSpec:
			for _, id := range x.Names {
				if id != nil && id.Name == name {
					found = true
				}
			}
		case *ast.AssignStmt:
			if x.Tok != token.DEFINE {
				return true
			}
			for _, lhs := range x.Lhs {
				id, ok := lhs.(*ast.Ident)
				if ok && id.Name == name {
					found = true
				}
			}
		case *ast.RangeStmt:
			if x.Tok != token.DEFINE {
				return true
			}
			for _, e := range []ast.Expr{x.Key, x.Value} {
				id, ok := e.(*ast.Ident)
				if ok && id != nil && id.Name == name {
					found = true
				}
			}
		case *ast.Field:
			for _, id := range x.Names {
				if id != nil && id.Name == name {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

func splice(src []byte, start, end int, text string) []byte {
	out := make([]byte, 0, len(src)-(end-start)+len(text))
	out = append(out, src[:start]...)
	out = append(out, text...)
	out = append(out, src[end:]...)
	return out
}

func insertImport(src []byte, importPath, spec string) ([]byte, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("insert import: %w", err)
	}
	if hasImport(f, importPath) {
		return src, nil
	}
	var imp *ast.GenDecl
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if ok && gd.Tok == token.IMPORT {
			imp = gd
			break
		}
	}
	if imp == nil {
		end := fset.Position(f.Name.End()).Offset
		nl := bytes.IndexByte(src[end:], '\n')
		if nl < 0 {
			return nil, fmt.Errorf("insert import: package clause has no newline")
		}
		return splice(src, end+nl+1, end+nl+1, "\nimport "+spec+"\n"), nil
	}
	if !imp.Lparen.IsValid() {
		ispec, ok := imp.Specs[0].(*ast.ImportSpec)
		if !ok {
			return nil, fmt.Errorf("insert import: import declaration has no spec")
		}
		start := fset.Position(imp.Pos()).Offset
		end := fset.Position(imp.End()).Offset
		existing := importText(src, fset, ispec)
		path, _ := strconv.Unquote(ispec.Path.Value)
		var b strings.Builder
		b.WriteString("import (\n\t")
		b.WriteString(existing)
		b.WriteByte('\n')
		if isStdlibImport(path) {
			b.WriteByte('\n')
		}
		b.WriteByte('\t')
		b.WriteString(spec)
		b.WriteString("\n)")
		return splice(src, start, end, b.String()), nil
	}
	lastThird := -1
	for i, sp := range imp.Specs {
		ispec, ok := sp.(*ast.ImportSpec)
		if !ok {
			continue
		}
		path, err := strconv.Unquote(ispec.Path.Value)
		if err != nil {
			continue
		}
		if !isStdlibImport(path) {
			lastThird = i
		}
	}
	if lastThird >= 0 {
		at := fset.Position(imp.Specs[lastThird].End()).Offset
		return splice(src, at, at, "\n\t"+spec), nil
	}
	rparen := fset.Position(imp.Rparen).Offset
	return splice(src, rparen, rparen, "\n\n\t"+spec+"\n"), nil
}

func importText(src []byte, fset *token.FileSet, spec *ast.ImportSpec) string {
	start := fset.Position(spec.Pos()).Offset
	end := fset.Position(spec.End()).Offset
	return string(src[start:end])
}

func isStdlibImport(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}
