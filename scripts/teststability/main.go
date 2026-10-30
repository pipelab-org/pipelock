// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Command teststability reports test code that defeats testport.WithRetry.
//
// WithRetry reruns its callback on a fresh port only when the callback
// returns a bind-collision error. A t.Fatal, t.FailNow, t.Skip, or require
// call inside the callback, or inside a helper the callback calls, ends the
// test before WithRetry sees the error, so a lost port race fails the run
// instead of retrying. Findings print as path:line:source so the stability
// allowlist can match them exactly.
package main

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// stopNames are the testing.TB methods that end a test from the calling
// goroutine.
var stopNames = map[string]bool{
	"Fatal": true, "Fatalf": true, "FailNow": true,
	"Skip": true, "Skipf": true, "SkipNow": true,
}

type finding struct {
	path string
	line int
	why  string
}

type pkgFiles struct {
	files []*ast.File
	paths []string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run scans the given test files and returns the exit status: 0 when clean,
// 1 when it reports findings, 2 when it cannot scan.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "teststability: no test files given; refusing an empty scan")
		return 2
	}
	out, err := analyze(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "teststability: %v\n", err)
		return 2
	}
	lines := map[string][]string{}
	for _, f := range out {
		src := sourceLine(lines, f.path, f.line)
		_, _ = fmt.Fprintf(stdout, "%s:%d:%s\n", f.path, f.line, src)
		_, _ = fmt.Fprintf(stderr, "  %s:%d: %s\n", f.path, f.line, f.why)
	}
	if len(out) > 0 {
		return 1
	}
	return 0
}

// analyze parses the _test.go files among paths, grouped by directory and
// package, and returns the findings sorted by position.
func analyze(paths []string) ([]finding, error) {
	fset := token.NewFileSet()
	pkgs := map[string]*pkgFiles{}
	for _, path := range paths {
		if !strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		key := filepath.Dir(path) + "\x00" + f.Name.Name
		p := pkgs[key]
		if p == nil {
			p = &pkgFiles{}
			pkgs[key] = p
		}
		p.files = append(p.files, f)
		p.paths = append(p.paths, path)
	}
	var out []finding
	for _, p := range pkgs {
		out = append(out, checkPackage(fset, p)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].path != out[j].path {
			return out[i].path < out[j].path
		}
		return out[i].line < out[j].line
	})
	return out, nil
}

// checkPackage finds WithRetry callbacks in one package and reports every
// test-ending call they can reach through package-local helpers.
func checkPackage(fset *token.FileSet, p *pkgFiles) []finding {
	decls := map[string]*ast.FuncDecl{}
	for _, f := range p.files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Body != nil {
				decls[fd.Name.Name] = fd
			}
		}
	}
	exitPath := map[token.Pos]bool{}
	for _, f := range p.files {
		markExitPathStops(f, exitPath)
	}
	observers := exitObservers(decls)
	for _, f := range p.files {
		markObserverResultStops(f, observers, exitPath)
	}
	stops := stoppingHelpers(decls, exitPath)
	unexcluded := unexcludedUpstreamHelpers(fset, decls)
	var out []finding
	seen := map[token.Pos]bool{}
	for _, f := range p.files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isWithRetry(call) || len(call.Args) == 0 {
				return true
			}
			lit, ok := call.Args[len(call.Args)-1].(*ast.FuncLit)
			if !ok {
				return true
			}
			for _, pos := range unexcludedInBody(lit.Body) {
				if !seen[pos] {
					seen[pos] = true
					p := fset.Position(pos)
					out = append(out, finding{path: p.Filename, line: p.Line, why: "readiness wait does not exclude a test server started inside this testport.WithRetry callback; that server can take a just-released port, so pass it to the wait"})
				}
			}
			ast.Inspect(lit.Body, func(m ast.Node) bool {
				inner, ok := m.(*ast.CallExpr)
				if !ok || seen[inner.Pos()] {
					return true
				}
				why := ""
				switch {
				case exitPath[inner.Pos()]:
					why = "test-ending call on a run-exit receive inside a testport.WithRetry callback; return the received error so a bind collision can retry"
				default:
					if name := localCallee(inner); name != "" && stops[name] {
						why = fmt.Sprintf("%s ends the test on a run-exit receive and is called from a testport.WithRetry callback; give it an error-returning form", name)
					} else if name != "" && unexcluded[name] {
						why = fmt.Sprintf("%s starts a test server and waits for readiness without excluding it, and is called from a testport.WithRetry callback; pass the server to the wait", name)
					}
				}
				if why != "" {
					seen[inner.Pos()] = true
					pos := fset.Position(inner.Pos())
					out = append(out, finding{path: pos.Filename, line: pos.Line, why: why})
				}
				return true
			})
			return true
		})
	}
	return out
}

// stoppingHelpers returns the package-local functions that can end a test
// because a run exited: those with a test-ending call on a run-exit receive or
// on the error of a function that watches for the run's exit (the
// "if err := waitFor(...); err != nil { t.Fatal(err) }" wrapper), and those
// that call such a function.
func stoppingHelpers(decls map[string]*ast.FuncDecl, exitPath map[token.Pos]bool) map[string]bool {
	calls := map[string][]string{}
	stops := map[string]bool{}
	for name, fd := range decls {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if _, ok := n.(*ast.GoStmt); ok {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if exitPath[call.Pos()] {
				stops[name] = true
			}
			if callee := localCallee(call); callee != "" && decls[callee] != nil {
				calls[name] = append(calls[name], callee)
			}
			return true
		})
	}
	propagate(stops, calls)
	return stops
}

// exitObservers returns the package-local functions that receive a value in
// a select case, directly or through another package-local function.
func exitObservers(decls map[string]*ast.FuncDecl) map[string]bool {
	calls := map[string][]string{}
	obs := map[string]bool{}
	for name, fd := range decls {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CommClause:
				if isReceive(x.Comm) {
					obs[name] = true
				}
			case *ast.CallExpr:
				if callee := localCallee(x); callee != "" && decls[callee] != nil {
					calls[name] = append(calls[name], callee)
				}
			}
			return true
		})
	}
	propagate(obs, calls)
	return obs
}

func propagate(set map[string]bool, calls map[string][]string) {
	for changed := true; changed; {
		changed = false
		for name, callees := range calls {
			if set[name] {
				continue
			}
			for _, c := range callees {
				if set[c] {
					set[name] = true
					changed = true
					break
				}
			}
		}
	}
}

func callsObserver(n ast.Node, observers map[string]bool) bool {
	found := false
	ast.Inspect(n, func(m ast.Node) bool {
		if found {
			return false
		}
		if call, ok := m.(*ast.CallExpr); ok {
			if name := localCallee(call); name != "" && observers[name] {
				found = true
			}
		}
		return true
	})
	return found
}

// markObserverResultStops records test-ending calls that handle the result
// of an exit observer: the body of an if statement whose init or condition
// calls one, and the body of an if statement that tests a variable assigned
// from one in the statement just before it.
func markObserverResultStops(f *ast.File, observers map[string]bool, exitPath map[token.Pos]bool) {
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.IfStmt:
			if (x.Init != nil && callsObserver(x.Init, observers)) || callsObserver(x.Cond, observers) {
				markStops(x.Body, exitPath)
			}
		case *ast.BlockStmt:
			markAssignedResultStops(x.List, observers, exitPath)
		case *ast.CaseClause:
			markAssignedResultStops(x.Body, observers, exitPath)
		case *ast.CommClause:
			markAssignedResultStops(x.Body, observers, exitPath)
		}
		return true
	})
}

// markAssignedResultStops handles "err := observe(); if err != nil { t.Fatal }".
func markAssignedResultStops(list []ast.Stmt, observers map[string]bool, exitPath map[token.Pos]bool) {
	for i := 0; i+1 < len(list); i++ {
		names := observerAssigned(list[i], observers)
		if len(names) == 0 {
			continue
		}
		ifs, ok := list[i+1].(*ast.IfStmt)
		if !ok || !mentions(ifs.Cond, names) {
			continue
		}
		markStops(ifs.Body, exitPath)
	}
}

// observerAssigned returns the variables an assignment or var declaration
// sets from a call to an exit observer.
func observerAssigned(stmt ast.Stmt, observers map[string]bool) map[string]bool {
	var lhs []ast.Expr
	var rhs []ast.Expr
	switch x := stmt.(type) {
	case *ast.AssignStmt:
		lhs, rhs = x.Lhs, x.Rhs
	case *ast.DeclStmt:
		gd, ok := x.Decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			return nil
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, n := range vs.Names {
				lhs = append(lhs, n)
			}
			rhs = append(rhs, vs.Values...)
		}
	default:
		return nil
	}
	called := false
	for _, r := range rhs {
		if callsObserver(r, observers) {
			called = true
		}
	}
	if !called {
		return nil
	}
	names := map[string]bool{}
	for _, l := range lhs {
		if id, ok := l.(*ast.Ident); ok && id.Name != "_" {
			names[id.Name] = true
		}
	}
	return names
}

func mentions(n ast.Node, names map[string]bool) bool {
	found := false
	ast.Inspect(n, func(m ast.Node) bool {
		if id, ok := m.(*ast.Ident); ok && names[id.Name] {
			found = true
		}
		return !found
	})
	return found
}

// markStops records the test-ending calls in body, outside nested function
// literals.
func markStops(body ast.Node, exitPath map[token.Pos]bool) {
	ast.Inspect(body, func(m ast.Node) bool {
		if _, ok := m.(*ast.FuncLit); ok {
			return false
		}
		if call, ok := m.(*ast.CallExpr); ok && (isStopCall(call) || isRequireCall(call)) {
			exitPath[call.Pos()] = true
		}
		return true
	})
}

// markExitPathStops records every test-ending call made while handling a
// value received from a channel in a select case: the "run exited early"
// branch. A lost port race reaches the test through exactly that receive, as
// the run's "address already in use" error.
func markExitPathStops(f *ast.File, exitPath map[token.Pos]bool) {
	ast.Inspect(f, func(n ast.Node) bool {
		cc, ok := n.(*ast.CommClause)
		if !ok {
			return true
		}
		if !isReceive(cc.Comm) {
			// A timeout or cancellation case has already decided the test
			// fails (a hang backstop); a receive nested inside it only
			// reports what the run did afterwards.
			return cc.Comm == nil
		}
		for _, stmt := range cc.Body {
			markStops(stmt, exitPath)
		}
		return true
	})
}

// isReceive reports whether a select case receives a value it names, as in
// "case err := <-errCh". A bare "case <-done" or "case <-ctx.Done()" carries
// no run error, so it is not a run-exit path.
func isReceive(comm ast.Stmt) bool {
	assign, ok := comm.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
		return false
	}
	if id, ok := assign.Lhs[0].(*ast.Ident); ok && id.Name == "_" {
		return false
	}
	u, ok := assign.Rhs[0].(*ast.UnaryExpr)
	return ok && u.Op == token.ARROW
}

// readinessWaits are the port-readiness helpers that accept the test servers
// to exclude as trailing arguments after their fixed parameters.
var readinessWaits = map[string]int{"waitForPortOrCommandExitResult": 3}

// unexcludedInBody returns the readiness waits in body that pass no test
// server to exclude although body starts one with net/http/httptest.
func unexcludedInBody(body *ast.BlockStmt) []token.Pos {
	starts := false
	var waits []token.Pos
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok && n != ast.Node(body) {
			// Handlers and goroutines start no readiness wait of their own.
			return true
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "httptest" && strings.HasPrefix(sel.Sel.Name, "New") && strings.HasSuffix(sel.Sel.Name, "Server") {
				starts = true
			}
		}
		if name := localCallee(call); name != "" {
			if fixed, ok := readinessWaits[name]; ok && len(call.Args) <= fixed {
				waits = append(waits, call.Pos())
			}
		}
		return true
	})
	if !starts {
		return nil
	}
	return waits
}

// unexcludedUpstreamHelpers returns the package-local functions whose bodies
// start a test server and wait for readiness without excluding it.
func unexcludedUpstreamHelpers(_ *token.FileSet, decls map[string]*ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	for name, fd := range decls {
		if len(unexcludedInBody(fd.Body)) > 0 {
			out[name] = true
		}
	}
	return out
}

func isWithRetry(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "WithRetry" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "testport"
}

// isStopCall matches x.Fatal(...) and friends on any receiver except a
// package selector other than log (log.Fatal exits the process as well).
func isStopCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && stopNames[sel.Sel.Name]
}

func isRequireCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "require"
}

func localCallee(call *ast.CallExpr) string {
	if id, ok := call.Fun.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func sourceLine(cache map[string][]string, path string, line int) string {
	src, ok := cache[path]
	if !ok {
		f, err := os.Open(path) // #nosec G304 -- paths come from git ls-files.
		if err == nil {
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for sc.Scan() {
				src = append(src, sc.Text())
			}
			_ = f.Close()
		}
		cache[path] = src
	}
	if line < 1 || line > len(src) {
		return ""
	}
	return src[line-1]
}
