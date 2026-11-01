// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Command teststability reports test code that defeats testport.WithRetry.
//
// WithRetry reruns its callback on a fresh port only when the callback
// returns a bind-collision error. A t.Fatal, t.FailNow, t.Skip, t.Error, or
// require or assert call on a run-exit path inside the callback, or inside a
// helper the callback calls, fails the test before WithRetry sees the error,
// so a lost port race fails the run instead of retrying. Findings print as
// path:line:source so the stability allowlist can match them exactly.
//
// The analyzer is syntactic (go/ast only, no type checking). It resolves
// import names per file, follows package-local functions, methods, and named
// callbacks, and uses channel and server declarations it can see in the
// package. Shapes it cannot see through (callbacks or helpers from other
// packages, channels it cannot find a declaration for) are treated
// conservatively for value-binding receives. Bare receives require a visible
// channel declaration, so readiness, timer, and cancellation backstops remain
// outside the run-exit check.
package main

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	testportPath = "github.com/luckyPipewrench/pipelock/internal/testport"
	httptestPath = "net/http/httptest"
)

// stopNames are the testing.TB methods that end a test from the calling
// goroutine, and failNames the ones that mark it failed and let it go on.
// Either kind on a run-exit path turns a retryable collision into a failure.
var (
	stopNames = map[string]bool{
		"Fatal": true, "Fatalf": true, "FailNow": true,
		"Skip": true, "Skipf": true, "SkipNow": true,
	}
	failNames = map[string]bool{"Error": true, "Errorf": true, "Fail": true}
)

// failPackages are the import paths whose package-level calls fail a test.
var failPackages = map[string]bool{
	"github.com/stretchr/testify/require": true,
	"github.com/stretchr/testify/assert":  true,
}

// fileNames holds the names a file uses for the packages the analyzer cares
// about. When a file does not import a package, its usual name is assumed so
// fragments without import blocks still resolve.
type fileNames struct {
	imports  map[string]bool // every local import name
	testport map[string]bool
	fail     map[string]bool // require, assert
	httptest map[string]bool
	dotPort  bool // testport is dot-imported
}

func newFileNames(f *ast.File) *fileNames {
	n := &fileNames{imports: map[string]bool{}, testport: map[string]bool{}, fail: map[string]bool{}, httptest: map[string]bool{}}
	seen := map[string]bool{}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := filepath.Base(path)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		seen[path] = true
		if name == "." {
			if path == testportPath {
				n.dotPort = true
			}
			continue
		}
		if name == "_" {
			continue
		}
		n.imports[name] = true
		switch {
		case path == testportPath:
			n.testport[name] = true
		case failPackages[path]:
			n.fail[name] = true
		case path == httptestPath:
			n.httptest[name] = true
		}
	}
	if !seen[testportPath] {
		n.testport["testport"] = true
	}
	if !seen["github.com/stretchr/testify/require"] {
		n.fail["require"] = true
	}
	if !seen["github.com/stretchr/testify/assert"] {
		n.fail["assert"] = true
	}
	if !seen[httptestPath] {
		n.httptest["httptest"] = true
	}
	return n
}

// isPackage reports whether id names an imported package rather than a
// value. fmt and errors are always packages, so "fmt.Errorf" in a fragment
// without imports is not mistaken for t.Errorf.
func (n *fileNames) isPackage(id *ast.Ident) bool {
	return n.imports[id.Name] || n.testport[id.Name] || n.fail[id.Name] || n.httptest[id.Name] || id.Name == "fmt" || id.Name == "errors"
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

// pkgInfo is what the analyzer knows about one package.
type pkgInfo struct {
	fset  *token.FileSet
	files []*ast.File
	names map[*ast.File]*fileNames
	// decls holds all functions by name and methods by "." + name.
	decls map[string][]*ast.FuncDecl
	// declFile maps each declaration to its file.
	declFile map[*ast.FuncDecl]*ast.File
	// namedLits holds function literals assigned to a name.
	namedLits map[string][]*ast.FuncLit
	// chanElems holds the element types declared for each channel name.
	chanElems map[string][]string
	// errStructs names the struct types that carry an error field.
	errStructs map[string]bool
	// serverFuncs names the package-local functions that return a test server.
	serverFuncs map[string]bool
	exitPath    map[token.Pos]bool
}

func newPkgInfo(fset *token.FileSet, p *pkgFiles) *pkgInfo {
	pi := &pkgInfo{
		fset: fset, files: p.files, names: map[*ast.File]*fileNames{},
		decls: map[string][]*ast.FuncDecl{}, declFile: map[*ast.FuncDecl]*ast.File{},
		namedLits: map[string][]*ast.FuncLit{}, chanElems: map[string][]string{},
		errStructs: map[string]bool{}, serverFuncs: map[string]bool{},
		exitPath: map[token.Pos]bool{},
	}
	for _, f := range p.files {
		pi.names[f] = newFileNames(f)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			key := fd.Name.Name
			if fd.Recv != nil {
				key = "." + key
			}
			pi.decls[key] = append(pi.decls[key], fd)
			pi.declFile[fd] = f
			if returnsServer(fd.Type, pi.names[f]) {
				pi.serverFuncs[key] = true
			}
		}
		pi.collectDeclarations(f)
	}
	return pi
}

func returnsServer(ft *ast.FuncType, n *fileNames) bool {
	if ft.Results == nil {
		return false
	}
	for _, r := range ft.Results.List {
		if star, ok := r.Type.(*ast.StarExpr); ok {
			if sel, ok := star.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "Server" {
				if id, ok := sel.X.(*ast.Ident); ok && n.httptest[id.Name] {
					return true
				}
			}
		}
	}
	return false
}

// collectDeclarations records channel element types, error-carrying struct
// types, and named function literals.
func (pi *pkgInfo) collectDeclarations(f *ast.File) {
	addChan := func(name string, t ast.Expr) {
		if ch, ok := t.(*ast.ChanType); ok {
			pi.chanElems[name] = append(pi.chanElems[name], types.ExprString(ch.Value))
		}
	}
	addFields := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, field := range fl.List {
			for _, n := range field.Names {
				addChan(n.Name, field.Type)
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncType:
			addFields(x.Params)
		case *ast.TypeSpec:
			if st, ok := x.Type.(*ast.StructType); ok {
				addFields(st.Fields)
				for _, field := range st.Fields.List {
					if id, ok := field.Type.(*ast.Ident); ok && id.Name == "error" {
						pi.errStructs[x.Name.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for i, name := range x.Names {
				if x.Type != nil {
					addChan(name.Name, x.Type)
				}
				if i < len(x.Values) {
					pi.recordValue(name.Name, x.Values[i])
				}
			}
		case *ast.AssignStmt:
			if len(x.Lhs) == len(x.Rhs) {
				for i, l := range x.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						pi.recordValue(id.Name, x.Rhs[i])
					}
				}
			}
		}
		return true
	})
}

func (pi *pkgInfo) recordValue(name string, v ast.Expr) {
	switch x := v.(type) {
	case *ast.FuncLit:
		pi.namedLits[name] = append(pi.namedLits[name], x)
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "make" && len(x.Args) > 0 {
			if ch, ok := x.Args[0].(*ast.ChanType); ok {
				pi.chanElems[name] = append(pi.chanElems[name], types.ExprString(ch.Value))
			}
		}
	}
}

// isExitChannel reports whether a receive from ch can deliver the run's
// exit error: its declared element type is error or a struct with an error
// field. A channel with no visible declaration counts as one.
func (pi *pkgInfo) isExitChannel(ch ast.Expr) bool {
	var name string
	switch x := ast.Unparen(ch).(type) {
	case *ast.Ident:
		name = x.Name
	case *ast.SelectorExpr:
		name = x.Sel.Name
	default:
		return true
	}
	elems := pi.chanElems[name]
	if len(elems) == 0 {
		return true
	}
	for _, e := range elems {
		if e == "error" || pi.errStructs[strings.TrimPrefix(e, "*")] {
			return true
		}
	}
	return false
}

// exitReceive reports whether e is a receive from a run-exit channel.
func (pi *pkgInfo) exitReceive(e ast.Expr) bool {
	u, ok := ast.Unparen(e).(*ast.UnaryExpr)
	return ok && u.Op == token.ARROW && pi.isExitChannel(u.X)
}

func (pi *pkgInfo) containsExitReceive(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(m ast.Node) bool {
		if found {
			return false
		}
		if _, ok := m.(*ast.FuncLit); ok {
			return false
		}
		if e, ok := m.(ast.Expr); ok && pi.exitReceive(e) {
			found = true
		}
		return !found
	})
	return found
}

// localCallee returns the decls key of a package-local function or method
// call, or "".
func (pi *pkgInfo) localCallee(call *ast.CallExpr, n *fileNames) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		if id, ok := fun.X.(*ast.Ident); ok && n.isPackage(id) {
			return ""
		}
		if pi.decls["."+fun.Sel.Name] != nil {
			return "." + fun.Sel.Name
		}
	}
	return ""
}

// isFailCall matches t.Fatal and friends, t.Error and friends, and require
// or assert calls. Package-level functions with those names (fmt.Errorf,
// klog.Fatal) are not test calls; log.Fatal still ends the process.
func isFailCall(call *ast.CallExpr, n *fileNames) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if id, ok := sel.X.(*ast.Ident); ok {
		if n.fail[id.Name] {
			return true
		}
		if n.isPackage(id) && id.Name != "log" {
			return false
		}
	}
	if stopNames[sel.Sel.Name] {
		return true
	}
	return failNames[sel.Sel.Name] && (len(call.Args) > 0 || sel.Sel.Name == "Fail")
}

func isWithRetry(call *ast.CallExpr, n *fileNames) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		id, ok := fun.X.(*ast.Ident)
		return ok && fun.Sel.Name == "WithRetry" && n.testport[id.Name]
	case *ast.Ident:
		return n.dotPort && fun.Name == "WithRetry"
	}
	return false
}

// callbackBodies returns the bodies the last WithRetry argument can run: a
// function literal, a named function or method, or a variable holding a
// function literal.
func (pi *pkgInfo) callbackBodies(arg ast.Expr) []*ast.BlockStmt {
	switch x := ast.Unparen(arg).(type) {
	case *ast.FuncLit:
		return []*ast.BlockStmt{x.Body}
	case *ast.Ident:
		var out []*ast.BlockStmt
		for _, fd := range pi.decls[x.Name] {
			out = append(out, fd.Body)
		}
		for _, lit := range pi.namedLits[x.Name] {
			out = append(out, lit.Body)
		}
		return out
	case *ast.SelectorExpr:
		var out []*ast.BlockStmt
		for _, fd := range pi.decls["."+x.Sel.Name] {
			out = append(out, fd.Body)
		}
		return out
	}
	return nil
}

func (pi *pkgInfo) fileOf(pos token.Pos) *ast.File {
	for _, f := range pi.files {
		if f.Pos() <= pos && pos <= f.End() {
			return f
		}
	}
	return nil
}

// checkPackage finds WithRetry callbacks in one package and reports every
// failing call they can reach through package-local helpers.
func checkPackage(fset *token.FileSet, p *pkgFiles) []finding {
	pi := newPkgInfo(fset, p)
	for _, f := range p.files {
		pi.markExitPathStops(f)
	}
	observers := pi.exitObservers()
	for _, f := range p.files {
		pi.markObserverResultStops(f, observers)
	}
	stops := pi.stoppingHelpers()
	unexcluded := pi.unexcludedUpstreamHelpers()
	var out []finding
	seen := map[token.Pos]bool{}
	report := func(pos token.Pos, why string) {
		if seen[pos] {
			return
		}
		seen[pos] = true
		p := fset.Position(pos)
		out = append(out, finding{path: p.Filename, line: p.Line, why: why})
	}
	for _, f := range p.files {
		n := pi.names[f]
		ast.Inspect(f, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !isWithRetry(call, n) || len(call.Args) == 0 {
				return true
			}
			for _, body := range pi.callbackBodies(call.Args[len(call.Args)-1]) {
				bn := pi.names[pi.fileOf(body.Pos())]
				if bn == nil {
					bn = n
				}
				for _, pos := range pi.unexcludedInBody(body, bn) {
					report(pos, "readiness wait does not exclude a test server started inside this testport.WithRetry callback; that server can take a just-released port, so pass it to the wait")
				}
				ast.Inspect(body, func(m ast.Node) bool {
					inner, ok := m.(*ast.CallExpr)
					if !ok {
						return true
					}
					switch name := pi.localCallee(inner, bn); {
					case pi.exitPath[inner.Pos()]:
						report(inner.Pos(), "failing call on a run-exit receive inside a testport.WithRetry callback; return the received error so a bind collision can retry")
					case name != "" && stops[name]:
						report(inner.Pos(), fmt.Sprintf("%s fails the test on a run-exit receive and is called from a testport.WithRetry callback; give it an error-returning form", strings.TrimPrefix(name, ".")))
					case name != "" && unexcluded[name]:
						report(inner.Pos(), fmt.Sprintf("%s starts a test server and waits for readiness without excluding it, and is called from a testport.WithRetry callback; pass the server to the wait", strings.TrimPrefix(name, ".")))
					}
					return true
				})
			}
			return true
		})
	}
	return out
}

// stoppingHelpers returns the package-local functions that can fail a test
// because a run exited, directly or through another such function.
func (pi *pkgInfo) stoppingHelpers() map[string]bool {
	calls := map[string][]string{}
	stops := map[string]bool{}
	for name, decls := range pi.decls {
		for _, fd := range decls {
			n := pi.names[pi.declFile[fd]]
			ast.Inspect(fd.Body, func(node ast.Node) bool {
				if _, ok := node.(*ast.GoStmt); ok {
					return false
				}
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				if pi.exitPath[call.Pos()] {
					stops[name] = true
				}
				if callee := pi.localCallee(call, n); callee != "" && pi.decls[callee] != nil {
					calls[name] = append(calls[name], callee)
				}
				return true
			})
		}
	}
	propagate(stops, calls)
	return stops
}

// exitObservers returns the package-local functions that receive from a
// run-exit channel, directly or through another package-local function.
func (pi *pkgInfo) exitObservers() map[string]bool {
	calls := map[string][]string{}
	obs := map[string]bool{}
	for name, decls := range pi.decls {
		for _, fd := range decls {
			n := pi.names[pi.declFile[fd]]
			ast.Inspect(fd.Body, func(node ast.Node) bool {
				switch x := node.(type) {
				case *ast.CommClause:
					if pi.isReceive(x.Comm) {
						obs[name] = true
					}
				case *ast.UnaryExpr:
					if pi.exitReceive(x) {
						obs[name] = true
					}
				case *ast.CallExpr:
					if callee := pi.localCallee(x, n); callee != "" && pi.decls[callee] != nil {
						calls[name] = append(calls[name], callee)
					}
				}
				return true
			})
		}
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

// exitSource reports whether n calls an exit observer or receives from a
// run-exit channel.
func (pi *pkgInfo) exitSource(n ast.Node, observers map[string]bool, names *fileNames) bool {
	if pi.containsExitReceive(n) {
		return true
	}
	found := false
	ast.Inspect(n, func(m ast.Node) bool {
		if found {
			return false
		}
		if call, ok := m.(*ast.CallExpr); ok {
			if name := pi.localCallee(call, names); name != "" && observers[name] {
				found = true
			}
		}
		return true
	})
	return found
}

// markObserverResultStops records failing calls that handle a run-exit
// value outside a select: the body of an if statement whose init or
// condition receives it or calls an exit observer, the body of an if
// statement testing a variable assigned that way just before it, and a
// failing call that takes the value as an argument.
func (pi *pkgInfo) markObserverResultStops(f *ast.File, observers map[string]bool) {
	n := pi.names[f]
	ast.Inspect(f, func(node ast.Node) bool {
		switch x := node.(type) {
		case *ast.CommClause:
			if x.Comm != nil && isBareReceive(x.Comm) {
				// A timeout or cancellation case: see markExitPathStops.
				return false
			}
			pi.markAssignedResultStops(x.Body, observers, n)
		case *ast.IfStmt:
			if (x.Init != nil && pi.exitSource(x.Init, observers, n)) || pi.exitSource(x.Cond, observers, n) {
				pi.markStops(x.Body, n)
			}
		case *ast.BlockStmt:
			pi.markAssignedResultStops(x.List, observers, n)
		case *ast.CaseClause:
			pi.markAssignedResultStops(x.Body, observers, n)
		case *ast.CallExpr:
			if isFailCall(x, n) {
				for _, a := range x.Args {
					if pi.containsExitReceive(a) {
						pi.exitPath[x.Pos()] = true
					}
				}
			}
		}
		return true
	})
}

// markAssignedResultStops handles "err := <-errCh" or "err := observe()"
// followed by "if err != nil { t.Fatal(err) }".
func (pi *pkgInfo) markAssignedResultStops(list []ast.Stmt, observers map[string]bool, n *fileNames) {
	for i := 0; i+1 < len(list); i++ {
		names := pi.exitAssigned(list[i], observers, n)
		if len(names) == 0 {
			continue
		}
		ifs, ok := list[i+1].(*ast.IfStmt)
		if !ok || !mentions(ifs.Cond, names) {
			continue
		}
		pi.markStops(ifs.Body, n)
	}
}

// exitAssigned returns the variables an assignment or var declaration sets
// from a run-exit receive or an exit observer call.
func (pi *pkgInfo) exitAssigned(stmt ast.Stmt, observers map[string]bool, n *fileNames) map[string]bool {
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
			for _, id := range vs.Names {
				lhs = append(lhs, id)
			}
			rhs = append(rhs, vs.Values...)
		}
	default:
		return nil
	}
	called := false
	for _, r := range rhs {
		if pi.exitSource(r, observers, n) {
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

// markStops records the failing calls in body, outside nested function
// literals.
func (pi *pkgInfo) markStops(body ast.Node, n *fileNames) {
	ast.Inspect(body, func(m ast.Node) bool {
		if _, ok := m.(*ast.FuncLit); ok {
			return false
		}
		if call, ok := m.(*ast.CallExpr); ok && isFailCall(call, n) {
			pi.exitPath[call.Pos()] = true
		}
		return true
	})
}

// markExitPathStops records every failing call made while handling a value
// received from a run-exit channel in a select case: the "run exited early"
// branch. A lost port race reaches the test through exactly that receive, as
// the run's "address already in use" error.
func (pi *pkgInfo) markExitPathStops(f *ast.File) {
	n := pi.names[f]
	ast.Inspect(f, func(node ast.Node) bool {
		cc, ok := node.(*ast.CommClause)
		if !ok {
			return true
		}
		if !pi.isReceive(cc.Comm) {
			// A timeout or cancellation case has already decided the test
			// fails (a hang backstop); a receive nested inside it only
			// reports what the run did afterwards.
			return cc.Comm == nil
		}
		for _, stmt := range cc.Body {
			pi.markStops(stmt, n)
		}
		return true
	})
}

// isReceive reports whether a select case receives from a run-exit channel,
// including cases that discard its value. A bare receive needs a visible
// channel declaration to distinguish it from readiness and hang backstops.
func (pi *pkgInfo) isReceive(comm ast.Stmt) bool {
	if es, ok := comm.(*ast.ExprStmt); ok {
		if !pi.exitReceive(es.X) {
			return false
		}
		u := ast.Unparen(es.X).(*ast.UnaryExpr)
		var name string
		switch ch := ast.Unparen(u.X).(type) {
		case *ast.Ident:
			name = ch.Name
		case *ast.SelectorExpr:
			name = ch.Sel.Name
		}
		return len(pi.chanElems[name]) > 0
	}
	assign, ok := comm.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
		return false
	}
	return pi.exitReceive(assign.Rhs[0])
}

func isBareReceive(comm ast.Stmt) bool {
	es, ok := comm.(*ast.ExprStmt)
	if !ok {
		return false
	}
	u, ok := es.X.(*ast.UnaryExpr)
	return ok && u.Op == token.ARROW
}

// readinessWaits are the port-readiness helpers that accept the test servers
// to exclude as trailing arguments after their fixed parameters.
var readinessWaits = map[string]int{"waitForPortOrCommandExitResult": 3}

// unexcludedInBody returns the readiness waits in body that do not pass
// every test server body starts. A server is started by a net/http/httptest
// New*Server call or a package-local function returning *httptest.Server;
// only the variable it is assigned to counts as excluding it.
func (pi *pkgInfo) unexcludedInBody(body *ast.BlockStmt, n *fileNames) []token.Pos {
	isStart := func(e ast.Expr) bool {
		call, ok := ast.Unparen(e).(*ast.CallExpr)
		if !ok {
			return false
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && n.httptest[id.Name] && strings.HasPrefix(sel.Sel.Name, "New") && strings.HasSuffix(sel.Sel.Name, "Server") {
				return true
			}
		}
		name := pi.localCallee(call, n)
		return name != "" && pi.serverFuncs[name]
	}
	named := map[string]bool{}
	bound := map[token.Pos]bool{}
	anonymous := false
	var waits []*ast.CallExpr
	ast.Inspect(body, func(node ast.Node) bool {
		switch x := node.(type) {
		case *ast.AssignStmt:
			if len(x.Lhs) == len(x.Rhs) {
				for i, r := range x.Rhs {
					if id, ok := x.Lhs[i].(*ast.Ident); ok && id.Name != "_" && isStart(r) {
						named[id.Name] = true
						bound[ast.Unparen(r).Pos()] = true
					}
				}
			}
		case *ast.ValueSpec:
			for i, r := range x.Values {
				if i < len(x.Names) && isStart(r) {
					named[x.Names[i].Name] = true
					bound[ast.Unparen(r).Pos()] = true
				}
			}
		case *ast.CallExpr:
			if name := pi.localCallee(x, n); name != "" {
				if _, ok := readinessWaits[name]; ok {
					waits = append(waits, x)
				}
			}
		}
		return true
	})
	ast.Inspect(body, func(node ast.Node) bool {
		if e, ok := node.(ast.Expr); ok && isStart(e) && !bound[e.Pos()] {
			anonymous = true
		}
		return true
	})
	if len(named) == 0 && !anonymous {
		return nil
	}
	var out []token.Pos
	for _, w := range waits {
		fixed := readinessWaits[pi.localCallee(w, n)]
		passed := map[string]bool{}
		if len(w.Args) > fixed {
			for _, a := range w.Args[fixed:] {
				if id, ok := ast.Unparen(a).(*ast.Ident); ok {
					passed[id.Name] = true
				}
			}
		}
		missing := anonymous
		for name := range named {
			if !passed[name] {
				missing = true
			}
		}
		if missing {
			out = append(out, w.Pos())
		}
	}
	return out
}

// unexcludedUpstreamHelpers returns the package-local functions whose bodies
// start a test server and wait for readiness without excluding it.
func (pi *pkgInfo) unexcludedUpstreamHelpers() map[string]bool {
	out := map[string]bool{}
	for name, decls := range pi.decls {
		for _, fd := range decls {
			if len(pi.unexcludedInBody(fd.Body, pi.names[pi.declFile[fd]])) > 0 {
				out[name] = true
			}
		}
	}
	return out
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
