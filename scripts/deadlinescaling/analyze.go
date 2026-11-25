// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
)

const (
	testwaitPath = "github.com/luckyPipewrench/pipelock/internal/testwait"
	requirePath  = "github.com/stretchr/testify/require"
	assertPath   = "github.com/stretchr/testify/assert"
	testingPath  = "testing"
	timePath     = "time"
)

const (
	kindAfter = iota + 1
	kindTimer
)

// hardFail ends the calling goroutine. softFail marks the test failed and
// continues. Both are test results when the receiver is a test handle.
var (
	hardFail = map[string]bool{
		"Fatal": true, "Fatalf": true, "FailNow": true, "Fail": true,
	}
	softFail = map[string]bool{"Error": true, "Errorf": true}
)

// finding is one raw duration on a select wait that fails the test.
// start and end are byte offsets of that duration expression.
type finding struct {
	path       string
	line, col  int
	start, end int
}

type timerBind struct {
	kind int
	arg  ast.Expr
}

// sym is a name declared in a scope. rhs is the expression last assigned to
// it when that expression is visible, so a duration already produced by
// Deadline is not wrapped again. timer is set only when this name itself was
// assigned from time.After or time.NewTimer in this function.
type sym struct {
	handle bool
	rhs    ast.Expr
	timer  *timerBind
}

// scope is one Go block. The file scope holds top-level names for shadowing
// and for following a duration back to Deadline. It does not carry timer
// bindings: a package-level time.After is not an assignment in the function
// that receives from it.
type scope struct {
	parent *scope
	file   bool
	binds  map[string]*sym
}

func newScope(parent *scope) *scope {
	return &scope{parent: parent, binds: map[string]*sym{}}
}

func (s *scope) child() *scope {
	return newScope(s)
}

func (s *scope) declare(name string, sm *sym) {
	if name == "" || name == "_" {
		return
	}
	s.binds[name] = sm
}

func (s *scope) local(name string) *sym {
	if s == nil {
		return nil
	}
	return s.binds[name]
}

func (s *scope) lookup(name string) (*sym, *scope) {
	for cur := s; cur != nil; cur = cur.parent {
		if sm := cur.binds[name]; sm != nil {
			return sm, cur
		}
	}
	return nil, nil
}

func (s *scope) shadows(name string) bool {
	sm, _ := s.lookup(name)
	return sm != nil
}

// funcRoot is the function body scope, the one whose parent is the file.
func (s *scope) funcRoot() *scope {
	cur := s
	for cur.parent != nil && !cur.parent.file {
		cur = cur.parent
	}
	return cur
}

// clone copies the function's scopes so a case-body walk can declare names
// without changing the walk that records timers. The file scope is shared
// and only read.
func (s *scope) clone() *scope {
	if s == nil || s.file {
		return s
	}
	n := &scope{parent: s.parent.clone(), binds: make(map[string]*sym, len(s.binds))}
	for k, v := range s.binds {
		cp := *v
		if v.timer != nil {
			tb := *v.timer
			cp.timer = &tb
		}
		n.binds[k] = &cp
	}
	return n
}

// fileNames is how this file spells the packages the scan cares about.
type fileNames struct {
	time    map[string]bool
	testing map[string]bool
	testify map[string]bool
	wait    map[string]bool
	imports map[string]bool
	dotTime bool
	dotTest bool
	dotWait bool
}

func namesOf(f *ast.File) *fileNames {
	n := &fileNames{
		time:    map[string]bool{},
		testing: map[string]bool{},
		testify: map[string]bool{},
		wait:    map[string]bool{},
		imports: map[string]bool{},
	}
	sawTime, sawTesting := false, false
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		local := filepath.Base(path)
		if imp.Name != nil {
			local = imp.Name.Name
		}
		switch local {
		case ".":
			switch path {
			case timePath:
				n.dotTime = true
			case testingPath:
				n.dotTest = true
			case testwaitPath:
				n.dotWait = true
			}
			continue
		case "_":
			continue
		}
		n.imports[local] = true
		switch path {
		case timePath:
			sawTime = true
			n.time[local] = true
		case testingPath:
			sawTesting = true
			n.testing[local] = true
		case requirePath, assertPath:
			n.testify[local] = true
		case testwaitPath:
			n.wait[local] = true
		}
	}
	// A fragment with no import block still means the ordinary names.
	// A file that imports the package under an alias does not also get the
	// default name, or a local of that name would be mistaken for the package.
	if !sawTime {
		n.time["time"] = true
		n.imports["time"] = true
	}
	if !sawTesting {
		n.testing["testing"] = true
		n.imports["testing"] = true
	}
	return n
}

func (n *fileNames) isPackage(id *ast.Ident) bool {
	if id == nil {
		return false
	}
	if n.imports[id.Name] || n.time[id.Name] || n.testing[id.Name] || n.testify[id.Name] {
		return true
	}
	switch id.Name {
	case "fmt", "errors", "log", "context":
		return true
	default:
		return false
	}
}

type checker struct {
	fset      *token.FileSet
	path      string
	names     *fileNames
	fileScope *scope
	findings  []finding
}

func analyze(paths []string) ([]finding, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no test files given")
	}
	fset := token.NewFileSet()
	var out []finding
	for _, path := range paths {
		c := &checker{fset: fset, path: path}
		if err := c.checkFile(); err != nil {
			return nil, err
		}
		out = append(out, c.findings...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].path != out[j].path {
			return out[i].path < out[j].path
		}
		if out[i].start != out[j].start {
			return out[i].start < out[j].start
		}
		return out[i].end < out[j].end
	})
	return out, nil
}

func (c *checker) checkFile() error {
	// parser.ParseFile reads the path. The gate passes tracked test files, not
	// request data, so this is the scan input rather than a file-inclusion sink.
	f, err := parser.ParseFile(c.fset, c.path, nil, parser.SkipObjectResolution)
	if err != nil {
		return fmt.Errorf("parse %s: %w", c.path, err)
	}
	c.names = namesOf(f)
	c.declareTop(f)
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		c.walkFunc(fn.Recv, fn.Type, fn.Body, nil)
	}
	return nil
}

func (c *checker) declareTop(f *ast.File) {
	c.fileScope = &scope{file: true, binds: map[string]*sym{}}
	for _, d := range f.Decls {
		switch n := d.(type) {
		case *ast.FuncDecl:
			if n.Name != nil {
				c.fileScope.declare(n.Name.Name, &sym{})
			}
		case *ast.GenDecl:
			for _, spec := range n.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name != nil {
						c.fileScope.declare(s.Name.Name, &sym{})
					}
				case *ast.ValueSpec:
					c.defineValueSpec(s, c.fileScope, false)
				}
			}
		}
	}
}

func (c *checker) walkFunc(recv *ast.FieldList, typ *ast.FuncType, body *ast.BlockStmt, inherited map[string]bool) {
	if body == nil {
		return
	}
	// Parameters share the function body block. A short declaration there
	// redeclares the parameter; it does not shadow it from a nested block.
	sc := newScope(c.fileScope)
	for name := range inherited {
		sc.declare(name, &sym{handle: true})
	}
	c.declareFields(recv, sc)
	if typ != nil {
		c.declareFields(typ.Params, sc)
		c.declareFields(typ.Results, sc)
	}
	c.walkStmts(body.List, sc)
}

func (c *checker) declareFields(list *ast.FieldList, sc *scope) {
	if list == nil {
		return
	}
	for _, f := range list.List {
		handle := c.isHandleType(f.Type)
		for _, name := range f.Names {
			if name == nil {
				continue
			}
			sc.declare(name.Name, &sym{handle: handle})
		}
	}
}

func (c *checker) isHandleType(e ast.Expr) bool {
	e = unparen(e)
	if e == nil {
		return false
	}
	if star, ok := e.(*ast.StarExpr); ok {
		return c.isTesting(star.X, "T", "B", "F")
	}
	return c.isTesting(e, "TB")
}

func (c *checker) isTesting(e ast.Expr, names ...string) bool {
	e = unparen(e)
	switch n := e.(type) {
	case *ast.SelectorExpr:
		id, ok := n.X.(*ast.Ident)
		if !ok || !c.names.testing[id.Name] {
			return false
		}
		return oneOf(n.Sel.Name, names)
	case *ast.Ident:
		return c.names.dotTest && oneOf(n.Name, names)
	default:
		return false
	}
}

func oneOf(name string, names []string) bool {
	for _, n := range names {
		if name == n {
			return true
		}
	}
	return false
}

func (c *checker) walkStmts(stmts []ast.Stmt, sc *scope) {
	for _, stmt := range stmts {
		c.walkStmt(stmt, sc)
	}
}

func (c *checker) walkBlock(b *ast.BlockStmt, sc *scope) {
	if b == nil {
		return
	}
	c.walkStmts(b.List, sc.child())
}

func (c *checker) walkStmt(stmt ast.Stmt, sc *scope) {
	switch s := stmt.(type) {
	case *ast.BlockStmt:
		c.walkBlock(s, sc)
	case *ast.ExprStmt:
		c.walkExpr(s.X, sc)
	case *ast.AssignStmt:
		c.walkExprs(s.Rhs, sc)
		c.walkExprs(s.Lhs, sc)
		c.defineAssign(s, sc)
	case *ast.DeclStmt:
		c.walkDecl(s.Decl, sc)
	case *ast.IfStmt:
		inner := sc.child()
		if s.Init != nil {
			c.walkStmt(s.Init, inner)
		}
		c.walkExpr(s.Cond, inner)
		c.walkBlock(s.Body, inner)
		if s.Else != nil {
			c.walkStmt(s.Else, inner)
		}
	case *ast.ForStmt:
		inner := sc.child()
		if s.Init != nil {
			c.walkStmt(s.Init, inner)
		}
		c.walkExpr(s.Cond, inner)
		if s.Post != nil {
			c.walkStmt(s.Post, inner)
		}
		c.walkBlock(s.Body, inner)
	case *ast.RangeStmt:
		c.walkExpr(s.X, sc)
		inner := sc.child()
		c.declareRange(s, inner)
		c.walkBlock(s.Body, inner)
	case *ast.SwitchStmt:
		c.walkSwitch(s.Init, s.Tag, s.Body, sc)
	case *ast.TypeSwitchStmt:
		c.walkTypeSwitch(s, sc)
	case *ast.SelectStmt:
		c.walkSelect(s, sc)
	case *ast.ReturnStmt:
		c.walkExprs(s.Results, sc)
	case *ast.SendStmt:
		c.walkExpr(s.Chan, sc)
		c.walkExpr(s.Value, sc)
	case *ast.IncDecStmt:
		c.walkExpr(s.X, sc)
	case *ast.GoStmt:
		c.walkExpr(s.Call, sc)
	case *ast.DeferStmt:
		c.walkExpr(s.Call, sc)
	case *ast.LabeledStmt:
		c.walkStmt(s.Stmt, sc)
	}
}

// walkTypeSwitch walks a type switch whose cases share the switch block.
func (c *checker) walkTypeSwitch(s *ast.TypeSwitchStmt, sc *scope) {
	inner := sc.child()
	if s.Init != nil {
		c.walkStmt(s.Init, inner)
	}
	if s.Assign != nil {
		c.walkStmt(s.Assign, inner)
	}
	if s.Body == nil {
		return
	}
	for _, stmt := range s.Body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		c.walkExprs(cc.List, inner)
		c.walkStmts(cc.Body, inner)
	}
}

func (c *checker) walkSwitch(init ast.Stmt, tag ast.Expr, body *ast.BlockStmt, sc *scope) {
	inner := sc.child()
	if init != nil {
		c.walkStmt(init, inner)
	}
	c.walkExpr(tag, inner)
	if body == nil {
		return
	}
	for _, stmt := range body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		c.walkExprs(cc.List, inner)
		c.walkStmts(cc.Body, inner)
	}
}

func (c *checker) walkSelect(s *ast.SelectStmt, sc *scope) {
	if s.Body == nil {
		return
	}
	for _, stmt := range s.Body.List {
		cc, ok := stmt.(*ast.CommClause)
		if !ok || cc.Comm == nil {
			continue
		}
		if arg := c.rawTimerArg(cc.Comm, sc); arg != nil && c.caseBodyFails(cc.Body, sc) {
			c.addFinding(arg)
		}
	}
	for _, stmt := range s.Body.List {
		cc, ok := stmt.(*ast.CommClause)
		if !ok {
			continue
		}
		// Each comm clause has its own scope for the receive variables.
		caseScope := sc.child()
		if cc.Comm != nil {
			c.walkStmt(cc.Comm, caseScope)
		}
		c.walkStmts(cc.Body, caseScope)
	}
}

func (c *checker) walkDecl(d ast.Decl, sc *scope) {
	gd, ok := d.(*ast.GenDecl)
	if !ok {
		return
	}
	for _, spec := range gd.Specs {
		switch s := spec.(type) {
		case *ast.ValueSpec:
			c.walkExpr(s.Type, sc)
			c.walkExprs(s.Values, sc)
			c.defineValueSpec(s, sc, true)
		case *ast.TypeSpec:
			if s.Name != nil {
				sc.declare(s.Name.Name, &sym{})
			}
		}
	}
}

func (c *checker) walkExpr(e ast.Expr, sc *scope) {
	if e == nil {
		return
	}
	ast.Inspect(e, func(n ast.Node) bool {
		fl, ok := n.(*ast.FuncLit)
		if !ok {
			return n != nil
		}
		c.walkFunc(nil, fl.Type, fl.Body, visibleHandles(sc))
		return false
	})
}

func (c *checker) walkExprs(es []ast.Expr, sc *scope) {
	for _, e := range es {
		c.walkExpr(e, sc)
	}
}

func visibleHandles(sc *scope) map[string]bool {
	out := map[string]bool{}
	seen := map[string]bool{}
	for cur := sc; cur != nil && !cur.file; cur = cur.parent {
		for name, sm := range cur.binds {
			if seen[name] {
				continue
			}
			seen[name] = true
			if sm.handle {
				out[name] = true
			}
		}
	}
	return out
}

func (c *checker) declareRange(s *ast.RangeStmt, sc *scope) {
	if s.Tok != token.DEFINE {
		return
	}
	for _, e := range []ast.Expr{s.Key, s.Value} {
		id, ok := e.(*ast.Ident)
		if !ok || id == nil {
			continue
		}
		// The range variable hides an outer test handle of the same name.
		sc.declare(id.Name, &sym{})
	}
}

func (c *checker) defineAssign(s *ast.AssignStmt, sc *scope) {
	if s.Tok != token.DEFINE && s.Tok != token.ASSIGN {
		return
	}
	if len(s.Lhs) != len(s.Rhs) {
		// A multi-value call does not tell us which result is a timer or a
		// handle. New names are recorded so they shadow outer bindings.
		if s.Tok != token.DEFINE {
			return
		}
		for _, lhs := range s.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || sc.local(id.Name) != nil {
				continue
			}
			sc.declare(id.Name, &sym{})
		}
		return
	}
	for i, lhs := range s.Lhs {
		id, ok := lhs.(*ast.Ident)
		if !ok {
			continue
		}
		c.bind(sc, id.Name, c.symFrom(s.Rhs[i], sc), s.Tok == token.DEFINE)
	}
}

func (c *checker) defineValueSpec(vs *ast.ValueSpec, sc *scope, timers bool) {
	for i, name := range vs.Names {
		if name == nil {
			continue
		}
		var rhs ast.Expr
		switch {
		case len(vs.Values) == len(vs.Names):
			rhs = vs.Values[i]
		case len(vs.Names) == 1 && len(vs.Values) == 1:
			rhs = vs.Values[0]
		}
		sm := &sym{handle: c.isHandleType(vs.Type)}
		if rhs != nil {
			built := c.symFrom(rhs, sc)
			if timers {
				sm.timer = built.timer
			}
			sm.rhs = built.rhs
			if built.handle {
				sm.handle = true
			}
		}
		sc.declare(name.Name, sm)
	}
}

func (c *checker) symFrom(rhs ast.Expr, sc *scope) *sym {
	rhs = unparen(rhs)
	sm := &sym{rhs: rhs}
	if rhs == nil {
		return sm
	}
	if c.isHandleExpr(rhs, sc) {
		sm.handle = true
	}
	if arg, ok := c.callArg(rhs, sc, "After"); ok {
		sm.timer = &timerBind{kind: kindAfter, arg: arg}
	} else if arg, ok := c.callArg(rhs, sc, "NewTimer"); ok {
		sm.timer = &timerBind{kind: kindTimer, arg: arg}
	}
	return sm
}

func (c *checker) isHandleExpr(e ast.Expr, sc *scope) bool {
	id, ok := unparen(e).(*ast.Ident)
	if !ok {
		return false
	}
	sm, _ := sc.lookup(id.Name)
	return sm != nil && sm.handle
}

func (c *checker) bind(sc *scope, name string, sm *sym, define bool) {
	if define {
		if existing := sc.local(name); existing != nil {
			*existing = *sm
			return
		}
		sc.declare(name, sm)
		return
	}
	existing, owner := sc.lookup(name)
	if existing != nil && owner != nil && !owner.file {
		*existing = *sm
		return
	}
	root := sc.funcRoot()
	if cur := root.local(name); cur != nil {
		*cur = *sm
		return
	}
	root.declare(name, sm)
}

func (c *checker) addFinding(arg ast.Expr) {
	start := c.fset.Position(arg.Pos())
	end := c.fset.Position(arg.End())
	c.findings = append(c.findings, finding{
		path:  c.path,
		line:  start.Line,
		col:   start.Column,
		start: start.Offset,
		end:   end.Offset,
	})
}

// rawTimerArg is the duration of a failing-wait receive, or nil when the
// receive is not a tracked timer or the duration is already scaled.
func (c *checker) rawTimerArg(comm ast.Stmt, sc *scope) ast.Expr {
	arg := c.timerDuration(recvChannel(comm), sc)
	if arg == nil || c.alreadyScaled(arg, sc) {
		return nil
	}
	return arg
}

func (c *checker) timerDuration(recv ast.Expr, sc *scope) ast.Expr {
	recv = unparen(recv)
	if recv == nil {
		return nil
	}
	if arg, ok := c.callArg(recv, sc, "After"); ok {
		return arg
	}
	if id, ok := recv.(*ast.Ident); ok {
		sm, _ := sc.lookup(id.Name)
		if sm != nil && sm.timer != nil && sm.timer.kind == kindAfter {
			return sm.timer.arg
		}
	}
	sel, ok := recv.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "C" {
		return nil
	}
	if arg, ok := c.callArg(sel.X, sc, "NewTimer"); ok {
		return arg
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil
	}
	sm, _ := sc.lookup(id.Name)
	if sm != nil && sm.timer != nil && sm.timer.kind == kindTimer {
		return sm.timer.arg
	}
	return nil
}

func (c *checker) callArg(e ast.Expr, sc *scope, sel string) (ast.Expr, bool) {
	e = unparen(e)
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || call.Ellipsis.IsValid() {
		return nil, false
	}
	switch fun := unparen(call.Fun).(type) {
	case *ast.SelectorExpr:
		id, ok := fun.X.(*ast.Ident)
		if !ok || fun.Sel.Name != sel || !c.names.time[id.Name] || sc.shadows(id.Name) {
			return nil, false
		}
		return call.Args[0], true
	case *ast.Ident:
		if fun.Name == sel && c.names.dotTime && !sc.shadows(fun.Name) {
			return call.Args[0], true
		}
	}
	return nil, false
}

func (c *checker) alreadyScaled(e ast.Expr, sc *scope) bool {
	if c.isDeadline(e, sc) {
		return true
	}
	return c.scaledIdent(e, sc, map[string]bool{})
}

// scaledIdent follows a duration identifier back to a Deadline value in this
// function or at file scope. Wrapping that value again would scale it twice.
func (c *checker) scaledIdent(e ast.Expr, sc *scope, seen map[string]bool) bool {
	id, ok := unparen(e).(*ast.Ident)
	if !ok {
		return false
	}
	if seen[id.Name] {
		return false
	}
	seen[id.Name] = true
	sm, _ := sc.lookup(id.Name)
	if sm == nil || sm.rhs == nil {
		return false
	}
	if c.isDeadline(sm.rhs, sc) || containsDeadline(sm.rhs) {
		return true
	}
	return c.scaledIdent(sm.rhs, sc, seen)
}

func (c *checker) isDeadline(e ast.Expr, sc *scope) bool {
	e = unparen(e)
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fun := unparen(call.Fun).(type) {
	case *ast.SelectorExpr:
		id, ok := fun.X.(*ast.Ident)
		if !ok || fun.Sel.Name != "Deadline" {
			return false
		}
		return c.names.waitName(id.Name) && !sc.shadows(id.Name)
	case *ast.Ident:
		return c.names.dotWait && fun.Name == "Deadline" && !sc.shadows(fun.Name)
	default:
		return false
	}
}

func (n *fileNames) waitName(name string) bool {
	return n.wait[name]
}

func containsDeadline(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if x.Sel != nil && x.Sel.Name == "Deadline" {
				found = true
			}
		case *ast.Ident:
			if x.Name == "Deadline" {
				found = true
			}
		}
		return !found
	})
	return found
}

// caseBodyFails reports whether the case body fails the test outside nested
// function literals. A vacuity check replaces the return below with a
// constant false and expects an inline violation to pass.
func (c *checker) caseBodyFails(body []ast.Stmt, sc *scope) bool {
	return c.stmtsFail(body, sc.clone())
}

func (c *checker) stmtsFail(stmts []ast.Stmt, sc *scope) bool {
	for _, stmt := range stmts {
		if c.stmtFails(stmt, sc) {
			return true
		}
	}
	return false
}

func (c *checker) stmtFails(stmt ast.Stmt, sc *scope) bool {
	switch s := stmt.(type) {
	case *ast.BlockStmt:
		return c.stmtsFail(s.List, sc.child())
	case *ast.ExprStmt:
		return c.exprFails(s.X, sc)
	case *ast.AssignStmt:
		if c.exprsFail(s.Lhs, sc) || c.exprsFail(s.Rhs, sc) {
			return true
		}
		c.defineAssign(s, sc)
		return false
	case *ast.DeclStmt:
		return c.declFails(s.Decl, sc)
	case *ast.IfStmt:
		inner := sc.child()
		if s.Init != nil && c.stmtFails(s.Init, inner) {
			return true
		}
		if c.exprFails(s.Cond, inner) || (s.Body != nil && c.stmtsFail(s.Body.List, inner.child())) {
			return true
		}
		if s.Else != nil {
			return c.stmtFails(s.Else, inner)
		}
		return false
	case *ast.ForStmt:
		inner := sc.child()
		if s.Init != nil && c.stmtFails(s.Init, inner) {
			return true
		}
		if c.exprFails(s.Cond, inner) || (s.Post != nil && c.stmtFails(s.Post, inner)) {
			return true
		}
		return s.Body != nil && c.stmtsFail(s.Body.List, inner.child())
	case *ast.RangeStmt:
		if c.exprFails(s.X, sc) {
			return true
		}
		inner := sc.child()
		c.declareRange(s, inner)
		return s.Body != nil && c.stmtsFail(s.Body.List, inner.child())
	case *ast.SwitchStmt:
		return c.switchFails(s.Init, s.Tag, s.Body, sc)
	case *ast.TypeSwitchStmt:
		inner := sc.child()
		if s.Init != nil && c.stmtFails(s.Init, inner) {
			return true
		}
		if s.Assign != nil && c.stmtFails(s.Assign, inner) {
			return true
		}
		return c.casesFail(s.Body, inner)
	case *ast.SelectStmt:
		if s.Body == nil {
			return false
		}
		for _, stmt := range s.Body.List {
			cc, ok := stmt.(*ast.CommClause)
			if !ok {
				continue
			}
			if (cc.Comm != nil && c.stmtFails(cc.Comm, sc)) || c.stmtsFail(cc.Body, sc) {
				return true
			}
		}
		return false
	case *ast.ReturnStmt:
		return c.exprsFail(s.Results, sc)
	case *ast.SendStmt:
		return c.exprFails(s.Chan, sc) || c.exprFails(s.Value, sc)
	case *ast.IncDecStmt:
		return c.exprFails(s.X, sc)
	case *ast.GoStmt:
		return c.exprFails(s.Call, sc)
	case *ast.DeferStmt:
		return c.exprFails(s.Call, sc)
	case *ast.LabeledStmt:
		return c.stmtFails(s.Stmt, sc)
	default:
		return false
	}
}

func (c *checker) switchFails(init ast.Stmt, tag ast.Expr, body *ast.BlockStmt, sc *scope) bool {
	inner := sc.child()
	if init != nil && c.stmtFails(init, inner) {
		return true
	}
	if c.exprFails(tag, inner) {
		return true
	}
	return c.casesFail(body, inner)
}

func (c *checker) casesFail(body *ast.BlockStmt, sc *scope) bool {
	if body == nil {
		return false
	}
	for _, stmt := range body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		if c.exprsFail(cc.List, sc) || c.stmtsFail(cc.Body, sc) {
			return true
		}
	}
	return false
}

func (c *checker) declFails(d ast.Decl, sc *scope) bool {
	gd, ok := d.(*ast.GenDecl)
	if !ok {
		return false
	}
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			if ts, ok := spec.(*ast.TypeSpec); ok && ts.Name != nil {
				sc.declare(ts.Name.Name, &sym{})
			}
			continue
		}
		if c.exprFails(vs.Type, sc) || c.exprsFail(vs.Values, sc) {
			return true
		}
		c.defineValueSpec(vs, sc, true)
	}
	return false
}

func (c *checker) exprsFail(es []ast.Expr, sc *scope) bool {
	for _, e := range es {
		if c.exprFails(e, sc) {
			return true
		}
	}
	return false
}

func (c *checker) exprFails(e ast.Expr, sc *scope) bool {
	if e == nil {
		return false
	}
	failed := false
	ast.Inspect(e, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if ok && c.isFailingCall(call, sc) {
			failed = true
			return false
		}
		return true
	})
	return failed
}

func (c *checker) isFailingCall(call *ast.CallExpr, sc *scope) bool {
	sel, ok := unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return false
	}
	name := sel.Sel.Name
	id, isIdent := unparen(sel.X).(*ast.Ident)
	if isIdent && c.names.testify[id.Name] && !sc.shadows(id.Name) {
		return true
	}
	if !hardFail[name] && !softFail[name] {
		return false
	}
	if !isIdent {
		return hardFail[name]
	}
	if c.names.isPackage(id) && !sc.shadows(id.Name) {
		return false
	}
	sm, _ := sc.lookup(id.Name)
	if sm != nil {
		return sm.handle
	}
	return hardFail[name]
}

func unparen(e ast.Expr) ast.Expr {
	for e != nil {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
	return nil
}

func recvChannel(comm ast.Stmt) ast.Expr {
	switch s := comm.(type) {
	case *ast.ExprStmt:
		return arrowOperand(s.X)
	case *ast.AssignStmt:
		if len(s.Rhs) == 1 {
			return arrowOperand(s.Rhs[0])
		}
	}
	return nil
}

func arrowOperand(e ast.Expr) ast.Expr {
	e = unparen(e)
	u, ok := e.(*ast.UnaryExpr)
	if !ok || u.Op != token.ARROW {
		return nil
	}
	return u.X
}
