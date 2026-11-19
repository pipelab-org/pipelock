// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"testing"
)

type receiptWriterSite struct {
	pkg  string
	node ast.Node
}

func (s receiptWriterSite) fingerprint() string {
	var source bytes.Buffer
	if err := format.Node(&source, token.NewFileSet(), s.node); err != nil {
		return "unavailable"
	}
	return fmt.Sprintf("%x", sha256.Sum256(source.Bytes()))[:16]
}

type receiptWriterIndex struct {
	sites     map[string]receiptWriterSite
	functions map[string]map[string][]ast.Node
}

func newReceiptWriterIndex() *receiptWriterIndex {
	return &receiptWriterIndex{
		sites:     make(map[string]receiptWriterSite),
		functions: make(map[string]map[string][]ast.Node),
	}
}

func (index *receiptWriterIndex) addFile(pkg string, file *ast.File) {
	if index.functions[pkg] == nil {
		index.functions[pkg] = make(map[string][]ast.Node)
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			index.functions[pkg][fn.Name.Name] = append(index.functions[pkg][fn.Name.Name], fn.Body)
		}
	}
}

func (index *receiptWriterIndex) reachesWriter(site receiptWriterSite) bool {
	seen := make(map[ast.Node]bool)
	var visit func(ast.Node) bool
	var resolve func(ast.Expr) bool

	resolve = func(expr ast.Expr) bool {
		switch expr := expr.(type) {
		case *ast.Ident:
			if expr.Obj != nil {
				switch decl := expr.Obj.Decl.(type) {
				case *ast.AssignStmt:
					for i, lhs := range decl.Lhs {
						if ident, ok := lhs.(*ast.Ident); ok && ident.Obj == expr.Obj && i < len(decl.Rhs) {
							return resolve(decl.Rhs[i])
						}
					}
				case *ast.FuncDecl:
					return visit(decl.Body)
				}
			}
			for _, body := range index.functions[site.pkg][expr.Name] {
				if visit(body) {
					return true
				}
			}
		case *ast.SelectorExpr:
			for _, body := range index.functions[site.pkg][expr.Sel.Name] {
				if visit(body) {
					return true
				}
			}
		case *ast.FuncLit:
			return visit(expr.Body)
		}
		return false
	}

	visit = func(node ast.Node) bool {
		if node == nil || seen[node] {
			return false
		}
		seen[node] = true
		found := false
		ast.Inspect(node, func(child ast.Node) bool {
			if found {
				return false
			}
			switch child := child.(type) {
			case *ast.FuncLit:
				// An uncalled closure elsewhere in the function is not a path.
				return false
			case *ast.IfStmt:
				if on, known := receiptV3Guard(child.Cond); known {
					if child.Init != nil {
						found = visit(child.Init)
					}
					if !found && on {
						found = visit(child.Body)
					}
					if !found && !on {
						found = visit(child.Else)
					}
					return false
				}
			case *ast.CallExpr:
				if callWritesReceiptV3(child) || resolve(child.Fun) {
					found = true
					return false
				}
				// A receipt writer may be passed to a forwarding adapter as
				// a callback. Ordinary call arguments are visited by Inspect.
				for _, arg := range child.Args {
					if _, ok := arg.(*ast.Ident); !ok && resolve(arg) {
						found = true
						return false
					}
				}
			}
			return true
		})
		return found
	}
	return visit(site.node)
}

func callWritesReceiptV3(call *ast.CallExpr) bool {
	target, ok := call.Fun.(*ast.SelectorExpr)
	return ok && (target.Sel.Name == "WriteAction" || target.Sel.Name == "WriteAdmissionBatch") && isReceiptV3Selector(target.X)
}

func isReceiptV3Selector(expr ast.Expr) bool {
	field, ok := expr.(*ast.SelectorExpr)
	return ok && (field.Sel.Name == "ReceiptV3" || field.Sel.Name == "receiptV3")
}

// receiptV3Guard evaluates guards whose result follows from v3 being enabled.
func receiptV3Guard(expr ast.Expr) (value, known bool) {
	binary, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return false, false
	}
	if binary.Op == token.EQL || binary.Op == token.NEQ {
		other, ok := binary.Y.(*ast.Ident)
		if ok && other.Name == "nil" && isReceiptV3Selector(binary.X) {
			return binary.Op == token.NEQ, true
		}
	}
	left, leftKnown := receiptV3Guard(binary.X)
	right, rightKnown := receiptV3Guard(binary.Y)
	switch binary.Op {
	case token.LAND:
		if (leftKnown && !left) || (rightKnown && !right) {
			return false, true
		}
		return left && right, leftKnown && rightKnown
	case token.LOR:
		if (leftKnown && left) || (rightKnown && right) {
			return true, true
		}
		return false, leftKnown && rightKnown
	default:
		return false, false
	}
}

func TestReceiptV3WriterPathStartsAtBoundCall(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "receipt.go", `package example
func handle(o options) {
	legacy()
	disabled(o)
	enabled(o)
}
func legacy() {}
func disabled(o options) {
	if o.ReceiptV3 == nil {
		o.ReceiptV3.WriteAction()
	}
}
func enabled(o options) {
	if o.ReceiptV3 != nil {
		o.ReceiptV3.WriteAction()
	}
}
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	index := newReceiptWriterIndex()
	index.addFile("example", file)
	handle := file.Decls[0].(*ast.FuncDecl)
	for i, want := range []bool{false, false, true} {
		call := handle.Body.List[i].(*ast.ExprStmt).X
		if got := index.reachesWriter(receiptWriterSite{pkg: "example", node: call}); got != want {
			t.Errorf("call %d writer reachability = %t, want %t", i, got, want)
		}
	}
}
