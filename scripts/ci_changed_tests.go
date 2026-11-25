//go:build ignore

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Select added or changed top-level tests from two Git revisions. This uses
// go/parser rather than diff hunks so body-only edits and multiline declarations
// have the same meaning. Build constraints are resolved by go list in the runner.
//
// With --include-support, a changed declaration that is not itself a test (a
// helper, type, variable, constant or init function in a test file) also
// selects every test of its package that refers to it, directly or through
// other test-file declarations. TestMain and init run for every test, so a
// change to either hook, including init order, or a hook that reaches a
// changed declaration, selects the whole package. A blank import does too:
// nothing else names it. The repeat gate uses this so an edit to a shared
// helper reruns the tests that depend on it; the race measurement keeps its
// own narrower selection.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type test struct {
	File    string `json:"file"`
	Package string `json:"package"`
	Name    string `json:"name"`
	// New is false when the package already declared this test name at the
	// base for the same build variant, even in another file. The runner
	// measures packages with new tests first, since no weight exists for them.
	New bool `json:"new"`
	// Reason is set only with --include-support: "changed" when the test's
	// own source changed, "support" when it only reaches a changed
	// declaration. The repeat gate bounds the second group by cost.
	Reason string `json:"reason,omitempty"`
	Source string `json:"-"`
	ident  string
	// refs holds every identifier the test's declaration mentions; support
	// selection matches it against changed support declarations by name.
	refs map[string]bool
	pkg  packageKey
}

// support is a non-test top-level declaration in a test file. name is the
// identifier a test reaches it by: a function, type, variable or constant's
// own name, and for a method its receiver type's name, because a test reaches
// a method through a value of that type, and method names such as Done are
// shared with unrelated types. A shared name selects too much, never too
// little.
type support struct {
	name   string
	source string
	refs   map[string]bool
}

// receiverType returns the base type name of a method receiver.
func receiverType(fn *ast.FuncDecl) string {
	expr := fn.Recv.List[0].Type
	for {
		switch t := expr.(type) {
		case *ast.StarExpr:
			expr = t.X
		case *ast.IndexExpr:
			expr = t.X
		case *ast.IndexListExpr:
			expr = t.X
		case *ast.ParenExpr:
			expr = t.X
		case *ast.Ident:
			return t.Name
		default:
			return fn.Name.Name
		}
	}
}

// packageKey groups declarations the compiler links together: one directory's
// test files with the same package clause (internal or external test package).
type packageKey struct{ dir, name string }

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

// buildCtx is the variant being measured: the runner's GOOS/GOARCH and cgo
// setting plus the race tag and any --tags, as go test -race -tags would use.
var buildCtx = build.Default

// builds reports whether buildCtx compiles file at a revision. MatchFile applies
// both //go:build lines and _GOOS/_GOARCH file-name suffixes; OpenFile serves
// the blob so no checkout of ref is needed.
func builds(file string, source []byte) (bool, error) {
	ctx := buildCtx
	ctx.OpenFile = func(string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(source)), nil }
	return ctx.MatchFile(path.Dir(file), path.Base(file))
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

func identifiers(node ast.Node) map[string]bool {
	refs := make(map[string]bool)
	if node == nil {
		return refs
	}
	ast.Inspect(node, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			refs[id.Name] = true
		}
		return true
	})
	return refs
}

func formatted(fset *token.FileSet, node any) (string, error) {
	var out bytes.Buffer
	if err := format.Node(&out, fset, node); err != nil {
		return "", err
	}
	return out.String(), nil
}

// supportDecls lists a file's non-test declarations keyed by package. Named
// imports are left out: an import whose use changed is visible in the
// declaration that uses it. Blank imports are not; inits records init
// function bodies in file order, which is the order the go command runs them.
func supportDecls(fset *token.FileSet, file string, parsed *ast.File, into map[packageKey]map[string]support, inits map[packageKey][]string, blanks map[packageKey][]string) error {
	key := packageKey{path.Dir(file), parsed.Name.Name}
	decls := into[key]
	if decls == nil {
		decls = make(map[string]support)
		into[key] = decls
	}
	add := func(kind, key, name string, node any, refsNode ast.Node) error {
		source, err := formatted(fset, node)
		if err != nil {
			return err
		}
		// A variable and a constant with the same text are different
		// declarations: record the kind in the compared value.
		if kind == "var" || kind == "const" {
			source = kind + " " + source
		}
		// Key by declaration, not file, so moving a helper between files is
		// not a change. Mutually exclusive build-tagged files that declare the
		// same helper differently are combined in a stable order. Package-level
		// names are unique within a package, so a function, type, variable or
		// constant is keyed by name alone and a change of kind is a change.
		// Methods are keyed by receiver type and name.
		id := key
		switch kind {
		case "method":
			id = "method/" + key
		case "import":
			id = "import/" + key
		}
		item := support{name: name, source: source, refs: identifiers(refsNode)}
		if prior, ok := decls[id]; ok {
			// A set of variants: two files importing the same path, or
			// identical build-tagged twins, are one binding, not a change.
			item.source = strings.Join(uniqueSorted(append(strings.Split(prior.source, "\x00"), source)), "\x00")
			for ref := range prior.refs {
				item.refs[ref] = true
			}
		}
		decls[id] = item
		return nil
	}
	for _, decl := range parsed.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if isTest(d) && runnableName(d.Name.Name) {
				continue
			}
			if d.Recv == nil && d.Name.Name == "init" {
				source, err := formatted(fset, d)
				if err != nil {
					return err
				}
				// Lexical file order, then source order: the go command's init order.
				inits[key] = append(inits[key], source)
			}
			kind, declKey, name := "func", d.Name.Name, d.Name.Name
			if d.Recv != nil && len(d.Recv.List) == 1 {
				name = receiverType(d)
				kind, declKey = "method", name+"."+d.Name.Name
			}
			if err := add(kind, declKey, name, d, d); err != nil {
				return err
			}
		case *ast.GenDecl:
			if d.Tok == token.IMPORT {
				for _, spec := range d.Specs {
					sp, ok := spec.(*ast.ImportSpec)
					if !ok || sp.Path == nil {
						continue
					}
					importPath, err := strconv.Unquote(sp.Path.Value)
					if err != nil {
						return err
					}
					if sp.Name != nil && sp.Name.Name == "_" {
						blanks[key] = append(blanks[key], importPath)
						continue
					}
					if sp.Name != nil && sp.Name.Name == "." {
						continue
					}
					// A file-local name bound to a different path calls
					// different code from unchanged helpers that use it.
					// Record the binding so only those helpers propagate.
					local := importName(importPath)
					if sp.Name != nil {
						local = sp.Name.Name
					}
					binding := &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(importPath)}
					if err := add("import", local, local, binding, nil); err != nil {
						return err
					}
				}
				continue
			}
			// In a constant group a spec without values repeats the previous
			// expression, and iota counts specs: a change to an earlier spec
			// changes later constants whose own text did not change.
			var inheritedType ast.Expr
			var inheritedValues []ast.Expr
			for index, spec := range d.Specs {
				switch sp := spec.(type) {
				case *ast.TypeSpec:
					if err := add("type", sp.Name.Name, sp.Name.Name, sp, sp); err != nil {
						return err
					}
				case *ast.ValueSpec:
					effective := sp
					if d.Tok == token.CONST {
						if len(sp.Values) > 0 {
							inheritedType, inheritedValues = sp.Type, sp.Values
						} else {
							effective = &ast.ValueSpec{Names: sp.Names, Type: inheritedType, Values: inheritedValues}
						}
						if usesIota(effective) {
							effective = &ast.ValueSpec{
								Names: effective.Names, Type: effective.Type,
								Values: append(append([]ast.Expr(nil), effective.Values...),
									&ast.BasicLit{Kind: token.INT, Value: strconv.Itoa(index)}),
							}
						}
					}
					blank := false
					for _, name := range sp.Names {
						if name.Name == "_" {
							blank = true
							continue
						}
						if err := add(d.Tok.String(), name.Name, name.Name, effective, effective); err != nil {
							return err
						}
					}
					// A named variable whose initializer calls a function
					// also runs that call at package initialization for every
					// test, whether or not a test names the variable: treat
					// it as a hook like a blank variable.
					if d.Tok == token.VAR && !blank && callsFunction(sp) {
						source, err := formatted(fset, sp)
						if err != nil {
							return err
						}
						inits[key] = append(inits[key], "var "+source)
						if err := add("func", "\x00blank", "\x00blank", sp, sp); err != nil {
							return err
						}
					}
					// A blank variable's initializer runs at package
					// initialization for every test, like init, and no test
					// names it. Record it in the same ordered sequence. A
					// variable also keeps the initializer's references, under
					// its own id so it does not merge with func init: a change
					// to a declaration it names selects the whole package, as
					// a change reached through init does. A blank constant
					// does not run; its text is still part of the sequence.
					if blank {
						source, err := formatted(fset, sp)
						if err != nil {
							return err
						}
						inits[key] = append(inits[key], d.Tok.String()+" "+source)
						if d.Tok == token.VAR {
							if err := add("func", "\x00blank", "\x00blank", sp, sp); err != nil {
								return err
							}
						}
					}
				}
			}
		}
	}
	return nil
}

// importName approximates the default file-local name of an import path,
// which Go takes from the imported package's package clause. Without loading
// every import, use the conventions that clause follows: the last element,
// skipping a major-version element such as /v2, without a gopkg.in-style
// .vN suffix or a go- prefix or -go suffix, and up to the first dot or dash.
func importName(importPath string) string {
	parts := strings.Split(importPath, "/")
	name := parts[len(parts)-1]
	if len(parts) > 1 && len(name) > 1 && name[0] == 'v' && strings.Trim(name[1:], "0123456789") == "" {
		name = parts[len(parts)-2]
	}
	if i := strings.LastIndex(name, ".v"); i > 0 && strings.Trim(name[i+2:], "0123456789") == "" && len(name) > i+2 {
		name = name[:i]
	}
	name = strings.TrimSuffix(strings.TrimPrefix(name, "go-"), "-go")
	if i := strings.IndexAny(name, ".-"); i > 0 {
		name = name[:i]
	}
	return name
}

// callsFunction reports whether a variable's initializer calls a function
// outside a function literal, so it runs code at package initialization.
func callsFunction(spec *ast.ValueSpec) bool {
	found := false
	for _, value := range spec.Values {
		ast.Inspect(value, func(n ast.Node) bool {
			switch n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.CallExpr:
				found = true
			}
			return !found
		})
	}
	return found
}

// usesIota reports whether a constant spec's values mention iota, so its
// value also depends on its position in the group.
func usesIota(spec *ast.ValueSpec) bool {
	found := false
	for _, value := range spec.Values {
		ast.Inspect(value, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "iota" {
				found = true
			}
			return !found
		})
	}
	return found
}

// runnableName applies cmd/go's test-name rule: Test followed by a
// non-lowercase rune.
func runnableName(name string) bool {
	tail := strings.TrimPrefix(name, "Test")
	first, _ := utf8.DecodeRuneInString(tail)
	return tail == "" || !unicode.IsLower(first)
}

func inventory(ref string, files []string) (map[string]test, map[packageKey]map[string]support, map[packageKey][]string, map[packageKey][]string, error) {
	tests := make(map[string]test)
	supports := make(map[packageKey]map[string]support)
	inits := make(map[packageKey][]string)
	blanks := make(map[packageKey][]string)
	for _, file := range files {
		source, err := git("show", ref+":"+file)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		// A file this variant doesn't build declares nothing for it, at the base
		// as at the head, so a name only another platform declared stays new.
		if ok, err := builds(file, source); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("build constraints %s:%s: %w", ref, file, err)
		} else if !ok {
			continue
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, source, 0)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("parse %s:%s: %w", ref, file, err)
		}
		if err := supportDecls(fset, file, parsed, supports, inits, blanks); err != nil {
			return nil, nil, nil, nil, err
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !isTest(fn) || !runnableName(fn.Name.Name) {
				continue
			}
			source, err := formatted(fset, fn)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			item := test{
				File: file, Package: "./" + path.Dir(file), Name: fn.Name.Name, Source: source,
				ident: path.Dir(file) + "/" + parsed.Name.Name + "/" + fn.Name.Name,
				refs:  identifiers(fn),
				pkg:   packageKey{path.Dir(file), parsed.Name.Name},
			}
			// Include the file: mutually exclusive build-tagged files may declare
			// the same test name with different bodies.
			key := file + "/" + parsed.Name.Name + "/" + fn.Name.Name
			tests[key] = item
		}
	}
	return tests, supports, inits, blanks, nil
}

// affectedNames returns the support names a test can reach through a changed
// declaration, and whether every test in the package is affected.
//
// Only a declaration present at both revisions with different source counts
// as changed. An unchanged test cannot name a declaration that did not exist
// at the base, or it would not have compiled there, and a test that names a
// deleted one must itself have changed and is selected on its own. TestMain
// and init are the exception, as is a blank import: each runs for every test,
// whether or not the test names it. Init order is the sequence of bodies,
// not a sorted merge, because the go command runs them in that order.
func affectedNames(base, head map[string]support, baseInits, headInits, baseBlanks, headBlanks []string, seed map[string]bool) (map[string]bool, bool) {
	affected := make(map[string]bool)
	// An external test package reaches its internal package's changed
	// declarations through its own helpers, so those names start affected.
	for name := range seed {
		affected[name] = true
	}
	whole := !sameSequence(baseInits, headInits) || !sameSet(baseBlanks, headBlanks)
	for id, item := range head {
		old, ok := base[id]
		if id == "TestMain" && (!ok || old.source != item.source) {
			whole = true
		}
		if ok && old.source != item.source {
			affected[item.name] = true
		}
		// A new method on a type that already existed can replace a method
		// promoted from an embedded type, so calls through that type change.
		if !ok && strings.HasPrefix(id, "method/") {
			if _, existed := base[item.name]; existed {
				affected[item.name] = true
			}
		}
	}
	for id := range base {
		if _, ok := head[id]; !ok && id == "TestMain" {
			whole = true
		}
	}
	// Propagate through helpers that call changed helpers until nothing new
	// is reached. Each pass adds at least one name or stops. A hook that
	// reaches a changed name affects every test, not only tests that spell
	// the hook's name.
	for {
		grew := false
		for _, item := range head {
			if affected[item.name] {
				continue
			}
			for name := range affected {
				if item.refs[name] {
					affected[item.name] = true
					grew = true
					break
				}
			}
		}
		if !grew {
			// "\x00blank" is the synthetic hook for a package-level
			// `var _ = ...` initializer. It runs for every test, and no
			// test names it.
			if affected["init"] || affected["TestMain"] || affected["\x00blank"] {
				whole = true
			}
			return affected, whole
		}
	}
}

func sameSequence(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// sameSet compares as sets: importing the same package from one more file
// changes nothing a test can observe.
func sameSet(left, right []string) bool {
	return sameSequence(uniqueSorted(left), uniqueSorted(right))
}

func uniqueSorted(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	n := 0
	for i, v := range out {
		if i == 0 || v != out[n-1] {
			out[n] = v
			n++
		}
	}
	return out[:n]
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

func selectTests(base, head string, includeSupport bool) ([]test, error) {
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
	supportInventories := make([]map[packageKey]map[string]support, 0, 2)
	initInventories := make([]map[packageKey][]string, 0, 2)
	blankInventories := make([]map[packageKey][]string, 0, 2)
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
		tests, supports, inits, blanks, err := inventory(ref, files)
		if err != nil {
			return nil, err
		}
		inventories = append(inventories, tests)
		supportInventories = append(supportInventories, supports)
		initInventories = append(initInventories, inits)
		blankInventories = append(blankInventories, blanks)
	}
	declared := make(map[string]bool, len(inventories[0]))
	for _, item := range inventories[0] {
		declared[item.ident] = true
	}
	type packageImpact struct {
		names map[string]bool
		whole bool
	}
	impacts := make(map[packageKey]packageImpact)
	if includeSupport {
		keys := make(map[packageKey]bool)
		for _, inv := range supportInventories {
			for key := range inv {
				keys[key] = true
			}
		}
		for _, inv := range initInventories {
			for key := range inv {
				keys[key] = true
			}
		}
		for _, inv := range blankInventories {
			for key := range inv {
				keys[key] = true
			}
		}
		// Close internal packages first: an external test package's helpers
		// can wrap an internal package's changed declarations, so its graph
		// starts from the internal package's affected names.
		ordered := make([]packageKey, 0, len(keys))
		for key := range keys {
			ordered = append(ordered, key)
		}
		sort.Slice(ordered, func(i, j int) bool {
			ei, ej := strings.HasSuffix(ordered[i].name, "_test"), strings.HasSuffix(ordered[j].name, "_test")
			if ei != ej {
				return !ei
			}
			if ordered[i].dir != ordered[j].dir {
				return ordered[i].dir < ordered[j].dir
			}
			return ordered[i].name < ordered[j].name
		})
		for _, key := range ordered {
			var seed map[string]bool
			if internal, external := strings.CutSuffix(key.name, "_test"); external {
				seed = impacts[packageKey{key.dir, internal}].names
			}
			names, whole := affectedNames(
				supportInventories[0][key], supportInventories[1][key],
				initInventories[0][key], initInventories[1][key],
				blankInventories[0][key], blankInventories[1][key], seed,
			)
			impacts[key] = packageImpact{names: names, whole: whole}
		}
	}
	reachedBy := func(item test, key packageKey) bool {
		impact, ok := impacts[key]
		if !ok {
			return false
		}
		if impact.whole {
			return true
		}
		for name := range impact.names {
			if item.refs[name] {
				return true
			}
		}
		return false
	}
	// The go command links an internal test package and its external
	// (_test) package into one test binary. The external package can call
	// the internal package's exported test helpers and runs its hooks. The
	// internal package cannot call the external package's helpers. An
	// external hook still runs for every test in the binary, so only that
	// whole-package impact crosses back.
	reaches := func(item test) bool {
		if reachedBy(item, item.pkg) {
			return true
		}
		internal, external := strings.CutSuffix(item.pkg.name, "_test")
		if external {
			return reachedBy(item, packageKey{item.pkg.dir, internal})
		}
		other, ok := impacts[packageKey{item.pkg.dir, item.pkg.name + "_test"}]
		return ok && other.whole
	}
	changed := []test{}
	for key, item := range inventories[1] {
		old, exists := inventories[0][key]
		edited := !exists || old.Source != item.Source
		if edited || includeSupport && reaches(item) {
			item.New = !declared[item.ident]
			if includeSupport {
				item.Reason = "support"
				if edited {
					item.Reason = "changed"
				}
			}
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
	tags := flag.String("tags", "", "comma-separated build tags of the measured variant")
	includeSupport := flag.Bool("include-support", false, "also select tests that reach a changed non-test declaration")
	flag.Parse()
	buildCtx.BuildTags = []string{"race"}
	for _, tag := range strings.Split(*tags, ",") {
		if tag != "" {
			buildCtx.BuildTags = append(buildCtx.BuildTags, tag)
		}
	}
	if *base == "" {
		fmt.Fprintln(os.Stderr, "--base is required")
		os.Exit(2)
	}
	tests, err := selectTests(*base, *head, *includeSupport)
	if err == nil {
		err = json.NewEncoder(os.Stdout).Encode(tests)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
