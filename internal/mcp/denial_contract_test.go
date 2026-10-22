// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestMCPDenialCatalog(t *testing.T) {
	seen := make(map[mcpDenialKind]bool)
	classes := []string{audit.BlockClassThreat, audit.BlockClassProtective, audit.BlockClassConfigMismatch, audit.BlockClassInfrastructureError, audit.BlockClassStructuralExemption}
	for _, spec := range mcpDenialCatalog {
		if seen[spec.kind] || spec.kind == "" {
			t.Errorf("duplicate/empty denial kind %q", spec.kind)
		}
		seen[spec.kind] = true
		if spec.label == "" || !slices.Contains(classes, spec.class) {
			t.Errorf("invalid denial spec %+v", spec)
		}
		if !slices.Contains([]string{"mcp_input", "mcp_response", "mcp_listener_header", "mcp_redirect_output", "upstream_error_reply", "mcp-input", "mcp_listener", "mcp_startup"}, spec.resource) {
			t.Errorf("unsafe resource in %+v", spec)
		}
		if scanner.OperatorHintForResult(spec.label, spec.reason) == "" {
			t.Errorf("no remediation for %q", spec.label)
		}
	}
	if _, valid := denialSpec("unregistered"); valid {
		t.Fatal("unknown denial accepted")
	}
}

// The URL family is published as Scanner* constants in scanner.go and core.go.
// Read that source rather than copying the label list into this contract test.
func TestMCPDenialURLCatalog(t *testing.T) {
	seen := make(map[string]bool)
	for _, path := range []string{"../scanner/scanner.go", "../scanner/core.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			spec, ok := node.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for index, name := range spec.Names {
				if !strings.HasPrefix(name.Name, "Scanner") {
					continue
				}
				// These describe a successful aggregate or a non-URL surface.
				if slices.Contains([]string{"ScannerAll", "ScannerMCPToolScanning", "ScannerCoreResponse"}, name.Name) {
					continue
				}
				if index >= len(spec.Values) {
					t.Fatalf("scanner label %s has no literal value", name.Name)
				}
				literal, ok := spec.Values[index].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Fatalf("scanner label %s is not a string", name.Name)
				}
				label, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				seen[label] = true
				for class, want := range map[scanner.ResultClass]string{
					scanner.ClassThreat:              audit.BlockClassThreat,
					scanner.ClassHeuristicEntropy:    audit.BlockClassThreat,
					scanner.ClassProtective:          audit.BlockClassProtective,
					scanner.ClassInfrastructureError: audit.BlockClassInfrastructureError,
					scanner.ClassConfigMismatch:      audit.BlockClassConfigMismatch,
				} {
					descriptor := mcpInputBlockAudit(InputVerdict{URLFindings: []scanner.Result{{Scanner: label, Class: class}}})
					registered, valid := denialSpec(descriptor.kind)
					if !valid || registered.label != label || registered.class != want {
						t.Errorf("URL label %s class %v lost: %+v", label, class, registered)
					}
				}
			}
			return true
		})
	}
	if !seen[scanner.ScannerSSRF] || !seen[scanner.ScannerCoreDLP] {
		t.Fatal("URL catalog source positive control missing")
	}
}

func TestSIEMMCPBlockedScannerLabelsMatchCatalog(t *testing.T) {
	guide, err := os.ReadFile("../../docs/guides/siem-integration.md")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkMCPDenialDocs(string(guide), MCPDenialLabels()); err != nil {
		t.Fatal(err)
	}
	// A deleted row and a deleted catalog registration must both be detected.
	mutated := strings.Replace(string(guide), "| `mcp_input_dlp`", "| `missing_label`", 1)
	if checkMCPDenialDocs(mutated, MCPDenialLabels()) == nil {
		t.Fatal("deleted docs row survived")
	}
	labels := MCPDenialLabels()
	if checkMCPDenialDocs(string(guide), labels[1:]) == nil {
		t.Fatal("deleted catalog registration survived")
	}
}

func checkMCPDenialDocs(guide string, labels []string) error {
	const begin = "<!-- BEGIN MCP blocked scanner labels -->"
	const end = "<!-- END MCP blocked scanner labels -->"
	start, finish := strings.Index(guide, begin), strings.Index(guide, end)
	if start < 0 || finish <= start {
		return fmt.Errorf("MCP label table markers missing")
	}
	rows := regexp.MustCompile("(?m)^\\| `([a-z0-9_]+)` \\|").FindAllStringSubmatch(guide[start:finish], -1)
	documented := make(map[string]bool)
	for _, row := range rows {
		if documented[row[1]] {
			return fmt.Errorf("duplicate MCP docs label %q", row[1])
		}
		documented[row[1]] = true
	}
	for _, label := range labels {
		if !documented[label] {
			return fmt.Errorf("undocumented MCP denial label %q", label)
		}
		delete(documented, label)
	}
	if len(documented) != 0 {
		return fmt.Errorf("unregistered MCP docs labels %v", documented)
	}
	return nil
}

// denialSourceViolations uses resolved objects, so import aliases and type
// aliases cannot hide a forbidden audit call. Wire writes are admitted only at
// finalizer adapters or the named ordinary forwarding/transport-error exits.
func denialSourceViolations(file *ast.File, info *types.Info, fset *token.FileSet) []string {
	parents := make(map[ast.Node]ast.Node)
	var stack []ast.Node
	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	var violations []string
	report := func(n ast.Node, reason string) {
		violations = append(violations, fmt.Sprintf("%s: %s", fset.Position(n.Pos()), reason))
	}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		name := fn.Name.Name
		denialFile := slices.Contains([]string{"denial.go", "denial_listener.go"}, filepath.Base(fset.Position(fn.Pos()).Filename))
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				if object, ok := info.ObjectOf(node.Sel).(*types.Func); ok && object.Name() == "WriteMessage" && !denialFile {
					call, direct := parents[node].(*ast.CallExpr)
					if !direct || call.Fun != node {
						report(node, "wire method reference bypasses denial/forwarding adapter")
					}
				}
				if object, ok := info.ObjectOf(node.Sel).(*types.Func); ok && object.Pkg() != nil && object.Pkg().Path() == "github.com/luckyPipewrench/pipelock/internal/audit" && slices.Contains([]string{"LogBlocked", "LogBlockedDetail", "LogMCPBlocked"}, object.Name()) && name != "finishMCPDenial" {
					report(node, "canonical MCP block reference bypasses finalizer")
				}

			case *ast.CallExpr:
				selector, ok := node.Fun.(*ast.SelectorExpr)
				if !ok {
					break
				}
				object, _ := info.ObjectOf(selector.Sel).(*types.Func)
				if object == nil || object.Pkg() == nil {
					break
				}
				pkg := object.Pkg().Path()
				if name == "RunHTTPListenerProxy" && slices.Contains([]string{"Write", "WriteHeader"}, object.Name()) {
					if typ := info.TypeOf(selector.X); typ == nil || typ.String() != "*github.com/luckyPipewrench/pipelock/internal/mcp.mcpListenerDenialWriter" {
						report(node, "listener delivery bypasses admission adapter")
					}
				}
				if pkg == "net/http" && object.Name() == "Error" && name == "RunHTTPListenerProxy" {
					if typ := info.TypeOf(node.Args[0]); typ == nil || typ.String() != "*github.com/luckyPipewrench/pipelock/internal/mcp.mcpListenerDenialWriter" {
						report(node, "listener error bypasses admission adapter")
					}
				}

				if pkg == "github.com/luckyPipewrench/pipelock/internal/audit" && slices.Contains([]string{"LogBlocked", "LogBlockedDetail", "LogMCPBlocked"}, object.Name()) && name != "finishMCPDenial" {
					report(node, "canonical MCP block emission bypasses finalizer")
				}
				if object.Name() == "WriteMessage" && !denialFile {
					permitted := false
					argument := ""
					if len(node.Args) == 1 {
						if id, ok := node.Args[0].(*ast.Ident); ok {
							argument = id.Name
						}
						if call, ok := node.Args[0].(*ast.CallExpr); ok {
							if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "upstreamErrorResponse" {
								argument = "ordinaryUpstreamError"
							}
						}
					}
					// Each exception is ordinary forwarding or a transport failure, never a
					// Pipelock refusal. Keep this function-scoped, not file-scoped.
					switch name {
					case "WriteMessage":
						permitted = argument == "msg" && slices.Contains([]string{"server_identity_writer.go", "mcp_sse_bridge.go"}, filepath.Base(fset.Position(fn.Pos()).Filename))
					case "ForwardScanned":
						permitted = argument == "line"
					case "ForwardScannedInput":
						permitted = argument == "msg" || argument == "heldLine"
					case "RunWSProxy":
						if field, ok := node.Args[0].(*ast.SelectorExpr); ok {
							permitted = field.Sel.Name == "ForwardMessage"
						}
					case "RunHTTPProxy":
						permitted = argument == "ordinaryUpstreamError" || argument == "errResp"
					case "emitPendingTimeoutResponses", "emitRequestScopedTimeout":
						permitted = argument == "resp"
					}
					if !permitted {
						report(node, "wire delivery bypasses denial/forwarding adapter")
					}
				}
			case *ast.SendStmt:
				typ := info.TypeOf(node.Value)
				if typ != nil && strings.HasSuffix(typ.String(), ".BlockedRequest") && name != "sendMCPDenial" && name != "sendMCPSynthetic" {
					report(node, "denial handoff bypasses finalizer")
				}
			case *ast.CompositeLit:
				typ := info.TypeOf(node)
				if typ == nil {
					break
				}
				switch types.Unalias(typ).String() {
				case "github.com/luckyPipewrench/pipelock/internal/mcp.mcpDenial", "github.com/luckyPipewrench/pipelock/internal/mcp.mcpTerminalDecision":
					if !denialFile {
						report(node, "terminal identity constructed outside denial adapters")
					}
				case "github.com/luckyPipewrench/pipelock/internal/mcp.mcpDenialAudit":
					if len(node.Elts) > 0 && !slices.Contains([]string{"denial.go", "audit.go"}, filepath.Base(fset.Position(fn.Pos()).Filename)) {
						report(node, "descriptor constructed outside kind-specific classifier")
					}

					for _, element := range node.Elts {
						field, ok := element.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						key, ok := field.Key.(*ast.Ident)
						if !ok || key.Name != "kind" {
							continue
						}
						literal, ok := field.Value.(*ast.BasicLit)
						if !ok || literal.Kind != token.STRING {
							continue
						}
						kind, err := strconv.Unquote(literal.Value)
						if err != nil {
							report(node, "invalid kind literal")
							continue
						}
						if _, valid := denialSpec(mcpDenialKind(kind)); !valid {
							report(node, "unregistered denial kind "+kind)
						}
					}
				}
			}
			return true
		})
	}
	return violations
}

type denialSourcePackage struct {
	files   []*ast.File
	info    *types.Info
	fset    *token.FileSet
	imports types.Importer
}

// Use Go's own export files with the standard-library type checker. This keeps
// the guard independent of third-party analyzer dependencies.
func loadDenialSource(t *testing.T, tags string, platform ...string) denialSourcePackage {
	t.Helper()
	command := exec.CommandContext(context.Background(), "go", "list", "-export", "-deps", "-json", "-tags=", ".")
	if tags == "enterprise" {
		command = exec.CommandContext(context.Background(), "go", "list", "-export", "-deps", "-json", "-tags=enterprise", ".")
	} else if tags != "" {
		t.Fatalf("unsupported source contract build tags %q", tags)
	}
	if len(platform) != 0 {
		command.Env = append(os.Environ(), "GOOS="+platform[0], "GOARCH=amd64", "CGO_ENABLED=0")
	}
	output, err := command.Output()
	if err != nil {
		t.Fatalf("go list export data: %v", err)
	}
	exports := make(map[string]string)
	var source struct {
		Dir        string
		GoFiles    []string
		ImportPath string
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	for decoder.More() {
		var pkg struct {
			Dir        string
			GoFiles    []string
			ImportPath string
			Export     string
		}
		if err := decoder.Decode(&pkg); err != nil {
			t.Fatal(err)
		}
		exports[pkg.ImportPath] = pkg.Export
		if pkg.ImportPath == "github.com/luckyPipewrench/pipelock/internal/mcp" {
			source.Dir, source.GoFiles, source.ImportPath = pkg.Dir, pkg.GoFiles, pkg.ImportPath
		}
	}
	if len(source.GoFiles) == 0 {
		t.Fatal("no source files analyzed")
	}
	fset := token.NewFileSet()
	imports := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) { return os.Open(exports[path]) })
	var files []*ast.File
	for _, name := range source.GoFiles {
		file, err := parser.ParseFile(fset, filepath.Join(source.Dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	checker := types.Config{Importer: imports}
	if _, err := checker.Check(source.ImportPath, fset, files, info); err != nil {
		t.Fatal(err)
	}
	return denialSourcePackage{files: files, info: info, fset: fset, imports: imports}
}

func TestMCPDenialSourceContract(t *testing.T) {
	for _, platform := range []string{"linux", "darwin", "windows"} {
		for _, tags := range []string{"", "enterprise"} {
			t.Run(platform+"/tags="+tags, func(t *testing.T) {
				pkg := loadDenialSource(t, tags, platform)
				for _, file := range pkg.files {
					for _, violation := range denialSourceViolations(file, pkg.info, pkg.fset) {
						t.Error(violation)
					}
				}
			})
		}
	}
}

// Parse/type-check malicious snippets against the real audit package export.
// Aliasing both the import and receiver type must not evade the source guard.
func TestMCPDenialSourceContractRejectsAliasedLogger(t *testing.T) {
	pkg := loadDenialSource(t, "")
	auditPackage, err := pkg.imports.Import("github.com/luckyPipewrench/pipelock/internal/audit")
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{
		`package mcp; import a "github.com/luckyPipewrench/pipelock/internal/audit"; func bypass(l *a.Logger, c a.LogContext) { l.LogBlocked(c,"mcp_input_dlp","test") }`,
		`package mcp; import a "github.com/luckyPipewrench/pipelock/internal/audit"; func bypass(l *a.Logger, c a.LogContext) { f:=l.LogBlocked; f(c,"mcp_input_dlp","test") }`,
		`package mcp; import renamed "github.com/luckyPipewrench/pipelock/internal/audit"; type alias = renamed.Logger; func bypass(l *alias, c renamed.LogContext) { l.LogMCPBlocked(c,"mcp_input_dlp","test",renamed.BlockDetail{}) }`,
	} {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "bypass.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
		checker := types.Config{Importer: denialTestImporter{pkg: auditPackage}}
		if _, err := checker.Check("github.com/luckyPipewrench/pipelock/internal/mcp", fset, []*ast.File{file}, info); err != nil {
			t.Fatal(err)
		}
		if len(denialSourceViolations(file, info, fset)) == 0 {
			t.Fatal("aliased canonical emission bypass survived")
		}
	}
}

type denialTestImporter struct{ pkg *types.Package }

func (i denialTestImporter) Import(string) (*types.Package, error) { return i.pkg, nil }

func TestMCPDenialSourceContractRejectsDirectWire(t *testing.T) {
	pkg := loadDenialSource(t, "")
	for _, source := range []string{
		`package mcp; import renamed "github.com/luckyPipewrench/pipelock/internal/mcp/transport"; func bypass(w renamed.MessageWriter) error { return w.WriteMessage([]byte("denied")) }`,
		`package mcp; import renamed "github.com/luckyPipewrench/pipelock/internal/mcp/transport"; type alias=renamed.MessageWriter; func bypass(w alias) error { return w.WriteMessage([]byte("denied")) }`,
		`package mcp; import renamed "github.com/luckyPipewrench/pipelock/internal/mcp/transport"; func bypass(w renamed.MessageWriter) error { send := w.WriteMessage; return send([]byte("denied")) }`,
	} {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "bypass.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
		checker := types.Config{Importer: pkg.imports}
		if _, err := checker.Check("github.com/luckyPipewrench/pipelock/internal/mcp", fset, []*ast.File{file}, info); err != nil {
			t.Fatal(err)
		}
		if len(denialSourceViolations(file, info, fset)) == 0 {
			t.Fatal("direct wire bypass survived")
		}
	}
}
