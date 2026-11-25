// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package readerinventory

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/luckyPipewrench/pipelock/"

type reader struct {
	Package string `json:"package"`
	Role    string `json:"role"`
	Reason  string `json:"reason"`
	Test    string `json:"test,omitempty"`
}

type listedPackage struct {
	ImportPath   string
	Imports      []string
	TestGoFiles  []string
	XTestGoFiles []string
}

func TestReceiptReaderInventory(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	data, err := os.ReadFile("../../../docs/security/receipt-readers.json")
	if err != nil {
		t.Fatal(err)
	}
	var registry []reader
	if err := json.Unmarshal(data, &registry); err != nil {
		t.Fatal(err)
	}

	packages := make(map[string]bool)
	importers := make(map[string]bool)
	tests := make(map[string]map[string]bool)
	for _, tags := range []string{"", "enterprise"} {
		collectPackages(t, root, tags, packages, importers, tests)
	}

	registered := make(map[string]bool, len(registry))
	for _, entry := range registry {
		if registered[entry.Package] {
			t.Errorf("duplicate receipt reader entry: %s", entry.Package)
		}
		registered[entry.Package] = true
		if !packages[entry.Package] {
			t.Errorf("receipt reader package no longer exists: %s", entry.Package)
		}
		if entry.Reason == "" {
			t.Errorf("receipt reader entry %s needs a reason", entry.Package)
		}
		switch entry.Role {
		case "writer", "not-a-reader":
		case "v3-verifier", "refuses-v3":
			testPackage, testName, external := strings.Cut(entry.Test, ":")
			if !external {
				testPackage, testName = entry.Package, entry.Test
			}
			if !tests[testPackage][testName] {
				t.Errorf("receipt reader entry %s needs an existing behavior test, got %q", entry.Package, entry.Test)
			}
		default:
			t.Errorf("receipt reader entry %s has invalid role %q", entry.Package, entry.Role)
		}
	}
	for pkg := range importers {
		if !registered[pkg] {
			t.Errorf("receipt evidence importer %s is missing from docs/security/receipt-readers.json", pkg)
		}
	}
}

func collectPackages(t *testing.T, root, tags string, packages, importers map[string]bool, tests map[string]map[string]bool) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", "list", "-tags", tags, "-json=ImportPath,Imports,TestGoFiles,XTestGoFiles", "./...") // #nosec G204 -- Go tool, fixed flags and build tags.
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list with tags %q: %v", tags, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(output)))
	for {
		var pkg listedPackage
		if err := dec.Decode(&pkg); err == io.EOF {
			return
		} else if err != nil {
			t.Fatal(err)
		}
		name, local := strings.CutPrefix(pkg.ImportPath, module)
		if !local {
			continue
		}
		packages[name] = true
		for _, path := range pkg.Imports {
			if isReceiptEvidenceImport(path) {
				importers[name] = true
				break
			}
		}
		if tests[name] == nil {
			tests[name] = make(map[string]bool)
		}
		for _, path := range append(pkg.TestGoFiles, pkg.XTestGoFiles...) {
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, name, path), nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
					tests[name][fn.Name.Name] = true
				}
			}
		}
	}
}

func isReceiptEvidenceImport(path string) bool {
	rel, local := strings.CutPrefix(path, module)
	if !local {
		return false
	}
	switch rel {
	case "internal/receipt", "internal/recorder", "internal/contract/receipt", "internal/evidence", "internal/evidenceview":
		return true
	}
	return strings.HasPrefix(rel, "internal/receipt/") || strings.HasPrefix(rel, "internal/evidence/")
}

// The browser verifier is built for js/wasm, which cannot link the receipt v3
// verifier's SQLite driver. A reader refusal helper that imports v3 breaks that
// artifact at build time.
func TestBrowserVerifierBuildsForWasm(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", "./cmd/pipelock-verifier-wasm") // #nosec G204 -- Go tool, fixed arguments.
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("browser verifier dependency graph does not resolve for js/wasm: %v\n%s", err, output)
	}
	if strings.Contains(string(output), "pipelock/internal/receipt/v3\n") {
		t.Fatal("browser verifier imports internal/receipt/v3, which needs SQLite")
	}
}
