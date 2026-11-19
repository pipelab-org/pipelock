// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var receiptEmissionCalls = strings.Fields(
	"emitReceiptDecision emitAdmittedReceiptDecision emitMCPStandaloneStreamReceipt emitMCPOutcomeReceipt emitMCPToolReceipt " +
		"EmitDeferredResolutionReceipt emitMCPDeferredKillSwitchReceipt confirmMCPResponseEffect " +
		"emitForwardReceipt emitFetchReceipt emitReverseReceipt emitTunnelReceipt emitWSReceipt " +
		"emitRecordedReceipt emitRequiredReceipt emitRequestPolicyReceipt confirmResponseDecision confirmResponseOrBlock " +
		"interceptConfirmResponseOrBlock interceptEmitReceiptOrBlock interceptEmitRequiredReceipt interceptEmitOutcomeReceipt " +
		"emitOutcomeReceipt emitObservedOutcomeReceipt emitOutcomeReceiptWithPattern " +
		"recordIssuerQueryAllow recordIssuerCookieAllow recordCredentialAudienceAllow recordCredentialAudienceAllows " +
		"emitDeferredReceipt emitAllowPathReceipt emitReceiptFailureMarker recordReceiptEmitterUnavailable")

func TestReceiptV3EmitterBindings(t *testing.T) {
	root := "../.."
	raw, err := os.ReadFile(filepath.Join(root, "sdk", "receipt-v3", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var registry struct {
		EmitSites map[string]string   `json:"emit_sites"`
		Enums     map[string][]string `json:"enums"`
	}
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	var discovered []string
	counts := make(map[string]int)
	fset := token.NewFileSet()
	for _, dir := range []string{"internal/mcp", "internal/proxy", "internal/deferred", "internal/cli/runtime", "internal/cli/setup"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return fmt.Errorf("parse emission sites in %s: %w", path, err)
			}
			for _, decl := range file.Decls {
				fn, isFunc := decl.(*ast.FuncDecl)
				if !isFunc || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					call, isCall := node.(*ast.CallExpr)
					if !isCall {
						return true
					}
					callee := calledName(call)
					if !slices.Contains(receiptEmissionCalls, callee) && !literalReceiptEmission(call, callee) {
						return true
					}
					key := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator))) + "/" + fn.Name.Name + "/" + callee
					counts[key]++
					key = fmt.Sprintf("%s/%d", key, counts[key])
					discovered = append(discovered, key)
					if _, exists := registry.EmitSites[key]; !exists {
						t.Errorf("unbound emission site %s (%s)", key, fset.Position(node.Pos()))
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for site, boundary := range registry.EmitSites {
		if !slices.Contains(discovered, site) {
			t.Errorf("unknown emission site %s", site)
		}
		if !slices.Contains(registry.Enums["boundary"], boundary) {
			t.Errorf("invalid effect boundary for %s: %s", site, boundary)
		}
	}
}

func calledName(call *ast.CallExpr) string {
	switch target := call.Fun.(type) {
	case *ast.Ident:
		return target.Name
	case *ast.SelectorExpr:
		return target.Sel.Name
	default:
		return ""
	}
}

func literalReceiptEmission(call *ast.CallExpr, callee string) bool {
	if callee != "Emit" && callee != "EmitDurable" {
		return false
	}
	for _, arg := range call.Args {
		literal, ok := arg.(*ast.CompositeLit)
		if !ok {
			continue
		}
		selector, ok := literal.Type.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "EmitOpts" {
			continue
		}
		pkg, ok := selector.X.(*ast.Ident)
		if ok && pkg.Name == "receipt" {
			return true
		}
	}
	return false
}
