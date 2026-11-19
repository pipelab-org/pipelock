// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
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
		"EmitDeferredResolutionReceipt emitDeferredResolutionReceipt emitMCPDeferredKillSwitchReceipt confirmMCPResponseEffect " +
		"emitForwardReceipt emitFetchReceipt emitReverseReceipt emitTunnelReceipt emitWSReceipt " +
		"emitRecordedReceipt emitRequiredReceipt emitRequestPolicyReceipt confirmResponseDecision confirmResponseOrBlock " +
		"interceptConfirmResponseOrBlock interceptEmitReceiptOrBlock interceptEmitRequiredReceipt interceptEmitOutcomeReceipt " +
		"emitOutcomeReceipt emitObservedOutcomeReceipt emitOutcomeReceiptWithPattern " +
		"recordIssuerQueryAllow recordIssuerCookieAllow recordCredentialAudienceAllow recordCredentialAudienceAllows " +
		"emitDeferredReceipt emitAllowPathReceipt emitReceiptFailureMarker recordReceiptEmitterUnavailable " +
		"emitReceipt emitMCPReceiptDecision emitMCPOutcome emitMCPToolScanReceipt " +
		"emitForwardDenial emitHoldFailureResolution emitKillSwitchDenialReceipt confirmShieldIntervention " +
		"commitAllow ensure blockCrossMessageIncomplete closeUpstreamCrossMessage sseFindingReceiptConfirmer emitV1 " +
		"emitCredentialAudienceReceipt emitCredentialAudienceReceiptWithFallback emitRequiredV2Receipt emitReceiptFailureMarkerWithLogger " +
		"emitReceiptDecisionWithControl EmitMCPDecision EmitMCPGroupDecision emitMCPDecision emitMCPV2Decision emitMCPBlockedOutcomeReceipt " +
		"emitReceiptWithEmitter emitRequiredReceiptWithEmitter interceptEmitReceipt " +
		"emitV2Receipt emitV2 emitRequiredV2 emitGroupV2Receipt emitDLPWarn " +
		"EmitSessionOpen EmitSessionClose EmitHeartbeat EmitTranscriptRoot " +
		"BuildProxyDecisionReceipt BuildProxyDecisionWithSpansReceipt BuildSecretEgressDecisionReceipt " +
		"SignReceipt EmitBatch RecordPrescanned buildReceipt")

func TestReceiptV3EmitterBindings(t *testing.T) {
	root := "../.."
	raw, err := os.ReadFile(filepath.Join(root, "sdk", "receipt-v3", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	type attribution struct {
		Source string `json:"source"`
		Fields string `json:"fields"`
		When   string `json:"when"`
	}
	var registry struct {
		Attribution map[string]attribution `json:"emit_attribution"`
		EmitSites   map[string]string      `json:"emit_sites"`
		Exclusions  map[string]string      `json:"emit_exclusions"`
		Forwarders  map[string]string      `json:"emit_forwarders"`
		Enums       map[string][]string    `json:"enums"`
	}
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	var discovered []string
	counts := make(map[string]int)
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "node_modules" || entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse emission sites in %s: %w", path, err)
		}
		check := func(owner, callee string, node ast.Node) {
			key := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator))) + "/" + owner + "/" + callee
			counts[key]++
			key = fmt.Sprintf("%s/%d", key, counts[key])
			discovered = append(discovered, key)
			boundary, bound := registry.EmitSites[key]
			exclusion, excluded := registry.Exclusions[key]
			forwarder, forwarded := registry.Forwarders[key]
			if entry, documented := registry.Attribution[key]; bound && documented {
				pos := fset.Position(node.Pos())
				source := fmt.Sprintf("%s:%d", filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator))), pos.Line)
				if entry.Source != source || strings.TrimSpace(entry.Fields) == "" || strings.TrimSpace(entry.When) == "" {
					t.Errorf("incorrect producer attribution at %s: %+v, expected %s", key, entry, source)
				}
			}
			if testing.Verbose() {
				var source bytes.Buffer
				if err := format.Node(&source, fset, node); err != nil {
					t.Errorf("format emission source %s: %v", key, err)
				}
				t.Logf("%s %s %s %s %s", key, fset.Position(node.Pos()), boundary, exclusion+forwarder, source.String())
			}
			switch {
			case (bound && excluded) || (forwarded && (bound || excluded)):
				t.Errorf("duplicate emission binding %s", key)
			case !bound && strings.TrimSpace(exclusion) == "" && strings.TrimSpace(forwarder) == "":
				t.Errorf("unbound emission site %s (%s)", key, fset.Position(node.Pos()))
			}
		}
		for _, decl := range file.Decls {
			owner := "package"
			if fn, ok := decl.(*ast.FuncDecl); ok {
				owner = fn.Name.Name
			}
			ast.Inspect(decl, func(node ast.Node) bool {
				switch node := node.(type) {
				case *ast.CallExpr:
					callee := calledName(node)
					if slices.Contains(receiptEmissionCalls, callee) || directReceiptEmission(node, callee) {
						check(owner, callee, node)
					}
				case *ast.CompositeLit:
					if name := receiptConstruction(node, file); name != "" {
						check(owner, name, node)
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, sites := range []map[string]string{registry.Exclusions, registry.Forwarders} {
		for site, reason := range sites {
			if !slices.Contains(discovered, site) || strings.TrimSpace(reason) == "" {
				t.Errorf("unknown or undocumented emission site %s", site)
			}
		}
	}
	for site := range registry.Attribution {
		if _, ok := registry.EmitSites[site]; !ok {
			t.Errorf("producer attribution has no effect binding %s", site)
		}
	}
	for site, boundary := range registry.EmitSites {
		if _, ok := registry.Attribution[site]; !ok {
			t.Errorf("effect binding has no producer attribution %s", site)
		}
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

// Receipt emitters take one decision or options value. Audit emitters take a
// context and event arguments. Check the call even when its options are built
// elsewhere, including through interface-typed receivers and function fields.
func directReceiptEmission(call *ast.CallExpr, name string) bool {
	return (name == "Emit" || name == "EmitDurable") && len(call.Args) == 1
}

func receiptConstruction(lit *ast.CompositeLit, file *ast.File) string {
	if len(lit.Elts) == 0 {
		return ""
	}
	switch typ := lit.Type.(type) {
	case *ast.Ident:
		if file.Name.Name == "receipt" && (typ.Name == "ActionRecord" || typ.Name == "Receipt" || typ.Name == "EvidenceReceipt") {
			return typ.Name
		}
	case *ast.SelectorExpr:
		pkg, ok := typ.X.(*ast.Ident)
		if !ok || typ.Sel.Name != "ActionRecord" && typ.Sel.Name != "Receipt" && typ.Sel.Name != "EvidenceReceipt" {
			return ""
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, "\"")
			if path != "github.com/luckyPipewrench/pipelock/internal/receipt" &&
				path != "github.com/luckyPipewrench/pipelock/internal/contract/receipt" {
				continue
			}
			name := "receipt"
			if imp.Name != nil {
				name = imp.Name.Name
			}
			if pkg.Name == name {
				return typ.Sel.Name
			}
		}
	}
	return ""
}
