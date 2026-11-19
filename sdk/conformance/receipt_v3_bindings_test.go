// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
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
		"confirmHTTPResponseDelivery emitForwardReceipt emitFetchReceipt emitReverseReceipt emitTunnelReceipt emitWSReceipt " +
		"emitRecordedReceipt emitRequiredReceipt emitRequestPolicyReceipt confirmResponseDecision confirmV3ResponseDecision confirmResponseOrBlock " +
		"interceptConfirmResponseOrBlock interceptEmitReceiptOrBlock interceptEmitRequiredReceipt interceptEmitOutcomeReceipt " +
		"emitOutcomeReceipt emitObservedOutcomeReceipt emitOutcomeReceiptWithPattern " +
		"recordIssuerQueryAllow recordIssuerCookieAllow recordCredentialAudienceAllow recordCredentialAudienceAllows recordV3IssuerCookieAllows recordV3CredentialAudienceAllows recordV3ExceptionAllows " +
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
		"SignReceipt EmitBatch RecordPrescanned buildReceipt confirmTransportReceipt recordTransportOutcome recordTransportNotReleased writePayload finishRedirect confirmV3ResponseDelivery confirmV3StreamAdmission writeV3Response WriteAction WriteAdmissionBatch")

type receiptProducerAttribution struct {
	Fields string `json:"fields"`
	When   string `json:"when"`
}

type receiptBindingRegistry struct {
	Attribution map[string]receiptProducerAttribution `json:"emit_attribution"`
	EmitSites   map[string]string                     `json:"emit_sites"`
	Exclusions  map[string]string                     `json:"emit_exclusions"`
	Forwarders  map[string]string                     `json:"emit_forwarders"`
	Enums       map[string][]string                   `json:"enums"`
}

type receiptEmissionSite struct {
	key      string
	position token.Position
}

const regenerateReceiptV3 = "Run python3 sdk/conformance/generate_receipt_v3.py to regenerate the spec and schemas."

func TestReceiptV3EmitterBindings(t *testing.T) {
	root := "../.."
	raw, err := os.ReadFile(filepath.Join(root, "sdk", "receipt-v3", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var registry receiptBindingRegistry
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}

	var discovered []receiptEmissionSite
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
		relative := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		sites, err := receiptEmissionSites(fset, relative, file)
		if err != nil {
			return err
		}
		discovered = append(discovered, sites...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range receiptBindingIssues(registry, discovered) {
		t.Error(issue)
	}
}

func receiptBindingIssues(registry receiptBindingRegistry, sites []receiptEmissionSite) []string {
	var issues []string
	discovered := make(map[string]bool, len(sites))
	for _, site := range sites {
		key := site.key
		discovered[key] = true
		_, bound := registry.EmitSites[key]
		_, excluded := registry.Exclusions[key]
		_, forwarded := registry.Forwarders[key]
		switch {
		case (bound && excluded) || (forwarded && (bound || excluded)):
			issues = append(issues, fmt.Sprintf("duplicate emission binding %s (%s)", key, site.position))
		case !bound && !excluded && !forwarded:
			issues = append(issues, fmt.Sprintf("unbound emission site %s (%s). In sdk/receipt-v3/registry.json, add this key to emit_sites with its effect boundary and to emit_attribution with \"when\" and \"fields\" (the condition and Group B field rule). For a shared forwarder or an out-of-profile site, add it to emit_forwarders or emit_exclusions with a reason. %s", key, site.position, regenerateReceiptV3))
		}
		if entry, ok := registry.Attribution[key]; bound && ok {
			if strings.TrimSpace(entry.Fields) == "" || strings.TrimSpace(entry.When) == "" {
				issues = append(issues, fmt.Sprintf("producer attribution for %s (%s) requires both \"when\" and \"fields\"", key, site.position))
			}
		}
	}
	for _, bindings := range []map[string]string{registry.Exclusions, registry.Forwarders} {
		for key, reason := range bindings {
			if !discovered[key] || strings.TrimSpace(reason) == "" {
				issues = append(issues, fmt.Sprintf("unknown or undocumented emission site %s", key))
			}
		}
	}
	for key := range registry.Attribution {
		if _, ok := registry.EmitSites[key]; !ok {
			issues = append(issues, fmt.Sprintf("producer attribution has no effect binding %s", key))
		}
	}
	for key, boundary := range registry.EmitSites {
		if _, ok := registry.Attribution[key]; !ok {
			issues = append(issues, fmt.Sprintf("effect binding has no producer attribution %s", key))
		}
		if !discovered[key] {
			issues = append(issues, fmt.Sprintf("unknown emission site %s. Remove or update its emit_sites and emit_attribution entries in sdk/receipt-v3/registry.json. %s", key, regenerateReceiptV3))
		}
		if !slices.Contains(registry.Enums["boundary"], boundary) {
			issues = append(issues, fmt.Sprintf("invalid effect boundary for %s: %s", key, boundary))
		}
	}
	slices.Sort(issues)
	return issues
}

func receiptEmissionSites(fset *token.FileSet, path string, file *ast.File) ([]receiptEmissionSite, error) {
	var sites []receiptEmissionSite
	counts := make(map[string]int)
	for _, decl := range file.Decls {
		owner := "package"
		if fn, ok := decl.(*ast.FuncDecl); ok {
			owner = fn.Name.Name
			if fn.Recv != nil {
				var receiver bytes.Buffer
				if err := printer.Fprint(&receiver, token.NewFileSet(), fn.Recv.List[0].Type); err != nil {
					return nil, fmt.Errorf("format receiver for %s/%s: %w", path, owner, err)
				}
				owner = "(" + receiver.String() + ")." + owner
			}
		}
		var fingerprintErr error
		ast.PreorderStack(decl, nil, func(node ast.Node, parents []ast.Node) bool {
			if fingerprintErr != nil {
				return false
			}
			callee := receiptEmissionName(node, file)
			if callee == "" {
				return true
			}
			position := fset.PositionFor(node.Pos(), false)
			position.Filename = path
			fingerprint, err := receiptEmissionFingerprint(node, parents)
			if err != nil {
				fingerprintErr = fmt.Errorf("fingerprint emission site %s at %s: %w", callee, position, err)
				return false
			}
			key := path + "/" + owner + "/" + callee + "/" + fingerprint
			counts[key]++
			if count := counts[key]; count > 1 {
				key = fmt.Sprintf("%s-%d", key, count)
			}
			sites = append(sites, receiptEmissionSite{key: key, position: position})
			return true
		})
		if fingerprintErr != nil {
			return nil, fingerprintErr
		}
	}
	return sites, nil
}

func receiptEmissionName(node ast.Node, file *ast.File) string {
	switch node := node.(type) {
	case *ast.CallExpr:
		callee := calledName(node)
		if slices.Contains(receiptEmissionCalls, callee) || directReceiptEmission(node, callee) {
			return callee
		}
	case *ast.CompositeLit:
		return receiptConstruction(node, file)
	}
	return ""
}

// Hash the emitting expression and the headers of its enclosing control flow.
// An empty file set prints syntax independently of source layout and comments.
func receiptEmissionFingerprint(node ast.Node, parents []ast.Node) (string, error) {
	var syntax bytes.Buffer
	var printErr error
	noPositions := token.NewFileSet()
	write := func(label string, parts ...ast.Node) {
		syntax.WriteString(label)
		for _, part := range parts {
			syntax.WriteByte(0)
			if part != nil && printErr == nil {
				printErr = printer.Fprint(&syntax, noPositions, part)
			}
		}
		syntax.WriteByte(0)
	}
	for i, parent := range parents {
		switch parent := parent.(type) {
		case *ast.IfStmt:
			write("if", parent.Init, parent.Cond)
			if i+1 < len(parents) && parents[i+1] == parent.Else {
				write("else")
			}
		case *ast.SwitchStmt:
			write("switch", parent.Init, parent.Tag)
		case *ast.TypeSwitchStmt:
			write("type-switch", parent.Init, parent.Assign)
		case *ast.CaseClause:
			write("case")
			for _, expr := range parent.List {
				write("case-expression", expr)
			}
		case *ast.CommClause:
			write("select-case", parent.Comm)
		case *ast.ForStmt:
			write("for", parent.Init, parent.Cond, parent.Post)
		case *ast.RangeStmt:
			write("range "+parent.Tok.String(), parent.Key, parent.Value, parent.X)
		case *ast.DeferStmt:
			write("defer")
		case *ast.GoStmt:
			write("go")
		}
	}
	write("emission", node)
	if printErr != nil {
		return "", printErr
	}
	sum := sha256.Sum256(syntax.Bytes())
	return fmt.Sprintf("%x", sum[:8]), nil
}

func TestReceiptV3EmitterBindingChanges(t *testing.T) {
	const (
		path         = "proxy/forward.go"
		upstreamSend = "upstream_send"
		emit         = `emitReceipt(ReceiptOptions{Verdict: "allow"})`
	)
	discover := func(t *testing.T, source string) []receiptEmissionSite {
		t.Helper()
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, source, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		sites, err := receiptEmissionSites(fset, path, file)
		if err != nil {
			t.Fatal(err)
		}
		return sites
	}
	base := "package proxy\nfunc (*Proxy) forward() {\nif admitted {\n" + emit + "\n}\n}\n"
	original := discover(t, base)
	if len(original) != 1 {
		t.Fatalf("got %d original sites, want 1", len(original))
	}
	key := original[0].key
	registry := receiptBindingRegistry{
		Attribution: map[string]receiptProducerAttribution{
			key: {Fields: "Use the request policy snapshot.", When: "The request is admitted."},
		},
		EmitSites: map[string]string{key: upstreamSend},
		Enums:     map[string][]string{"boundary": {upstreamSend}},
	}
	for _, tc := range []struct {
		name        string
		source      string
		newSite     bool
		staleSite   bool
		newSiteLine int
	}{
		{
			name: "unrelated insertion",
			source: strings.NewReplacer(
				"func", "var unrelated = true\n\nfunc",
				emit, "recordMetric()\nemitReceipt(ReceiptOptions{\nVerdict: \"allow\", // retained verdict\n})",
			).Replace(base),
		},
		{
			name:    "parenthesized emitter",
			source:  strings.Replace(base, emit, "(emitReceipt)(ReceiptOptions{Verdict: \"warn\"})", 1),
			newSite: true, staleSite: true, newSiteLine: 4,
		},
		{
			name:    "unbound call before bound call",
			source:  strings.Replace(base, emit, `emitReceipt(ReceiptOptions{Verdict: "warn"})`+"\n"+emit, 1),
			newSite: true, newSiteLine: 4,
		},
		{
			name:    "identical unbound call",
			source:  strings.Replace(base, emit, emit+"\n"+emit, 1),
			newSite: true, newSiteLine: 5,
		},
		{
			name:      "removed call",
			source:    strings.Replace(base, emit, "", 1),
			staleSite: true,
		},
		{
			name:    "changed branch condition",
			source:  strings.Replace(base, "if admitted", "if !admitted", 1),
			newSite: true, staleSite: true, newSiteLine: 4,
		},
		{
			name:    "changed field value",
			source:  strings.Replace(base, "allow", "block", 1),
			newSite: true, staleSite: true, newSiteLine: 4,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sites := discover(t, tc.source)
			issues := receiptBindingIssues(registry, sites)
			if tc.newSite {
				var newKey string
				for _, site := range sites {
					if site.key != key {
						newKey = site.key
						break
					}
				}
				if newKey == "" || !strings.HasPrefix(newKey, path+"/(*Proxy).forward/emitReceipt/") {
					t.Fatalf("expected a new emission key, got %q", newKey)
				}
				message := fmt.Sprintf("unbound emission site %s (%s:%d:1).", newKey, path, tc.newSiteLine)
				var diagnostic string
				for _, issue := range issues {
					if strings.HasPrefix(issue, message) {
						diagnostic = issue
						break
					}
				}
				for _, instruction := range []string{
					message, "sdk/receipt-v3/registry.json", "emit_sites with its effect boundary",
					`emit_attribution with "when" and "fields"`, regenerateReceiptV3,
				} {
					if !strings.Contains(diagnostic, instruction) {
						t.Fatalf("missing %q in diagnostic: %v", instruction, issues)
					}
				}
				t.Log(diagnostic)
			}
			if tc.staleSite && !slices.ContainsFunc(issues, func(issue string) bool {
				return strings.HasPrefix(issue, "unknown emission site "+key+".")
			}) {
				t.Fatalf("missing stale binding diagnostic for %s: %v", key, issues)
			}
			want := 0
			if tc.newSite {
				want++
			}
			if tc.staleSite {
				want++
			}
			if len(issues) != want {
				t.Fatalf("got %d binding issues, want %d: %v", len(issues), want, issues)
			}
			if want == 0 {
				t.Logf("binding %s still matches after moving from line %d to line %d", key, original[0].position.Line, sites[0].position.Line)
			}
		})
	}
}

func calledName(call *ast.CallExpr) string {
	switch target := ast.Unparen(call.Fun).(type) {
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
