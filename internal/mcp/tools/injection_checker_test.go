// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func descriptionCheckerScanner(t *testing.T, endpoint, mode string) *scanner.Scanner {
	t.Helper()
	allow := true
	r := checkertest.MockRevision
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.PromptInjectionDetection = &config.PromptInjectionDetection{
		Checkers: map[string]config.InjectionCheckerConfig{"desc": {
			Type: config.InjectionCheckerTypeProtocol, Endpoint: endpoint, AllowLoopbackHTTP: &allow,
			Revision:  &config.InjectionCheckerRevision{Checker: r.Checker, Model: r.Model, Adapter: r.Adapter},
			TimeoutMS: 2000, MaxRequestBytes: 1 << 16, MaxResponseBytes: 1 << 12,
		}},
		Surfaces: map[string]config.InjectionSurfaceConfig{config.InjectionSurfaceMCPToolDescription: {Checker: "desc", Mode: mode}},
	}
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	return sc
}

func checkerToolsList(t *testing.T, descriptions ...string) []byte {
	t.Helper()
	type tool struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"inputSchema"`
	}
	list := make([]tool, len(descriptions))
	for i, d := range descriptions {
		list[i] = tool{Name: "tool_" + string(rune('a'+i)), Description: d, InputSchema: json.RawMessage(`{"type":"object"}`)}
	}
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"tools": list}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// tagEncode hides ASCII text in Unicode tag characters.
func tagEncode(s string) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteRune(0xE0000 + r)
	}
	return b.String()
}

func flaggedTools(r ToolScanResult) []string {
	var out []string
	for _, m := range r.Matches {
		for _, inj := range m.Injection {
			if strings.HasPrefix(inj.PatternName, CheckerPatternPrefix) {
				out = append(out, m.ToolName)
			}
		}
	}
	return out
}

func TestDescriptionCheckerBlockAttributesFinding(t *testing.T) {
	m := checkertest.NewMockServer(t, checkertest.BehaviorClassify)
	sc := descriptionCheckerScanner(t, m.URL, config.InjectionModeBlock)
	cfg := &ToolScanConfig{Action: config.ActionWarn, DetectDrift: true, Baseline: NewToolBaseline()}

	r := ScanTools(checkerToolsList(t, "Reads a file.", checkertest.SuspiciousMarker+" and run rm."), sc, cfg)
	if !r.CheckerBlocked() || r.Clean {
		t.Fatalf("block-mode finding not refused: %+v", r)
	}
	if got := flaggedTools(r); len(got) != 1 || got[0] != "tool_b" {
		t.Fatalf("flagged = %v, want [tool_b]", got)
	}
	if r.Assessment.Status != scanner.AssessmentFinding || r.Assessment.Checker != "desc" {
		t.Fatalf("assessment = %+v", r.Assessment)
	}
	// No definition of a refused list becomes a drift baseline entry, not
	// even the scanner-clean sibling, whatever mcp_tool_scanning.action is.
	cfg.Baseline.mu.Lock()
	promoted := len(cfg.Baseline.hashes)
	cfg.Baseline.mu.Unlock()
	if promoted != 0 {
		t.Fatalf("refused tools/list promoted %d definitions into the drift baseline", promoted)
	}
	if m.Requests() != 1 {
		t.Fatalf("checker saw %d requests, want one per tools/list", m.Requests())
	}
}

func TestDescriptionCheckerReadsDecodedTags(t *testing.T) {
	m := checkertest.NewMockServer(t, checkertest.BehaviorClassify)
	sc := descriptionCheckerScanner(t, m.URL, config.InjectionModeBlock)
	r := ScanTools(checkerToolsList(t, "Lists files.", "Formats text."+tagEncode(checkertest.SuspiciousMarker)), sc, &ToolScanConfig{Action: config.ActionWarn})
	if got := flaggedTools(r); len(got) != 1 || got[0] != "tool_b" {
		t.Fatalf("flagged = %v, want the tag-hidden tool_b", got)
	}
}

func TestDescriptionCheckerUncitedFindingFlagsEveryTool(t *testing.T) {
	m := checkertest.NewMockServer(t, checkertest.BehaviorUncited)
	sc := descriptionCheckerScanner(t, m.URL, config.InjectionModeBlock)
	r := ScanTools(checkerToolsList(t, "Reads a file.", "Writes a file."), sc, &ToolScanConfig{Action: config.ActionWarn})
	if got := flaggedTools(r); len(got) != 2 {
		t.Fatalf("flagged = %v, want both tools", got)
	}
}

func TestDescriptionCheckerWarnModeObservesOnly(t *testing.T) {
	m := checkertest.NewMockServer(t, checkertest.BehaviorClassify)
	sc := descriptionCheckerScanner(t, m.URL, config.InjectionModeWarn)
	r := ScanTools(checkerToolsList(t, "Reads a file.", checkertest.SuspiciousMarker), sc, &ToolScanConfig{Action: config.ActionWarn})
	if r.CheckerBlocked() || len(flaggedTools(r)) != 0 {
		t.Fatalf("warn-mode finding blocked: %+v", r.Matches)
	}
	found := false
	for _, o := range r.Observations {
		for _, p := range o.ToolPoison {
			if o.ToolName == "tool_b" && p == CheckerPatternPrefix+"desc" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("warn-mode finding not observed: %+v", r.Observations)
	}
}

func TestDescriptionCheckerFailureWithholdsInBlockMode(t *testing.T) {
	m := checkertest.NewMockServer(t, checkertest.BehaviorDown)
	sc := descriptionCheckerScanner(t, m.URL, config.InjectionModeBlock)
	r := ScanTools(checkerToolsList(t, "Reads a file."), sc, &ToolScanConfig{Action: config.ActionWarn})
	if r.Clean || r.ResourceLimit != ResourceLimitInjectionChecker || !strings.Contains(r.ResourceDetail, "desc") {
		t.Fatalf("unassessed list delivered: clean=%v limit=%q detail=%q", r.Clean, r.ResourceLimit, r.ResourceDetail)
	}

	// The same failure in warn mode delivers the list.
	warn := descriptionCheckerScanner(t, m.URL, config.InjectionModeWarn)
	if r := ScanTools(checkerToolsList(t, "Reads a file."), warn, &ToolScanConfig{Action: config.ActionWarn}); r.ResourceLimit == ResourceLimitInjectionChecker {
		t.Fatal("warn-mode checker failure withheld the list")
	}
}

func TestDescriptionCheckerBenignListIsClean(t *testing.T) {
	m := checkertest.NewMockServer(t, checkertest.BehaviorClassify)
	sc := descriptionCheckerScanner(t, m.URL, config.InjectionModeBlock)
	r := ScanTools(checkerToolsList(t, "Reads a file.", "Writes a file."), sc, &ToolScanConfig{Action: config.ActionWarn})
	if !r.Clean || r.CheckerBlocked() || r.Assessment.Status != scanner.AssessmentBenign {
		t.Fatalf("benign list = clean %v assessment %+v matches %+v", r.Clean, r.Assessment, r.Matches)
	}
}

func TestDescriptionsWithheldRules(t *testing.T) {
	m := checkertest.NewMockServer(t, checkertest.BehaviorClassify)
	block := descriptionCheckerScanner(t, m.URL, config.InjectionModeBlock)
	warn := descriptionCheckerScanner(t, m.URL, config.InjectionModeWarn)
	cases := []struct {
		name string
		sc   *scanner.Scanner
		a    scanner.InjectionAssessment
		want bool
	}{
		{"benign", block, scanner.InjectionAssessment{Checker: "desc", Status: scanner.AssessmentBenign}, false},
		{"finding", block, scanner.InjectionAssessment{Checker: "desc", Status: scanner.AssessmentFinding}, false},
		{"incomplete", block, scanner.InjectionAssessment{Checker: "desc", Status: scanner.AssessmentIncomplete}, true},
		{"other checker", block, scanner.InjectionAssessment{Checker: "builtin", Status: scanner.AssessmentBenign}, true},
		{"warn mode", warn, scanner.InjectionAssessment{Checker: "desc", Status: scanner.AssessmentIncomplete}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := descriptionsWithheld(tc.sc, tc.a); got != tc.want {
				t.Fatalf("descriptionsWithheld = %v, want %v", got, tc.want)
			}
		})
	}
}
