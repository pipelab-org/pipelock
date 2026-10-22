// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/discover"
)

func TestAssessmentUnconfirmedDiscovery(t *testing.T) {
	for _, client := range []string{"codex", "grok", "claude-code", "cursor", "vscode", "claude-desktop", "cline", "continue", "junie", "zed"} {
		t.Run(client, func(t *testing.T) {
			raw := &discover.Report{
				Servers: []discover.MCPServer{{Client: client, ServerName: "probe", Protection: discover.Unconfirmed}},
				Summary: discover.Summary{TotalServers: 1, Unconfirmed: 1},
			}
			wrapped := wrapDiscoverReport(raw, "/home/example")
			section := scoreMCPProtection(&wrapped)
			if section.Score != 50 {
				t.Fatalf("score=%d, want Unknown-equivalent 50", section.Score)
			}
			sources := AssessSources{Discover: &wrapped}
			findings := generateFindings(sources)
			if len(findings) != 1 || !strings.Contains(findings[0].Title, "unconfirmed") || !strings.Contains(findings[0].Remediation, "Verify the effective") {
				t.Fatalf("findings=%+v", findings)
			}
			data, err := json.Marshal(wrapped)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `"unconfirmed":1`) || !strings.Contains(string(data), `"protection_state":"unconfirmed"`) {
				t.Fatalf("JSON=%s", data)
			}
		})
	}
}

func TestProjectInventoryFindingsKeepDistinctIDs(t *testing.T) {
	report := &AssessDiscoverReport{Servers: []AssessDiscoverServer{
		{MCPServer: discover.MCPServer{Client: "codex", ServerName: "probe", Protection: discover.Unconfirmed}},
		{MCPServer: discover.MCPServer{Client: "codex", ServerName: "probe", Protection: discover.Unprotected}},
		{MCPServer: discover.MCPServer{Client: "codex", ServerName: "probe", Protection: discover.Unprotected}},
	}}
	findings := generateFindings(AssessSources{Discover: report})
	if len(findings) != 3 {
		t.Fatalf("findings=%+v", findings)
	}
	seen := map[string]bool{}
	for _, finding := range findings {
		if seen[finding.ID] {
			t.Fatalf("duplicate ID=%s", finding.ID)
		}
		seen[finding.ID] = true
	}
}
