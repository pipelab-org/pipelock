package tools

import (
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func headerDriftList(id int, schema string) []byte {
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"tools":[{"name":"echo","description":"Echo input","inputSchema":%s}]}}`, id, schema))
}

func headerDriftScanner(t *testing.T) *scanner.Scanner {
	t.Helper()
	sc, err := scanner.New(config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	return sc
}

// Header contract enforcement must not change warn-mode drift adoption: a
// changed definition is reported once and then becomes the baseline, as it is
// without contract enforcement.
func TestScanTools_HeaderContractsKeepWarnDriftAdoption(t *testing.T) {
	for _, require := range []bool{false, true} {
		t.Run(fmt.Sprint("require=", require), func(t *testing.T) {
			sc := headerDriftScanner(t)
			cfg := &ToolScanConfig{Action: config.ActionWarn, DetectDrift: true, Baseline: NewToolBaseline(), RequireHeaderContracts: require}
			v1 := `{"type":"object","properties":{"a":{"type":"string"}}}`
			v2 := `{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}}}`
			if r := ScanTools(headerDriftList(1, v1), sc, cfg); !r.Clean {
				t.Fatalf("first list not clean: %+v", r.Matches)
			}
			if r := ScanTools(headerDriftList(2, v2), sc, cfg); r.Clean {
				t.Fatal("structural change was not reported")
			}
			for id := 3; id <= 4; id++ {
				r := ScanTools(headerDriftList(id, v2), sc, cfg)
				if !r.Clean {
					var cues []string
					for _, m := range r.Matches {
						cues = append(cues, strings.Join(m.DriftCues, ","))
					}
					t.Fatalf("list %d re-reported an adopted change: %v", id, cues)
				}
			}
		})
	}
}

// A definition excluded for an invalid header contract never reaches the
// agent, so it must not become the drift baseline either.
func TestScanTools_ExcludedHeaderContractNotAdopted(t *testing.T) {
	sc := headerDriftScanner(t)
	cfg := &ToolScanConfig{Action: config.ActionWarn, DetectDrift: true, Baseline: NewToolBaseline(), RequireHeaderContracts: true}
	invalid := `{"type":"object","properties":{"a":{"type":"array","items":{"type":"string","x-mcp-header":"A"}}}}`
	corrected := `{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"A"}}}`
	_ = ScanTools(headerDriftList(1, invalid), sc, cfg)
	// Had the excluded definition been adopted, the corrected one would be a
	// structural change against it and report drift.
	r := ScanTools(headerDriftList(2, corrected), sc, cfg)
	for _, m := range r.Matches {
		if len(m.DriftCues) > 0 {
			t.Fatalf("corrected definition drifted from an excluded one: %v", m.DriftCues)
		}
	}
}
