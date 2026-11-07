// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblyCoreRegistry(t *testing.T) {
	for _, defaults := range []bool{false, true} {
		t.Run(map[bool]string{false: "core only", true: "defaults"}[defaults], func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			cfg.DLP.IncludeDefaults = &defaults
			if !defaults {
				cfg.DLP.Patterns = nil
			}
			sc := MustNew(cfg)
			t.Cleanup(sc.Close)
			value := "AKIA" + strings.Repeat("Q", 16)
			body := reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("x", 5000) + value)))
			result := sc.ScanTextForDLP(t.Context(), body)
			count := 0
			for _, match := range result.Matches {
				if match.PatternName != "AWS Access ID" {
					continue
				}
				count++
				if !IsCoreCriticalMatch(match) || match.Warn || !match.hasValueIdentity || match.valueIdentity != sha256.Sum256([]byte(value)) {
					t.Fatalf("core classification or credential identity lost: %+v", match)
				}
			}
			t.Logf("include_defaults=%v clean=%v core_findings=%d informational=%d", defaults, result.Clean, count, len(result.InformationalMatches))
			if result.Clean || count != 1 || len(result.InformationalMatches) != 0 {
				t.Fatalf("want one enforcing core finding: %+v", result)
			}
			for _, core := range sc.core.dlpPatterns {
				count := 0
				for _, pattern := range sc.reassemblyPlan.patterns {
					if pattern == core {
						count++
					}
				}
				if count != 1 {
					t.Errorf("core pattern %q compiled instance occurs %d times", core.name, count)
				}
			}
		})
	}
}
