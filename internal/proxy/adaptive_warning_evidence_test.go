// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestSessionFindingEvidenceMatchesEnforcement(t *testing.T) {
	for _, adaptive := range []bool{false, true} {
		for _, observeOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("adaptive=%t/observe_only=%t", adaptive, observeOnly), func(t *testing.T) {
				cfg := config.Defaults()
				cfg.SessionProfiling.Enabled = true
				cfg.AdaptiveEnforcement.Enabled = adaptive
				cfg.ApplyDefaults()
				sm := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, nil)
				t.Cleanup(sm.Close)
				p := &Proxy{metrics: metrics.New()}
				p.sessionMgrPtr.Store(sm)
				const reason = "configured destination finding"
				sr := p.recordSessionActivityWithUserAgent(sessionActivityOptions{
					ClientIP: "192.0.2.1", Hostname: "api.vendor.example", RequestID: "finding-request",
					Result:      scanner.Result{Allowed: false, Scanner: scanner.ScannerBlocklist, Reason: reason},
					ObserveOnly: observeOnly, Config: cfg, Logger: audit.NewNop(),
				})
				sess := sr.recorder
				if sess == nil {
					t.Fatal("request did not create session evidence")
				}
				events := sess.RecentEvents()
				if len(events) != 1 {
					t.Fatalf("events=%+v, want one finding", events)
				}
				wantKind, wantSeverity := config.ActionBlock, config.SeverityCritical
				if observeOnly {
					wantKind, wantSeverity = "anomaly", config.SeverityWarn
				}
				if event := events[0]; event.Kind != wantKind || event.Severity != wantSeverity || event.Detail != reason {
					t.Fatalf("event=%+v, want kind=%s severity=%s detail=%s", event, wantKind, wantSeverity, reason)
				}
				var explanation SessionExplanation
				attachMostRecentEvidence(&explanation, events)
				if explanation.EvidenceKind != wantKind || explanation.EvidenceDetail != reason {
					t.Fatalf("explanation misclassified finding: %+v", explanation)
				}
			})
		}
	}
}
