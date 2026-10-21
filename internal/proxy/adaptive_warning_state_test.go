// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestWarningObservationPreservesEnforcementAndInterruptsRecovery(t *testing.T) {
	for _, scope := range []string{"", "https://api.vendor.example"} {
		t.Run(scope, func(t *testing.T) {
			s := &SessionState{}
			if edge, _, _ := s.RecordScopedSignal(scope, session.SignalWarning, 1); edge || s.ThreatScore() != 0 || s.EscalationLevel() != 0 {
				t.Fatal("initial warning escalated")
			}
			s.RecordScopedSignal(scope, session.SignalBlock, 1)
			s.RecordScopedCleanWithRecovery(scope, 0, 2, func(int) bool { return true })
			before := s.ThreatScore()
			lastEscalation := s.lastEscalation
			if edge, _, _ := s.RecordScopedSignal(scope, session.SignalWarning, 1); edge || s.ThreatScore() != before {
				t.Fatal("warning changed enforcement score or level")
			}
			if !s.lastEscalation.Equal(lastEscalation) {
				t.Fatal("warning postponed time recovery")
			}
			if changed, _, _ := s.RecordScopedCleanWithRecovery(scope, 0, 2, func(int) bool { return true }); changed {
				t.Fatal("warning counted as a clean request")
			}
			if changed, _, _ := s.RecordScopedCleanWithRecovery(scope, 0, 2, func(int) bool { return false }); !changed {
				t.Fatal("two genuinely clean requests did not recover")
			}
		})
	}
}

func TestWarningsDoNotExhaustAdaptiveScopes(t *testing.T) {
	s := &SessionState{}
	for i := range maxAdaptiveScopes + 1 {
		s.RecordScopedSignal(fmt.Sprintf("host-%d.example", i), session.SignalWarning, 1)
	}
	if len(s.scopes) != 0 || s.globalSignalsAuthoritative {
		t.Fatal("warnings allocated enforcement scope state")
	}
	scope := adaptiveScopeForHost("api.vendor.example")
	s.RecordScopedSignal(scope, session.SignalBlock, 1)
	if s.ScopedEscalationLevel(scope) != 1 || s.EffectiveEscalationLevel("other.example") != 0 {
		t.Fatal("concrete evidence did not remain destination-scoped")
	}
}

type adaptiveDetailTestRecorder struct{ *SessionState }

func TestAdaptiveDiagnosticsHTTPWebSocketAndLog(t *testing.T) {
	cfg := config.Defaults()
	cfg.ApplyDefaults()
	cfg.AdaptiveEnforcement.EscalationThreshold = 0.25
	var logs bytes.Buffer
	logger, err := audit.NewWithStream("json", "stdout", "", false, true, &logs)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	s := &SessionState{}
	s.RecordSignal(session.SignalBlock, 0.25)
	wrapped := adaptiveDetailTestRecorder{s}
	rr := httptest.NewRecorder()
	setAdaptiveBlockDetail(rr, adaptiveAudit{logger, "10.0.0.7", "req-adaptive-detail"}, wrapped, cfg, "", "dlp")
	for _, want := range []string{`category="dlp"`, "score=3", "escalation_threshold=0.25", "wait 300s"} {
		if !strings.Contains(rr.Header().Get(headerAdaptiveDetail), want) {
			t.Errorf("HTTP detail missing %s", want)
		}
	}
	if !strings.Contains(logs.String(), "escalation_threshold=0.25") {
		t.Fatal("audit log omitted recovery diagnostics")
	}
	if !strings.Contains(logs.String(), `"request_id":"req-adaptive-detail"`) || !strings.Contains(logs.String(), `"client_ip":"10.0.0.7"`) {
		t.Fatalf("audit diagnostics lost request correlation: %s", logs.String())
	}
	info := blockInfoFor(blockreason.EscalationLevel, adaptiveSessionDeny)
	for _, duration := range []int{300, 0} {
		cfg.AdaptiveEnforcement.LevelDurationSeconds = duration
		payload := adaptiveWSClosePayload(adaptiveAudit{log: logger}, s, cfg, "", info)
		for _, want := range []string{`"score":3`, `"threshold":0.25`, `"wait_s":300`} {
			if !strings.Contains(payload, want) {
				t.Errorf("WS payload %s missing %s", payload, want)
			}
		}
	}
	var typedNil *SessionState
	if score, level := adaptiveBlockState(typedNil, ""); score != 0 || level != 0 {
		t.Fatal("nil recorder produced state")
	}
}

func TestConcurrentWarningsCannotCreateSessionOrScopedEnforcement(t *testing.T) {
	s := &SessionState{}
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			for range 100 {
				if i%2 == 0 {
					s.RecordSignal(session.SignalWarning, 1)
				} else {
					s.RecordScopedSignal("api.vendor.example", session.SignalWarning, 1)
				}
			}
		})
	}
	wg.Wait()
	if s.ThreatScore() != 0 || s.EscalationLevel() != 0 || s.EffectiveEscalationLevel("api.vendor.example") != 0 || s.globalSignalsAuthoritative {
		t.Fatal("concurrent observations created enforcement state")
	}
}

func TestAdaptiveDetailUsesEnforcingScope(t *testing.T) {
	cfg := config.Defaults()
	s := &SessionState{}
	s.RecordScopedSignal("api.vendor.example", session.SignalBlock, 1)
	s.RecordScopedSignal("other.example", session.SignalBlock, 1)
	if got := adaptiveBlockDetail(adaptiveAudit{}, s, cfg, "api.vendor.example", "dlp"); !strings.Contains(got, "score=3") || !strings.Contains(got, "level=elevated") {
		t.Fatalf("reported another destination's score: %s", got)
	}
	s.RecordSignal(session.SignalBlock, 1)
	if got := adaptiveBlockDetail(adaptiveAudit{}, s, cfg, "api.vendor.example", "session_deny"); !strings.Contains(got, "score=9") {
		t.Fatalf("did not report authoritative global score: %s", got)
	}
	_ = adaptiveBlockDetail(adaptiveAudit{}, nil, cfg, "", "session_deny")
}

func TestAirlockDiagnosticUsesScopedStateAndTimers(t *testing.T) {
	cfg := config.Defaults()
	cfg.ApplyDefaults()
	var logs bytes.Buffer
	logger, err := audit.NewWithStream("json", "stdout", "", false, true, &logs)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	s := &SessionState{}
	s.RecordScopedSignal("api.vendor.example", session.SignalBlock, 1)
	detail := airlockBlockDetail(adaptiveAudit{log: logger}, s, cfg, "api.vendor.example", config.AirlockTierHard)
	for _, want := range []string{`category="airlock"`, "score=3", `tier="hard"`, "hard_minutes="} {
		if !strings.Contains(detail, want) {
			t.Errorf("missing %s: %s", want, detail)
		}
	}
	if !strings.Contains(logs.String(), "hard_minutes=") {
		t.Fatal("audit omitted airlock recovery")
	}
	_ = airlockBlockDetail(adaptiveAudit{}, nil, cfg, "", config.AirlockTierHard)
}
