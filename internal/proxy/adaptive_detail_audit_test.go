// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// An adaptive refusal is one request decision. Its explanation must not reach
// external audit sinks as an extra block event detached from the request.
func TestAdaptiveRefusalExplanationKeepsBlockEventsRequestScoped(t *testing.T) {
	for _, mode := range []string{"block_all", "upgrade_warn"} {
		t.Run(mode, func(t *testing.T) { testAdaptiveRefusalAudit(t, mode) })
	}
}

func testAdaptiveRefusalAudit(t *testing.T, mode string) {
	t.Helper()
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.MaxSessions = 1000
	cfg.SessionProfiling.DomainBurst = 100
	cfg.SessionProfiling.WindowMinutes = 5
	cfg.SessionProfiling.SessionTTLMinutes = 30
	cfg.SessionProfiling.CleanupIntervalSeconds = 300
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = 3.0
	blockAll := true
	cfg.AdaptiveEnforcement.Levels.Critical.BlockAll = &blockAll
	level := 3
	if mode == "upgrade_warn" {
		level = 1
		enforce := false
		cfg.Enforce = &enforce
		cfg.FetchProxy.Monitoring.Blocklist = []string{"127.0.0.1"}
		block := config.ActionBlock
		cfg.AdaptiveEnforcement.Levels.Elevated.UpgradeWarn = &block
	}

	logger, sink := newCorrelationAuditLogger(t)
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()
	sm := p.sessionMgrPtr.Load()
	const clientIP = "10.50.50.51"
	_ = escalateSession(sm, clientIP, "", cfg.AdaptiveEnforcement.EscalationThreshold, level)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+backend.URL+"/clean", nil)
	req.RemoteAddr = clientIP + ":12345"
	w := httptest.NewRecorder()
	p.handleFetch(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	var body FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.BlockReason == "" {
		t.Fatal("adaptive refusal carried no explanation")
	}
	if !strings.Contains(body.BlockReason, "recovery:") {
		t.Fatalf("adaptive refusal omitted recovery guidance: %s", body.BlockReason)
	}
	// Fetch carries guidance in its JSON body; fixed-body transports use the header.
	if detail := w.Header().Get(headerAdaptiveDetail); detail != "" {
		t.Fatalf("fetch unexpectedly emitted adaptive detail header: %q", detail)
	}
	for _, forbidden := range []string{"score=", "threshold=", "level=", "auto_recover_at=", "decay=", "minutes=", "seconds="} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("caller response exposes %s: %s", forbidden, w.Body.String())
		}
	}

	// The emitter delivers in order; a later sentinel proves earlier events arrived.
	logger.LogAdaptiveEscalation("sentinel", "none", "elevated", "", "", 0)
	_ = waitForEvent(t, sink, emit.EventAdaptiveEscalation)
	blockedEvents := 0
	for _, ev := range sink.eventsSnapshot() {
		if ev.Type != emit.EventBlocked {
			continue
		}
		blockedEvents++
		if ev.Fields["request_id"] == nil || ev.Fields["client_ip"] == nil {
			t.Fatalf("block event lacks request correlation: %v", ev.Fields)
		}
		reason, _ := ev.Fields["reason"].(string)
		if !strings.Contains(reason, "escalation_threshold=3") || !strings.Contains(reason, "score=") {
			t.Fatalf("block event lost adaptive detail: %v", ev.Fields)
		}
	}
	if blockedEvents != 1 {
		t.Fatalf("blocked events = %d, want one per refusal", blockedEvents)
	}
}

// Entering quarantine is a state transition, not a request refusal.
func TestAdaptiveAirlockEntryDoesNotEmitBlockEvent(t *testing.T) {
	logger, sink := newCorrelationAuditLogger(t)
	cfg := config.Defaults()
	cfg.Airlock.Enabled = true
	cfg.Airlock.Triggers.OnElevated = config.AirlockTierSoft
	sm := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, nil)
	t.Cleanup(sm.Close)
	sess := sm.GetOrCreate("airlock-entry")
	sess.RecordScopedSignal("dest.example", session.SignalBlock, 1)
	triggerScopedAirlockOnEscalation(sess, "dest.example", "elevated", &cfg.Airlock, decide.EscalationParams{
		Threshold: 1, Logger: logger, Session: "airlock-entry", ClientIP: "10.0.0.9", RequestID: "req-airlock-entry",
	})
	_ = waitForEvent(t, sink, emit.EventAirlockEnter)
	logger.LogAdaptiveEscalation("sentinel", "none", "elevated", "", "", 0)
	_ = waitForEvent(t, sink, emit.EventAdaptiveEscalation)
	if ev, ok := findEvent(sink.eventsSnapshot(), emit.EventBlocked); ok {
		t.Fatalf("airlock entry emitted a block event without a blocked request: %v", ev.Fields)
	}
}
