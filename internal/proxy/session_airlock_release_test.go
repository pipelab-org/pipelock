// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// Quarantine that outlives the airlock consumer used to stay in force for the
// life of the process. Admission reads the stored tier and does not consult
// cfg.Airlock.Enabled, and timer recovery does not run once the airlock
// pointer is nil or disabled. Disabling profiling used to drop the manager.
// Keeping it for taint must not keep the quarantine.
func TestProxy_ReloadReleasesAirlockWithoutConsumer(t *testing.T) {
	const host = "api.vendor.example"
	scope := adaptiveScopeForHost(host)
	other := adaptiveScopeForHost("other.vendor.example")

	t.Run("profiling off keeps taint and drops quarantine", func(t *testing.T) {
		p, sess := quarantinedAirlockProxy(t, scope, other)
		score, scopedScore, level := sess.ThreatScore(), sess.ScopedThreatScore(scope), sess.EscalationLevel()
		sess.SetBlockAll(true)
		observeHTTPResponseTaint(sess, p.CurrentConfig(), taintSessionSource, "text/plain", "http_response", false)

		code, body, trips := forwardAirlockProbe(t, p)
		if code != http.StatusForbidden || trips != 0 || !strings.Contains(body, "airlock") {
			t.Fatalf("precondition: drain did not deny before reload: status=%d trips=%d body=%q", code, trips, body)
		}

		next := p.CurrentConfig().Clone()
		next.SessionProfiling.Enabled = false
		next.AdaptiveEnforcement.Enabled = false
		next.Airlock.Enabled = false
		next.Taint.Enabled = true
		if !p.Reload(next, mustScanner(t, next)) {
			t.Fatal("reload rejected")
		}
		sm := p.sessionMgrPtr.Load()
		if sm == nil || sm.SessionByKey(airlockAdmissionClient) != sess {
			t.Fatal("profiling-off reload replaced the taint store")
		}
		assertAirlockReleased(t, sess, scope, other)
		if sess.ThreatScore() != score || sess.ScopedThreatScore(scope) != scopedScore || sess.EscalationLevel() != level {
			t.Fatalf("adaptive residual changed: score=%g scoped=%g level=%d", sess.ThreatScore(), sess.ScopedThreatScore(scope), sess.EscalationLevel())
		}
		if sess.BlockAll() {
			t.Fatal("block_all survived adaptive disable")
		}
		destination, err := url.Parse("http://" + host + "/publish")
		if err != nil {
			t.Fatal(err)
		}
		if decision := evaluateHTTPTaint(next, sess, http.MethodPost, destination); decision.Result.Reason != "external_publish_after_untrusted_external_exposure" {
			t.Fatalf("retained taint = %+v", decision.Result)
		}
		code, body, trips = forwardAirlockProbe(t, p)
		if code != http.StatusOK || trips != 1 || !strings.Contains(body, "upstream-ok") || strings.Contains(body, "airlock") {
			t.Fatalf("released quarantine still denied: status=%d trips=%d body=%q", code, trips, body)
		}

		sess.mu.Lock()
		sess.lastActivity = time.Now().Add(-2 * time.Hour)
		sess.mu.Unlock()
		sm.cleanup()
		if sm.SessionByKey(airlockAdmissionClient) != nil {
			t.Fatal("released quarantine still held its idle capacity slot")
		}
	})

	t.Run("airlock disabled while profiling stays on", func(t *testing.T) {
		p, sess := quarantinedAirlockProxy(t, scope, other)
		score := sess.ThreatScore()
		code, body, trips := forwardAirlockProbe(t, p)
		if code != http.StatusForbidden || trips != 0 || !strings.Contains(body, "airlock") {
			t.Fatalf("precondition: drain did not deny before reload: status=%d trips=%d body=%q", code, trips, body)
		}
		next := p.CurrentConfig().Clone()
		next.SessionProfiling.Enabled = true
		next.AdaptiveEnforcement.Enabled = true
		next.Airlock.Enabled = false
		next.Taint.Enabled = true
		if !p.Reload(next, mustScanner(t, next)) {
			t.Fatal("reload rejected")
		}
		if p.sessionMgrPtr.Load().SessionByKey(airlockAdmissionClient) != sess {
			t.Fatal("airlock-off reload replaced the session")
		}
		assertAirlockReleased(t, sess, scope, other)
		if sess.ThreatScore() != score {
			t.Fatalf("threat score = %g, want %g", sess.ThreatScore(), score)
		}
		code, body, trips = forwardAirlockProbe(t, p)
		if code != http.StatusOK || trips != 1 || strings.Contains(body, "airlock") {
			t.Fatalf("airlock disable left quarantine in force: status=%d trips=%d body=%q", code, trips, body)
		}
	})

	t.Run("airlock still enabled keeps the tier", func(t *testing.T) {
		p, sess := quarantinedAirlockProxy(t, scope, other)
		next := p.CurrentConfig().Clone()
		next.SessionProfiling.Enabled = true
		next.AdaptiveEnforcement.Enabled = true
		next.Airlock.Enabled = true
		next.Taint.Enabled = true
		next.SessionProfiling.SessionTTLMinutes++
		if !p.Reload(next, mustScanner(t, next)) {
			t.Fatal("reload rejected")
		}
		if got := airlockTierForScope(sess, scope); got != config.AirlockTierDrain {
			t.Fatalf("destination tier = %q, want drain", got)
		}
		if got := airlockTierForScope(sess, other); got != config.AirlockTierHard {
			t.Fatalf("other tier = %q, want hard", got)
		}
		if got := sess.AirlockTier(); got != config.AirlockTierSoft {
			t.Fatalf("global tier = %q, want soft", got)
		}
		code, body, trips := forwardAirlockProbe(t, p)
		if code != http.StatusForbidden || trips != 0 || !strings.Contains(body, "airlock") {
			t.Fatalf("enabled airlock stopped denying: status=%d trips=%d body=%q", code, trips, body)
		}
	})
}

// A disabled airlock struct is the same missing consumer as a nil pointer.
// Reload stores nil; this pins the enabled check on the release itself.
func TestSessionManager_DisabledAirlockStructReleasesTiers(t *testing.T) {
	cfg := testSessionConfig()
	enabled := &config.Airlock{Enabled: true}
	sm := NewSessionManager(cfg, nil, nil, SessionManagerOptions{AirlockCfg: enabled})
	t.Cleanup(sm.Close)
	sess := sm.GetOrCreate("disabled-airlock")
	scope := adaptiveScopeForHost("api.vendor.example")
	if changed, _, _ := sess.AirlockForScope(scope).ForceSetTier(config.AirlockTierHard); !changed {
		t.Fatal("precondition: hard tier was not set")
	}
	sess.RecordScopedSignal(scope, session.SignalBlock, 1000)
	score := sess.ThreatScore()

	disabled := *enabled
	disabled.Enabled = false
	sm.UpdateConfig(cfg, nil, &disabled)
	if got := airlockTierForScope(sess, scope); got != config.AirlockTierHard {
		t.Fatalf("UpdateConfig released the tier before publication: %q", got)
	}
	sm.releaseUnenforcedAirlock()
	if got := airlockTierForScope(sess, scope); got != config.AirlockTierNone {
		t.Fatalf("disabled airlock tier = %q, want none", got)
	}
	if sess.ThreatScore() != score {
		t.Fatalf("threat score = %g, want %g", sess.ThreatScore(), score)
	}

	kept := sm.GetOrCreate("still-enabled")
	if changed, _, _ := kept.AirlockForScope(scope).ForceSetTier(config.AirlockTierDrain); !changed {
		t.Fatal("precondition: drain tier was not set")
	}
	sm.UpdateConfig(cfg, nil, enabled)
	sm.releaseUnenforcedAirlock()
	if got := airlockTierForScope(kept, scope); got != config.AirlockTierDrain {
		t.Fatalf("enabled airlock tier = %q, want drain", got)
	}
}

func quarantinedAirlockProxy(t *testing.T, scope, other string) (*Proxy, *SessionState) {
	t.Helper()
	p := newForwardBoundaryProxy(t, func(cfg *config.Config) {
		disableForwardBoundaryResponseTransforms(cfg)
		cfg.SessionProfiling.Enabled = true
		cfg.AdaptiveEnforcement.Enabled = true
		cfg.Airlock.Enabled = true
		cfg.Taint.Enabled = true
		cfg.SessionProfiling.MaxSessions = 4
		cfg.SessionProfiling.SessionTTLMinutes = 30
	}, forwardBoundaryRoundTripper(func(req *http.Request) (*http.Response, error) {
		t.Fatal("quarantine setup must not reach upstream")
		return nil, nil
	}))
	sm := p.sessionMgrPtr.Load()
	if sm == nil {
		t.Fatal("session manager missing")
	}
	sess := sm.GetOrCreate(airlockAdmissionClient)
	if changed, _, _ := sess.Airlock().ForceSetTier(config.AirlockTierSoft); !changed {
		t.Fatal("global soft tier was not set")
	}
	if changed, _, _ := sess.AirlockForScope(scope).ForceSetTier(config.AirlockTierDrain); !changed {
		t.Fatal("destination drain tier was not set")
	}
	if changed, _, _ := sess.AirlockForScope(other).ForceSetTier(config.AirlockTierHard); !changed {
		t.Fatal("other hard tier was not set")
	}
	sess.RecordScopedSignal(scope, session.SignalBlock, 1000)
	return p, sess
}

func forwardAirlockProbe(t *testing.T, p *Proxy) (int, string, int32) {
	t.Helper()
	rawURL := "http://api.vendor.example/read"
	var trips atomic.Int32
	p.client.Transport = forwardBoundaryRoundTripper(func(req *http.Request) (*http.Response, error) {
		trips.Add(1)
		payload := "upstream-ok"
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        http.StatusText(http.StatusOK),
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(payload)),
			ContentLength: int64(len(payload)),
			Request:       req,
		}, nil
	})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
	req.RemoteAddr = airlockAdmissionClient + ":12345"
	rec := httptest.NewRecorder()
	p.handleForwardHTTP(rec, req)
	return rec.Code, rec.Body.String(), trips.Load()
}

func assertAirlockReleased(t *testing.T, sess *SessionState, scope, other string) {
	t.Helper()
	if got := sess.AirlockTier(); got != config.AirlockTierNone && got != "" {
		t.Fatalf("global tier = %q, want none", got)
	}
	if got := airlockTierForScope(sess, scope); got != config.AirlockTierNone {
		t.Fatalf("destination tier = %q, want none", got)
	}
	if got := airlockTierForScope(sess, other); got != config.AirlockTierNone {
		t.Fatalf("other tier = %q, want none", got)
	}
	var sawDrain, sawHard, sawSoft bool
	for _, evt := range sess.RecentEvents() {
		if evt.Kind != "airlock_deescalate" || evt.Type != "config_disabled" {
			continue
		}
		switch evt.Detail {
		case config.AirlockTierDrain + "->none":
			sawDrain = true
		case config.AirlockTierHard + "->none":
			sawHard = true
		case config.AirlockTierSoft + "->none":
			sawSoft = true
		}
	}
	if !sawDrain || !sawHard || !sawSoft {
		t.Fatalf("release events drain=%t hard=%t soft=%t events=%+v", sawDrain, sawHard, sawSoft, sess.RecentEvents())
	}
}

func mustScanner(t *testing.T, cfg *config.Config) *scanner.Scanner {
	t.Helper()
	return scanner.MustNew(cfg)
}
