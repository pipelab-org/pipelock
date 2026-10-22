// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// A core credential refused under a warn-configured action is a floor block,
// not an upgraded warning. Upgraded warnings score zero only because each site
// reads its scoring origin after the floor has raised the action; these cases
// fail if a site reads the configured action instead.
func TestAdaptiveWarnConfiguredFloorBlocksStillScore(t *testing.T) {
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	for _, stage := range []string{"body", "header"} {
		for _, enforce := range []bool{false, true} {
			for _, seeded := range []bool{false, true} {
				t.Run(fmt.Sprintf("intercept/%s/enforce=%t/elevated=%t", stage, enforce, seeded), func(t *testing.T) {
					cfg := adaptiveConfig()
					cfg.Enforce = &enforce
					cfg.RequestBodyScanning.Enabled = true
					cfg.RequestBodyScanning.Action = config.ActionWarn
					cfg.RequestBodyScanning.ScanHeaders = true
					cfg.RequestBodyScanning.HeaderMode = config.HeaderModeSensitive
					cfg.RequestBodyScanning.SensitiveHeaders = []string{"Authorization"}
					cfg.ApplyDefaults()
					cfg.Internal = nil
					sc := scanner.MustNew(cfg)
					defer sc.Close()
					rec := &SessionState{}
					if seeded {
						for range 2 {
							rec.RecordScopedSignal(adaptiveScopeForHost("api.vendor.example"), session.SignalBlock, cfg.AdaptiveEnforcement.EscalationThreshold)
						}
					}
					before := rec.ThreatScore()
					body := "clean body"
					if stage == "body" {
						body = "token=" + secret
					}
					req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.vendor.example/page", strings.NewReader(body))
					req.Header.Set("Content-Type", "text/plain")
					if stage == "header" {
						req.Header.Set("Authorization", secret)
					}
					roundTrips := 0
					rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
						roundTrips++
						return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("clean response")), Request: r}, nil
					})
					w := httptest.NewRecorder()
					newInterceptHandler(&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: metrics.New(), ClientIP: adaptiveSessionKeyLoopback, Agent: agentAnonymous, RequestID: "floor-block", Recorder: rec}, rt).ServeHTTP(w, req)
					if w.Code != http.StatusForbidden || roundTrips != 0 {
						t.Fatalf("core credential not refused: status=%d roundTrips=%d body=%s", w.Code, roundTrips, w.Body.String())
					}
					assertUpgradedWarningScore(t, rec, before, config.ActionBlock)
				})
			}
		}
	}
	t.Run("frames/body", func(t *testing.T) {
		relay, _ := newAdaptiveWSRelay(t, 1)
		enforce := true
		relay.cfg.Enforce = &enforce
		relay.cfg.RequestBodyScanning.Action = config.ActionWarn
		before := relay.rec.ThreatScore()
		match := scanner.TextDLPMatch{PatternName: "AWS Access ID", Severity: config.SeverityCritical}
		if !scanner.IsCoreCriticalMatch(match) {
			t.Fatal("fixture is not a core credential match")
		}
		blocked := relay.handleClientMessageBodyResult(audit.NewNop(), []byte("token="+secret), BodyScanResult{Clean: false, Action: config.ActionWarn, Reason: "body finding", DLPMatches: []scanner.TextDLPMatch{match}})
		if !blocked {
			t.Fatal("core credential frame was delivered")
		}
		assertUpgradedWarningScore(t, relay.rec, before, config.ActionBlock)
	})
}
