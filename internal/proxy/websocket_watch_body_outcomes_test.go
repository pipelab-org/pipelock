// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"fmt"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestWatchWebSocketBodyScoringParity(t *testing.T) {
	for _, kind := range []string{"injection", "dlp"} {
		for _, action := range []string{config.ActionBlock, config.ActionWarn} {
			for _, count := range []int{1, 2} {
				t.Run(fmt.Sprintf("%s/%s/matches=%d", kind, action, count), func(t *testing.T) {
					var auditScore float64
					for _, watch := range []bool{false, true} {
						relay := watchReviewRelay(t, func(cfg *config.Config) {
							cfg.WatchOnly = watch
							enforce := false
							cfg.Enforce = &enforce
							cfg.RequestBodyScanning.Action = action
							if action == config.ActionWarn {
								cfg.RequestBodyScanning.TrustedHosts = []string{"api.vendor.example"}
							}
						})
						matches := make([]scanner.ResponseMatch, count)
						for i := range matches {
							matches[i].PatternName = fmt.Sprintf("injection-%d", i)
						}
						result := BodyScanResult{Action: action, Reason: "body " + kind + " finding", InjectionMatches: matches}
						if kind == "dlp" {
							result.InjectionMatches = nil
							result.DLPMatches = make([]scanner.TextDLPMatch, count)
							for i := range result.DLPMatches {
								result.DLPMatches[i] = scanner.TextDLPMatch{PatternName: fmt.Sprintf("custom-%d", i), Severity: config.SeverityMedium, Warn: action == config.ActionWarn}
							}
						}
						blocked := relay.handleClientMessageBodyResult(relay.proxy.logger, []byte(watchReviewInjection), result)
						if blocked != (!watch && action == config.ActionBlock) {
							t.Fatalf("watch=%t action=%s blocked=%t", watch, action, blocked)
						}
						rec := relay.rec.(*SessionState)
						scope := adaptiveScopeForHost(relay.hostname)
						if !watch {
							auditScore = rec.ScopedThreatScore(scope)
							continue
						}
						if rec.watchAdaptive == nil {
							t.Fatal("body observation did not reach shadow scorer")
						}
						if got := rec.watchAdaptive.ScopedThreatScore(scope); got != auditScore {
							t.Fatalf("shadow score=%v audit score=%v", got, auditScore)
						}
						if rec.ScopedThreatScore(scope) != 0 {
							t.Fatal("watch finding changed enforcement score")
						}
					}
				})
			}
		}
	}
}

func TestWatchWebSocketBodyReceiptRefusal(t *testing.T) {
	for _, watch := range []bool{false, true} {
		t.Run(fmt.Sprint(watch), func(t *testing.T) {
			relay := watchReviewRelay(t, func(cfg *config.Config) { cfg.WatchOnly = watch })
			result := BodyScanResult{Clean: true, CredentialAudienceReceiptErr: errors.New("required receipt unavailable")}
			if !relay.handleClientMessageBodyResult(relay.proxy.logger, []byte(watchReviewInjection), result) {
				t.Fatal("clean body bypassed receipt refusal")
			}
		})
	}
}
