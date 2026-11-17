// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestBufferedCheckerReplay(t *testing.T) {
	for _, state := range []string{"benign", "finding", "failure"} {
		t.Run(state, func(t *testing.T) {
			srv := checkertest.New(t, state)
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			cfg.ResponseScanning.Action = config.ActionWarn
			srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeBlock)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			re := NewReplayEngine(cfg, sc)
			text := "ordinary capture content"
			if state == "benign" {
				text = checkertest.Directive
			}
			got := re.ReplayRecord(CaptureSummary{Surface: SurfaceResponse, Subsurface: "response_fetch", EffectiveAction: config.ActionAllow}, text)
			want := config.ActionBlock
			if state == "benign" {
				want = config.ActionAllow
			}
			if got.CandidateAction != want {
				t.Fatalf("got=%+v want=%s", got, want)
			}
		})
	}
}

func TestBufferedCheckerReplayWarn(t *testing.T) {
	for _, state := range []string{"finding", "not_checked"} {
		t.Run(state, func(t *testing.T) {
			srv := checkertest.New(t, state)
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeWarn)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			got := NewReplayEngine(cfg, sc).ReplayRecord(CaptureSummary{Surface: SurfaceResponse, Subsurface: "response_fetch", EffectiveAction: config.ActionAllow}, "ordinary content")
			if got.Assessment == nil || got.Assessment.Status == scanner.AssessmentBenign {
				t.Fatalf("missing assessment: %+v", got)
			}
			want := config.ActionAllow
			if state == "finding" {
				want = config.ActionWarn
			}
			if got.CandidateAction != want {
				t.Fatalf("action=%s want=%s", got.CandidateAction, want)
			}
		})
	}
}

func TestBufferedCheckerReplayMCPSurface(t *testing.T) {
	srv := checkertest.New(t, "finding")
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	srv.Configure(cfg, config.InjectionSurfaceMCPToolResult, config.InjectionModeBlock)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	got := NewReplayEngine(cfg, sc).ReplayRecord(CaptureSummary{Surface: SurfaceResponse, Subsurface: "response_mcp", EffectiveAction: config.ActionAllow}, "ordinary content")
	if got.CandidateAction != config.ActionBlock || srv.Items()[0].Surface != config.InjectionSurfaceMCPToolResult {
		t.Fatalf("wrong selection: %+v", got)
	}
	got = NewReplayEngine(cfg, sc).ReplayRecord(CaptureSummary{Surface: SurfaceResponse, Subsurface: "response_websocket", EffectiveAction: config.ActionAllow}, "ordinary content")
	if got.CandidateAction != config.ActionAllow || len(srv.Items()) != 1 {
		t.Fatal("stream replay used buffered selection")
	}
}

func TestBufferedCheckerReplayCapturedWarning(t *testing.T) {
	for _, external := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.DLP.ScanEnv = false
		text := checkertest.Directive
		if external {
			srv := checkertest.New(t, "finding")
			srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeWarn)
			text = "ordinary upstream content"
		} else {
			cfg.PromptInjectionDetection = &config.PromptInjectionDetection{Action: config.InjectionModeWarn}
		}
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		got := NewReplayEngine(cfg, sc).ReplayRecord(CaptureSummary{Surface: SurfaceResponse, Subsurface: "response_fetch", EffectiveAction: config.ActionWarn}, text)
		if got.CandidateAction != config.ActionWarn || got.Changed || len(got.CandidateFindings) == 0 {
			t.Fatalf("external=%t warning replay differs: %+v", external, got)
		}
	}
}
