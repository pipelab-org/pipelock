// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestBufferedCheckerDecide(t *testing.T) {
	for _, inbound := range []bool{false, true} {
		for _, state := range []string{"benign", "finding", "failure", "not_checked"} {
			for _, mode := range []string{config.InjectionModeOff, config.InjectionModeWarn, config.InjectionModeBlock} {
				surface := config.InjectionSurfaceHookToolInput
				if inbound {
					surface = config.InjectionSurfaceHookToolResult
				}
				t.Run(surface+"/"+state+"/"+mode, func(t *testing.T) {
					srv := checkertest.New(t, state)
					cfg := config.Defaults()
					cfg.Internal = nil
					cfg.DLP.ScanEnv = false
					cfg.ResponseScanning.Action = config.ActionWarn
					srv.Configure(cfg, surface, mode)
					sc := scanner.MustNew(cfg)
					t.Cleanup(sc.Close)
					text := "ordinary hook content"
					if state == "benign" {
						text = checkertest.Directive
					}
					var got Decision
					if inbound {
						got = decideFileContent(cfg, sc, nil, "read_file", "notes.txt", text)
					} else {
						got = decideShell(t.Context(), cfg, sc, nil, &ShellPayload{Command: text})
					}
					block := mode == config.InjectionModeBlock && state != "benign"
					if (got.Outcome == Deny) != block {
						t.Fatalf("block=%v decision=%+v", block, got)
					}
					if state == "benign" && len(got.Evidence) != 0 {
						t.Fatalf("basic wording ran on an external surface: %+v", got)
					}
					if mode != config.InjectionModeOff && len(srv.Items()) != 1 {
						t.Fatalf("calls=%d", len(srv.Items()))
					}
				})
			}
		}
	}
}

func TestBufferedCheckerDecideAuditBlock(t *testing.T) {
	for _, state := range []string{"finding", "failure"} {
		t.Run(state, func(t *testing.T) {
			srv := checkertest.New(t, state)
			cfg := config.Defaults()
			disabled := false
			cfg.Enforce = &disabled
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			srv.Configure(cfg, config.InjectionSurfaceHookToolInput, config.InjectionModeBlock)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			got := decideShell(t.Context(), cfg, sc, nil, &ShellPayload{Command: "ordinary command"})
			if got.Outcome != Deny {
				t.Fatalf("explicit external refusal diluted: %+v", got)
			}
		})
	}
}
