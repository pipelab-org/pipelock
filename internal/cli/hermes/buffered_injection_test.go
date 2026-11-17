// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestBufferedCheckerHermes(t *testing.T) {
	for _, inbound := range []bool{false, true} {
		for _, state := range []string{"benign", "finding", "failure", "not_checked"} {
			for _, mode := range []string{config.InjectionModeOff, config.InjectionModeWarn, config.InjectionModeBlock} {
				surface, dir := config.InjectionSurfaceHookToolInput, directionOutbound
				if inbound {
					surface, dir = config.InjectionSurfaceHookToolResult, directionInbound
				}
				t.Run(surface+"/"+state+"/"+mode, func(t *testing.T) {
					srv := checkertest.New(t, state)
					cfg := config.Defaults()
					cfg.Internal = nil
					cfg.DLP.ScanEnv = false
					srv.Configure(cfg, surface, mode)
					sc := scanner.MustNew(cfg)
					t.Cleanup(sc.Close)
					text := "ordinary hook content"
					if state == "benign" {
						text = checkertest.Directive
					}
					got := scanCombined(t.Context(), sc, text, "tool", dir)
					block := mode == config.InjectionModeBlock && state != "benign"
					if (got.Decision == DecisionBlock) != block {
						t.Fatalf("block=%v decision=%+v", block, got)
					}
					if mode != config.InjectionModeOff && len(srv.Items()) != 1 {
						t.Fatalf("calls=%d", len(srv.Items()))
					}
				})
			}
		}
	}
}

func TestBufferedCheckerHermesAudit(t *testing.T) {
	for _, enforce := range []bool{true, false} {
		for _, state := range []string{"builtin", "finding", "failure", "not_checked", "incomplete"} {
			t.Run(fmt.Sprintf("enforce=%t/%s", enforce, state), func(t *testing.T) {
				srv := checkertest.New(t, state)
				cfg := config.Defaults()
				cfg.Enforce = &enforce
				cfg.Internal = nil
				cfg.DLP.ScanEnv = false
				cfg.ResponseScanning.Action = config.ActionBlock
				text := "ordinary hook input"
				if state == "builtin" {
					text = checkertest.Directive
				} else {
					srv.Configure(cfg, config.InjectionSurfaceHookToolInput, config.InjectionModeBlock)
				}
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				got := scanCombined(t.Context(), sc, text, "tool", directionOutbound)
				if got.Decision != DecisionBlock {
					t.Fatalf("decision=%+v", got)
				}
				failure := state != "builtin" && state != "finding"
				if strings.Contains(got.Reason, "scan failed") != failure {
					t.Fatalf("wrong failure/finding classification: %+v", got)
				}
				if state != "builtin" && len(srv.Items()) != 1 {
					t.Fatalf("calls=%d", len(srv.Items()))
				}
			})
		}
	}
}
