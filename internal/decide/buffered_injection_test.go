// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"fmt"
	"strings"
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
	for _, enforce := range []bool{true, false} {
		for _, state := range []string{"builtin", "finding", "failure", "not_checked", "incomplete"} {
			for _, event := range []string{"shell", "mcp", "tool", "write", "response"} {
				t.Run(fmt.Sprintf("enforce=%t/%s/%s", enforce, state, event), func(t *testing.T) {
					srv := checkertest.New(t, state)
					cfg := config.Defaults()
					cfg.Enforce = &enforce
					cfg.Internal = nil
					cfg.DLP.ScanEnv = false
					cfg.MCPInputScanning.Enabled = true
					cfg.MCPInputScanning.Action = config.ActionBlock
					cfg.ResponseScanning.Action = config.ActionBlock
					surface := config.InjectionSurfaceHookToolInput
					if event == "response" {
						surface = config.InjectionSurfaceHookToolResult
					}
					text := "ordinary command"
					if state == "builtin" {
						text = checkertest.Directive
					} else {
						srv.Configure(cfg, surface, config.InjectionModeBlock)
					}
					sc := scanner.MustNew(cfg)
					t.Cleanup(sc.Close)
					var got Decision
					switch event {
					case "shell":
						got = decideShell(t.Context(), cfg, sc, nil, &ShellPayload{Command: text})
					case "mcp":
						got = decideMCP(cfg, sc, nil, &MCPPayload{ToolName: "notes", ToolInput: `{"text":"` + text + `"}`})
					case "tool":
						got = decideToolUse(cfg, sc, nil, &ToolUsePayload{ToolName: "notes", ToolInput: `{"text":"` + text + `"}`})
					case "write":
						got = decideFileContent(cfg, sc, nil, "write_file", "notes.txt", text)
					case "response":
						got = decideFileContent(cfg, sc, nil, "read_file", "notes.txt", text)
					}
					failure := state != "finding" && state != "builtin"
					block := failure || enforce || (event == "response" && state == "finding")
					if (got.Outcome == Deny) != block {
						t.Fatalf("block=%t decision=%+v", block, got)
					}
					if !block && (!strings.Contains(got.UserMessage, "enforce off") || len(got.Evidence) == 0) {
						t.Fatalf("missing audit observation: %+v", got)
					}
					if failure && (len(got.Evidence) != 1 || got.Evidence[0].Scanner != scanner.DecideStructuralLabel) {
						t.Fatalf("failure became finding: %+v", got)
					}
				})
			}
		}
	}
}
