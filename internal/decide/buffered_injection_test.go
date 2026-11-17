// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"fmt"
	"reflect"
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

func TestBufferedCheckerMCPIndependentInputToggle(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, mode := range []string{config.InjectionModeBlock, config.InjectionModeWarn} {
			t.Run(fmt.Sprintf("enabled=%t/%s", enabled, mode), func(t *testing.T) {
				srv := checkertest.New(t, "finding")
				cfg := config.Defaults()
				cfg.Internal = nil
				cfg.DLP.ScanEnv = false
				cfg.MCPInputScanning.Enabled = enabled
				cfg.MCPInputScanning.Action = config.ActionBlock
				srv.Configure(cfg, config.InjectionSurfaceHookToolInput, mode)
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				got := Decide(t.Context(), cfg, sc, nil, Action{Kind: EventMCPExecution, MCP: &MCPPayload{ToolName: "notes", ToolInput: `{"text":"ordinary notes"}`}})
				if len(srv.Items()) != 1 || (got.Outcome == Deny) != (mode == config.InjectionModeBlock) {
					t.Fatalf("calls=%d decision=%+v", len(srv.Items()), got)
				}
			})
		}
	}
}

func TestBufferedCheckerMCPLegacyParity(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, action := range []string{config.ActionWarn, config.ActionBlock} {
			cfg := config.Defaults()
			cfg.DLP.ScanEnv = false
			cfg.MCPInputScanning.Enabled = enabled
			cfg.MCPInputScanning.Action = action
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			input := `{"text":"` + checkertest.Directive + `"}`
			extracted := ExtractAllStringsFromJSONResult([]byte(input)).Strings
			text := strings.Join(extracted, " ")
			got := decideMCP(cfg, sc, nil, &MCPPayload{ToolName: "notes", ToolInput: input})
			var evidence []Evidence
			if enabled {
				evidence = append(evidence, evidenceFromJSONDLP(sc, text, input, extracted)...)
				evidence = append(evidence, evidenceFromInjection(sc.ScanResponse(t.Context(), text), action)...)
			}
			want := buildDecision(cfg, evidence)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("enabled=%t action=%s got=%+v main=%+v", enabled, action, got, want)
			}
		}
	}
}

func TestBufferedCheckerMCPSelectedAction(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.DLP.ScanEnv = false
		cfg.MCPInputScanning.Enabled = enabled
		cfg.MCPInputScanning.Action = config.ActionWarn
		cfg.PromptInjectionDetection = &config.PromptInjectionDetection{Surfaces: map[string]config.InjectionSurfaceConfig{config.InjectionSurfaceHookToolInput: {Checker: config.InjectionCheckerBasic, Mode: config.InjectionModeBlock}}}
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		got := decideMCP(cfg, sc, nil, &MCPPayload{ToolName: "notes", ToolInput: `{"text":"` + checkertest.Directive + `"}`})
		if got.Outcome != Deny {
			t.Fatalf("enabled=%t selected block lowered to MCP warn: %+v", enabled, got)
		}
	}
}
