// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func TestRedirectOutputCancellationRefusesSyntheticResponse(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("redirect test requires /bin/echo")
	}
	sc := testInputScanner(t)
	policyCfg := policy.New(config.MCPToolPolicy{
		Enabled: true, Action: config.ActionWarn,
		RedirectProfiles: map[string]config.RedirectProfile{
			"local-report": {Exec: []string{"/bin/echo", "ordinary report"}},
		},
		Rules: []config.ToolPolicyRule{{Name: "report", ToolPattern: "^report$", Action: config.ActionRedirect, RedirectProfile: "local-report"}},
	})
	request := makeRequest(1, methodToolsCall, map[string]any{"name": "report", "arguments": map[string]string{"text": "ordinary report"}})
	for _, kind := range []string{"http", "stdio"} {
		t.Run(kind, func(t *testing.T) {
			var checks int32
			outputRefusals := 0
			for checkpoint := int32(0); checkpoint <= checks; checkpoint++ {
				t.Run(fmt.Sprint(checkpoint), func(t *testing.T) {
					base, cancel := context.WithCancel(t.Context())
					defer cancel()
					ctx := &cancelOnErrorCheck{Context: base, cancel: cancel, after: checkpoint}
					opts := MCPProxyOpts{Scanner: sc, PolicyCfg: policyCfg, WarnContext: ctx}
					var log bytes.Buffer
					var denied *BlockedRequest
					var synthetic []byte
					if kind == "http" {
						result := scanHTTPInputDecision([]byte(request), &log, "session", "session", opts)
						denied = result.Blocked
						if result.Synthetic != nil {
							synthetic = result.Synthetic.response
						}
					} else {
						var upstream bytes.Buffer
						responses := make(chan BlockedRequest, 10)
						ForwardScannedInput(transport.NewStdioReader(strings.NewReader(request+"\n")), transport.NewStdioWriter(&upstream), &log, config.ActionWarn, config.ActionWarn, responses, nil, nil, opts)
						for response := range responses {
							if len(response.SyntheticResponse) != 0 {
								synthetic = response.SyntheticResponse
							} else {
								denied = &response
							}
						}
						if upstream.Len() != 0 {
							t.Fatalf("redirect forwarded %d request bytes", upstream.Len())
						}
					}
					if checkpoint == 0 {
						checks = ctx.checks.Load()
						if checks == 0 || denied != nil || !bytes.Contains(synthetic, []byte("ordinary report")) {
							t.Fatalf("complete redirect: checks=%d denied=%+v synthetic=%s log=%s", checks, denied, synthetic, log.String())
						}
						return
					}
					if base.Err() == nil || denied == nil || len(synthetic) != 0 {
						t.Fatalf("unverified output delivered: canceled=%v denied=%+v synthetic=%s log=%s", base.Err(), denied, synthetic, log.String())
					}
					if denied.ErrorMessage == "pipelock: redirect handler output scan failed" {
						outputRefusals++
						data, err := json.Marshal(denied.ErrorData)
						if err != nil || denied.ErrorCode != -32001 || !bytes.Contains(data, []byte(blockreason.ParseError)) {
							t.Fatalf("output refusal lost error classification: %+v data=%s error=%v", denied, data, err)
						}
					}
				})
			}
			if outputRefusals == 0 {
				t.Fatal("no cancellation reached the redirect output scan")
			}
		})
	}
}

func TestDecodeInspectionLimitRedirectResponsesDeliver(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("redirect test requires /bin/echo")
	}
	for _, tc := range []struct {
		name, output string
		blocked      bool
	}{
		{"benign deep entities", deepEntityChain(), false},
		{"core credential", "AK" + "IA" + "Q9W8E7R6T5Y4U3I2", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := testInputScanner(t)
			policyCfg := policy.New(config.MCPToolPolicy{
				Enabled: true,
				Action:  config.ActionWarn,
				RedirectProfiles: map[string]config.RedirectProfile{
					"local-report": {Exec: []string{"/bin/echo", tc.output}},
				},
				Rules: []config.ToolPolicyRule{{Name: "report", ToolPattern: "^report$", Action: config.ActionRedirect, RedirectProfile: "local-report"}},
			})
			request := makeRequest(1, methodToolsCall, map[string]any{"name": "report", "arguments": map[string]string{"text": "ordinary report"}})
			opts := MCPProxyOpts{Scanner: sc, PolicyCfg: policyCfg}
			checkOutput := func(payload []byte) {
				t.Helper()
				var reply struct {
					Result struct {
						Content []struct{ Text string }
					}
				}
				if err := json.Unmarshal(payload, &reply); err != nil {
					t.Fatalf("invalid handler response: %v", err)
				}
				if len(reply.Result.Content) != 1 || reply.Result.Content[0].Text != tc.output+"\n" {
					t.Fatalf("response lost handler output: %+v", reply)
				}
			}
			var httpLog bytes.Buffer
			result := scanHTTPInputDecision([]byte(request), &httpLog, "session", "session", opts)
			if (result.Blocked != nil) != tc.blocked || (result.Synthetic == nil) != tc.blocked {
				t.Errorf("HTTP: want blocked=%v, result=%+v log=%s", tc.blocked, result, httpLog.String())
			} else if !tc.blocked {
				checkOutput(result.Synthetic.response)
			}

			var serverIn, stdioLog bytes.Buffer
			responses := make(chan BlockedRequest, 10)
			ForwardScannedInput(transport.NewStdioReader(strings.NewReader(request+"\n")), transport.NewStdioWriter(&serverIn), &stdioLog, config.ActionBlock, config.ActionBlock, responses, nil, nil, opts)
			count := 0
			for response := range responses {
				count++
				if (len(response.SyntheticResponse) == 0) != tc.blocked {
					t.Errorf("stdio: want blocked=%v, response=%+v log=%s", tc.blocked, response, stdioLog.String())
				} else if !tc.blocked {
					checkOutput(response.SyntheticResponse)
				}
			}
			if count != 1 || serverIn.Len() != 0 {
				t.Fatalf("stdio: responses=%d upstream bytes=%d", count, serverIn.Len())
			}
		})
	}
}
