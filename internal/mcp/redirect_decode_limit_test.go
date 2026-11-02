// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

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
