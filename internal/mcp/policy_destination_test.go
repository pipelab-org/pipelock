// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func TestForwardScannedInput_WriteDestinationScope(t *testing.T) {
	sc := testInputScanner(t)
	pc := buildPolicyConfig(config.ActionBlock, policy.DefaultToolPolicyRules())
	for _, tc := range []struct {
		name, path, content string
		blocked             bool
	}{
		{"document cron", "/project/notes.md", "/etc/cron.d/job", false},
		{"document traversal", "/project/notes.md", "/etc/cache space/../cron.d/job", false},
		{"document profile", "/project/notes.md", "~/.bashrc", false},
		{"document credential", "/project/notes.md", "/etc/shadow", false},
		{"protected target", "/etc/cron.d/job", "notes", true},
		{"protected traversal target", "/etc/cache space/../cron.d/job", "notes", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{"path": tc.path, "content": tc.content})
			if err != nil {
				t.Fatal(err)
			}
			req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":` + string(args) + "}}\n"
			var upstream, logs bytes.Buffer
			blocked := make(chan BlockedRequest, 1)
			ForwardScannedInput(transport.NewStdioReader(strings.NewReader(req)), transport.NewStdioWriter(&upstream), &logs,
				config.ActionBlock, config.ActionBlock, blocked, nil, nil, MCPProxyOpts{Scanner: sc, PolicyCfg: pc})
			if got := strings.Contains(upstream.String(), "tools/call"); got == tc.blocked {
				t.Fatalf("forwarded=%v, want blocked=%v; logs=%s", got, tc.blocked, logs.String())
			}
			count := 0
			for refusal := range blocked {
				count++
				if refusal.ErrorCode != -32002 {
					t.Errorf("error=%d, want -32002", refusal.ErrorCode)
				}
			}
			want := 0
			if tc.blocked {
				want = 1
			}
			if count != want {
				t.Errorf("refusals=%d, want %d", count, want)
			}
		})
	}
}
