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
		name, key, path, content string
		blocked                  bool
	}{
		{"document cron", "path", "/project/notes.md", "/etc/cron.d/job", false},
		{"document traversal", "path", "/project/notes.md", "/etc/cache space/../cron.d/job", false},
		{"document profile", "path", "/project/notes.md", "~/.bashrc", false},
		{"document credential", "path", "/project/notes.md", "/etc/shadow", false},
		{"protected target", "path", "/etc/cron.d/job", "notes", true},
		{"protected traversal target", "path", "/etc/cache space/../cron.d/job", "notes", true},
		{"credential target", "target", "/etc/shadow", "notes", true},
		{"credential destination", "destination", ".ssh/id_rsa", "notes", true},
		{"credential dest", "dest", ".ssh/id_rsa", "notes", true},
		{"dd profile", "command", "dd if=payload of=.bashrc", "", true},
		{"dd persistence", "command", "dd of=/tmp/safe of=/etc/cron.d/job", "", true},
		{"dd audit", "command", "dd if=/dev/zero of=/var/log/auth.log", "", true},
		{"dd input", "command", "dd of=/tmp/backup if=/etc/cron.d/job", "", false},
		{"dd comment", "command", "dd of=/tmp/disk.img # notes /etc/cron.d/job", "", false},
		{"dd comment operand", "command", "dd of=/tmp/disk.img # of=/etc/cron.d/job", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tool := "write_file"
			input := map[string]string{tc.key: tc.path, "content": tc.content}
			if tc.key == "command" {
				tool = "bash"
				input = map[string]string{tc.key: tc.path}
			}
			args, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + string(args) + "}}\n"
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
