// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0
package runtime

import (
	"bytes"
	"strings"
	"testing"
)

func TestMCPProxyOAuthFlagsRequireListener(t *testing.T) {
	for _, flags := range [][]string{
		{"--oauth-resource-url", "http://127.0.0.1:18891/mcp"},
		{"--oauth-authorization-server", "https://mcp.slack.com"},
		{"--oauth-resource-url", "http://127.0.0.1:18891/mcp", "--oauth-authorization-server", "https://mcp.slack.com"},
	} {
		cmd := McpCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetIn(strings.NewReader(""))
		cmd.SetArgs(append([]string{"proxy", "--upstream", "http://127.0.0.1:1/mcp"}, flags...))
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "OAuth flags require --listen") {
			t.Fatalf("flags=%v error=%v", flags, err)
		}
	}
}

func TestMCPProxyOAuthFlagsRequirePair(t *testing.T) {
	for _, flag := range []string{"--oauth-resource-url", "--oauth-authorization-server"} {
		cmd := McpCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetIn(strings.NewReader(""))
		cmd.SetArgs([]string{"proxy", "--upstream", "http://127.0.0.1:1/mcp", "--listen", "127.0.0.1:0", flag, "https://example.com"})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "must be provided together") {
			t.Fatalf("flag=%s error=%v", flag, err)
		}
	}
}
