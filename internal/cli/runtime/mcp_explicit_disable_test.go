// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
)

const disabledMCPYAML = "mcp_input_scanning: {enabled: false}\nmcp_tool_scanning: {enabled: false}\nmcp_tool_policy: {enabled: false}\n"

func TestMCPCommandsExplicitDisable(t *testing.T) {
	for _, tc := range []struct {
		name, action string
		disabled     bool
	}{
		{name: "omitted"},
		{name: "false", disabled: true},
		{name: "false empty action", action: `, action: ""`, disabled: true},
		{name: "false null action", action: ", action: null", disabled: true},
		{name: "false warn", action: ", action: warn", disabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			body := "flight_recorder: {enabled: false}\n"
			if tc.disabled {
				body += strings.ReplaceAll(disabledMCPYAML, "enabled: false}", "enabled: false"+tc.action+"}")
			}
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Run("scan", func(t *testing.T) {
				cmd := McpCmd()
				var out, errOut bytes.Buffer
				cmd.SetOut(&out)
				cmd.SetErr(&errOut)
				cmd.SetIn(strings.NewReader(cliBenignToolsListLine))
				cmd.SetArgs([]string{"scan", "--json", "--config", path})
				err := cmd.Execute()
				if tc.disabled && !errors.Is(err, ErrMCPScanMalformedInput) || !tc.disabled && err != nil {
					t.Fatalf("scan error = %v", err)
				}
				var verdict jsonrpc.ScanVerdict
				if err := json.Unmarshal([]byte(strings.SplitN(out.String(), "\n", 2)[0]), &verdict); err != nil {
					t.Fatalf("decode verdict: %v; output=%s", err, out.String())
				}
				if verdict.Clean == tc.disabled || slices.Contains(verdict.Unscanned, jsonrpc.ScanScopeToolScanning) != tc.disabled || slices.Contains(verdict.Scanned, jsonrpc.ScanScopeToolScanning) == tc.disabled {
					t.Fatalf("disabled tool scanner certified coverage: %+v", verdict)
				}
			})
			t.Run("proxy", func(t *testing.T) {
				if runtime.GOOS == "windows" {
					t.Skip("subprocess fixture requires /bin/true")
				}
				cmd := McpCmd()
				var out, errOut bytes.Buffer
				cmd.SetOut(&out)
				cmd.SetErr(&errOut)
				cmd.SetIn(strings.NewReader(""))
				cmd.SetArgs([]string{"proxy", "--config", path, "--", "/bin/true"})
				if err := cmd.Execute(); err != nil {
					t.Fatalf("proxy: %v; stderr=%s", err, errOut.String())
				}
				log := errOut.String()
				want := "input=block, tools=warn, policy=warn"
				if tc.disabled {
					want = "input=disabled, tools=disabled, policy=disabled"
				}
				if strings.Contains(log, "auto-enabling MCP") == tc.disabled || !strings.Contains(log, want) {
					t.Fatalf("startup mislabeled disabled scanners: %s", log)
				}
			})
		})
	}
}

func TestServerReloadMCPExplicitDisable(t *testing.T) {
	for _, tc := range []struct {
		name, initial string
		reject        bool
	}{
		{name: "unchanged disabled", initial: disabledMCPYAML},
		{name: "enabled downgrade", reject: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.yaml")
			if err := os.WriteFile(path, []byte(tc.initial), 0o600); err != nil {
				t.Fatal(err)
			}
			s, _ := newTestServer(t, func(o *ServerOpts) { o.ConfigFile = path })
			s.runtimeMode = config.RuntimeMCPProxy
			first, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Reload(first); err != nil {
				t.Fatal(err)
			}
			for _, extra := range []string{"", "logging: {format: json}\n"} {
				before := s.proxy.CurrentConfig()
				s.lastReloadAt = time.Time{}
				update, err := config.LoadBytes([]byte(disabledMCPYAML + extra))
				if err != nil {
					t.Fatal(err)
				}
				err = s.Reload(update)
				after := s.proxy.CurrentConfig()
				if tc.reject {
					if err == nil || !strings.Contains(err.Error(), "would weaken security posture") || after != before {
						t.Fatalf("downgrade error=%v retained=%t", err, after == before)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if after.MCPInputScanning.Enabled != tc.reject || after.MCPToolScanning.Enabled != tc.reject || after.MCPToolPolicy.Enabled != tc.reject {
					t.Fatal("reload lost effective MCP state")
				}
			}
		})
	}
}
