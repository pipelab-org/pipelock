// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func TestFileToolPathIdentityWhitespaceTransports(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink fixture needs POSIX link semantics")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	profile := filepath.Join(home, ".profile")
	if err := os.WriteFile(profile, []byte("baseline\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(home, "release notes")
	if err := os.Symlink(profile, alias); err != nil {
		t.Fatal(err)
	}
	sc := testInputScanner(t)
	for _, enabled := range []bool{false, true} {
		pc := buildPolicyConfig(config.ActionBlock, policy.DefaultToolPolicyRules())
		if enabled {
			pc.EnableLocalPathIdentity()
		}
		args, err := json.Marshal(map[string]string{"workspace_entry": alias})
		if err != nil {
			t.Fatal(err)
		}
		req := `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"write_file","arguments":` + string(args) + `}}` + "\n"
		var serverIn, logW bytes.Buffer
		blocked := make(chan BlockedRequest, 1)
		opts := MCPProxyOpts{Scanner: sc, PolicyCfg: pc}
		ForwardScannedInput(transport.NewStdioReader(strings.NewReader(req)), transport.NewStdioWriter(&serverIn), &logW, config.ActionBlock, config.ActionBlock, blocked, nil, nil, opts)
		if forwarded := strings.Contains(serverIn.String(), "tools/call"); forwarded == enabled {
			t.Fatalf("local identity=%v: forwarded=%v log=%s", enabled, forwarded, logW.String())
		}
		var stdioBlock *BlockedRequest
		for br := range blocked {
			stdioBlock = &br
		}
		for surface, br := range map[string]*BlockedRequest{
			"stdio": stdioBlock,
			"HTTP":  scanHTTPInput([]byte(req), io.Discard, "", "", opts),
		} {
			if !enabled {
				if br != nil {
					t.Fatalf("%s control blocked without local identity: %+v", surface, br)
				}
				continue
			}
			if br == nil || br.ErrorCode != -32002 || string(br.ID) != "10" || !strings.Contains(br.ErrorMessage, "tool call policy") {
				t.Fatalf("%s: missing policy denial with original ID: %+v", surface, br)
			}
		}
		if enabled && !strings.Contains(logW.String(), "policy:Shell Profile Modification") {
			t.Fatalf("denial log omitted the matching rule: %s", logW.String())
		}
	}
}
