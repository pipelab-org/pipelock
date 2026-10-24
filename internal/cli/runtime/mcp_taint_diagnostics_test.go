// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestMCPProxyTaintDiagnostics_Startup(t *testing.T) {
	for _, tc := range []struct{ name, yaml, want string }{
		{"omitted", "", "no persistent taint recorder"},
		{"null", "session_profiling: {enabled: null}\n", "no persistent taint recorder"},
		{"false", "session_profiling: {enabled: false}\n", "no persistent taint recorder"},
		{"true", "session_profiling: {enabled: true}\n", "invocation-scoped recorder"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte("flight_recorder: {enabled: false}\n"+tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := McpCmd()
			var out, log bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&log)
			cmd.SetIn(strings.NewReader(""))
			cmd.SetArgs([]string{"proxy", "--config", path, "--", "/bin/true"})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("proxy: %v; %s", err, log.String())
			}
			recorder := "recorder_risk_state=false cross_request_recording=inactive"
			if tc.name == "true" {
				recorder = "recorder_risk_state=true cross_request_recording=active"
			}
			for _, want := range []string{tc.want, recorder, "taint.mcp_recorder:", "taint.mcp_listener:", "taint.mcp_origin:", "taint.mcp_recovery:"} {
				if !strings.Contains(log.String(), want) {
					t.Errorf("startup omitted %q: %s", want, log.String())
				}
			}
		})
	}
}

func TestMCPListenerTaintDiagnostics_ActualReload(t *testing.T) {
	s, output := newTestServer(t, func(o *ServerOpts) {})
	s.runtimeMode = config.RuntimeForwardWithMCPListener
	for _, body := range []string{"", "logging: {format: json}\n", "taint: {enabled: false}\n", "taint: {enabled: true}\n"} {
		before := len(output.String())
		updated, err := config.LoadBytes([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		s.lastReloadAt = time.Time{}
		err = s.Reload(updated)
		log := output.String()[before:]
		if !updated.Taint.Enabled {
			if err == nil || !s.proxy.CurrentConfig().Taint.Enabled || strings.Contains(log, "taint is disabled") {
				t.Fatalf("rejected downgrade must retain active config without a disabled diagnostic: err=%v log=%s", err, log)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"taint.mcp_recorder:", "taint.mcp_listener:", "taint.mcp_origin:", "taint.mcp_recovery:"} {
			if !strings.Contains(log, want) {
				t.Errorf("reload omitted %q: %s", want, log)
			}
		}
		want := "no persistent taint recorder"
		if !updated.Taint.Enabled {
			want = "taint is disabled"
		}
		if !strings.Contains(log, want) {
			t.Errorf("reload has stale setting; want %q: %s", want, log)
		}
	}
}
