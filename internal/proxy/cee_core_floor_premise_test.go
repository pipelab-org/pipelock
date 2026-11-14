// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/ceereason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A core credential split across requests is refused when
// cross_request_detection.action is warn. The operator record names the core
// pattern and says it cannot be downgraded.
func TestCeeAdmit_CoreFragmentWarnRefused(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	fb := scanner.NewFragmentBuffer(65536, 1000, 300)
	t.Cleanup(fb.Close)
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", logPath, false, true)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	t.Cleanup(logger.Close)
	ceeCfg := config.CrossRequestDetection{
		FragmentReassembly: config.CrossRequestFragments{Enabled: true, MaxBufferBytes: 65536, WindowMinutes: 5},
		Action:             config.ActionWarn,
	}
	prefix, suffix := pathSecretHalves()
	admit := func(part, id string) ceeResult {
		t.Helper()
		return ceeAdmit(context.Background(), ceeAdmitOptions{
			Outbound: []byte(part), TargetURL: "http://api.vendor.example/collect",
			Agent: testCEEAgent, ClientIP: testCEEClientIP, RequestID: id,
			Config: ceeCfg, Fragments: fb, Scanner: sc, Logger: logger, Metrics: metrics.New(),
		})
	}
	if got := admit(prefix, "req-1"); got.Blocked || got.FragmentHit {
		t.Fatalf("prefix = %+v, want clean", got)
	}
	got := admit(suffix, "req-2")
	if !got.Blocked || !got.FragmentHit || got.Reason != ceereason.ClientFragmentMatch || got.BlockKind != "AWS Access ID" {
		t.Fatalf("reassembled core credential = %+v, want a blocked core fragment", got)
	}
	logger.Close()
	raw, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	logged := string(raw)
	if !strings.Contains(logged, "core pattern cannot be downgraded") || !strings.Contains(logged, "cross_request_fragment") {
		t.Fatalf("audit log = %s, want a blocked core fragment record", logged)
	}
}
