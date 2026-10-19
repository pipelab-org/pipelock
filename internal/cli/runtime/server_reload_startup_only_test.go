// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

// Startup-only blocks are warned about as "ignored on reload", so the reload
// verdict must report them as pending restart rather than as an activation.
func TestReloadOutcomeStartupOnlyFieldsPendingRestart(t *testing.T) {
	const base = "mode: balanced\n"
	for _, tc := range []struct{ name, body, field string }{
		{"health watchdog", base + "health_watchdog:\n  enabled: true\n  interval_seconds: 7\n", "health_watchdog"},
		{"sentry dsn", base + "sentry:\n  dsn: https://k@o.vendor.example/1\n", "sentry.dsn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := reloadStatusServer(t)
			before := s.ReloadStatus()
			writeReloadCandidate(t, s, tc.body)
			out := s.ReloadFile()
			if out.Verdict != proxy.ReloadRestartRequired || !out.PendingRestart || !slices.Contains(out.RestartRequiredFields, tc.field) {
				t.Fatalf("outcome: %+v", out)
			}
			if out.Generation != before.Generation {
				t.Fatalf("preserved startup-only value advanced generation: %d -> %d", before.Generation, out.Generation)
			}
			// The drift is recomputed, not erased, by a repeat of the same file.
			if again := s.ReloadFile(); again.Verdict != proxy.ReloadRestartRequired || !again.PendingRestart {
				t.Fatalf("repeat cleared pending restart: %+v", again)
			}
			writeReloadCandidate(t, s, base)
			if reverted := s.ReloadFile(); reverted.PendingRestart || reverted.Verdict == proxy.ReloadRestartRequired {
				t.Fatalf("revert kept drift: %+v", reverted)
			}
		})
	}
}
