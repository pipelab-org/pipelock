// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

const hostileField = "evil\x1b[2K\r\b\u202Eok"

const escapedHostileField = `evil\x1b[2K\r\x08\u202Eok`

func assertTerminalSafe(t *testing.T, out string, wantEscaped int) {
	t.Helper()
	for _, c := range []string{"\x1b", "\r", "\b", "\u202e"} {
		if strings.Contains(out, c) {
			t.Fatalf("output contains raw %q:\n%q", c, out)
		}
	}
	if got := strings.Count(out, escapedHostileField); got < wantEscaped {
		t.Fatalf("escaped field shown %d times, want at least %d:\n%s", got, wantEscaped, out)
	}
}

// These views are printed by "session recover" right before its interactive
// choice, and by "session deferred list" for approve/deny decisions. Agent
// names, targets and details come from client traffic.
func TestRenderersEscapeClientFields(t *testing.T) {
	t.Parallel()
	now := time.Now()

	t.Run("detail", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		d := proxy.SessionDetail{RecoverHint: hostileField, RecentEvents: []proxy.SessionEvent{
			{At: now, Kind: hostileField, Target: hostileField, Detail: hostileField},
		}}
		d.Key = hostileField
		d.Agent = hostileField
		d.ClientIP = "192.0.2.10"
		if err := renderDetail(&buf, d); err != nil {
			t.Fatal(err)
		}
		assertTerminalSafe(t, buf.String(), 6)
		if !strings.Contains(buf.String(), "client_ip:        192.0.2.10\n") {
			t.Fatalf("benign field altered:\n%s", buf.String())
		}
	})
	t.Run("explanation", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		e := proxy.SessionExplanation{
			Key: hostileField, Reason: hostileField, Trigger: hostileField,
			EvidenceKind: hostileField, EvidenceTarget: hostileField, EvidenceDetail: hostileField,
		}
		if err := renderExplanation(&buf, e); err != nil {
			t.Fatal(err)
		}
		assertTerminalSafe(t, buf.String(), 6)
	})
	t.Run("list", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		if err := renderList(&buf, []proxy.SessionSnapshot{{Key: hostileField, Agent: hostileField, LastActivity: now}}); err != nil {
			t.Fatal(err)
		}
		assertTerminalSafe(t, buf.String(), 2)
	})
	t.Run("deferred list", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		resp := proxy.DeferredListResponse{Count: 1, Held: []proxy.DeferredHeldView{{
			DeferID: "d-1", Surface: "fetch", Method: "GET", Target: hostileField, SessionID: "s-1", Reason: hostileField,
		}}}
		if err := renderDeferredList(&buf, resp); err != nil {
			t.Fatal(err)
		}
		assertTerminalSafe(t, buf.String(), 2)
		if !strings.Contains(buf.String(), "d-1") || !strings.Contains(buf.String(), "fetch") {
			t.Fatalf("benign fields missing:\n%s", buf.String())
		}
	})
}
