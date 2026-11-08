// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/eventcatalog"
)

func TestWatchOnlyEvents(t *testing.T) {
	cases := []struct {
		action, event string
		enforced      bool
		bytes         int64
	}{
		{"block", eventcatalog.EventWouldBlock, false, 0},
		{"warn", eventcatalog.EventWatchOnlyObservation, false, 0},
		{"allow", eventcatalog.EventWatchOnlyObservation, false, 0},
		{"", eventcatalog.EventWatchOnlyObservation, false, 0},
		{"strip", eventcatalog.EventWouldBlock, false, 0},
		{"escalate", eventcatalog.EventWouldEscalate, false, 0},
		{"uninspected", eventcatalog.EventUninspected, false, 42},
		{"block", eventcatalog.EventWatchOnlyEnforced, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.event+tc.action, func(t *testing.T) {
			logger, sink := newLoggerWithEmitter(t)
			var buf bytes.Buffer
			logger.zl = logger.zl.Output(&buf)
			logger.includeBlocked = false
			logger.LogWatchOnly("forward", "request_body", "inspection limit", tc.action, tc.bytes, tc.enforced)
			var entry map[string]any
			if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
				t.Fatal(err)
			}
			if entry["event"] != tc.event || entry["watch_only"] != true || entry["enforced"] != tc.enforced || entry["would_have_been_action"] != tc.action || entry["uninspected_bytes"] != float64(tc.bytes) {
				t.Fatalf("wrong observation: %+v", entry)
			}
			if tc.enforced && !strings.Contains(entry["message"].(string), "enforced in watch-only") {
				t.Fatal("enforcement exception not explicit")
			}
			ev, ok := sink.lastEvent()
			if !ok || ev.Type != tc.event || ev.Severity != emit.SeverityWarn {
				t.Fatalf("external observation: %+v", ev)
			}
		})
	}
}

func TestWatchOnlyModeChangesAndNilLogger(t *testing.T) {
	var absent *Logger
	absent.LogWatchOnly("forward", "request_body", "limit", "uninspected", 1, false)
	absent.LogWatchOnlyMode(true)
	logger, sink := newLoggerWithEmitter(t)
	for _, enabled := range []bool{true, false} {
		logger.LogWatchOnlyMode(enabled)
		ev, ok := sink.lastEvent()
		if !ok || ev.Type != eventcatalog.EventWatchOnlyMode || ev.Fields["watch_only"] != enabled {
			t.Fatalf("mode not emitted: %+v", ev)
		}
	}
}

func TestWatchOnlyCatalogDoesNotClaimObservationBlocked(t *testing.T) {
	wanted := map[string]string{eventcatalog.EventWatchOnlyObservation: "warn", eventcatalog.EventWouldBlock: "warn", eventcatalog.EventWouldEscalate: "warn", eventcatalog.EventUninspected: "warn", eventcatalog.EventWatchOnlyMode: "warn", eventcatalog.EventWatchOnlyEnforced: "block"}
	for _, d := range eventcatalog.Builtins() {
		if action, ok := wanted[d.Name]; ok {
			if d.Action != action {
				t.Errorf("%s classifies as %s", d.Name, d.Action)
			}
			delete(wanted, d.Name)
		}
	}
	if len(wanted) != 0 {
		t.Fatalf("missing descriptors: %v", wanted)
	}
}
