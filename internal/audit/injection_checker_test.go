// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import "testing"

func TestLogInjectionChecker_EmitsOutcomeWithoutContent(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	ctx := LogContext{requestID: "req-chk", agent: "agent-a"}.WithScanRoute("mcp_stdio", "files", "agent-a")
	logger.LogInjectionChecker(ctx, "local", "mcp_tool_result", "block", "finding", "instruction_override", false, false)

	ev := sink.onlyEvent(t)
	if ev.Type != string(EventInjectionChecker) {
		t.Fatalf("event type = %q", ev.Type)
	}
	for key, want := range map[string]any{
		"checker":    "local",
		"surface":    "mcp_tool_result",
		"mode":       "block",
		"state":      "finding",
		"reason":     "instruction_override",
		"transport":  "mcp_stdio",
		"mcp_server": "files",
		"request_id": "req-chk",
		"watch":      false,
		"dropped":    false,
	} {
		if got := ev.Fields[key]; got != want {
			t.Errorf("field %s = %v, want %v", key, got, want)
		}
	}
}

// A dropped watch call carries no mode, state or reason: those fields are
// omitted rather than logged empty.
func TestLogInjectionChecker_DroppedWatchOmitsEmptyFields(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	logger.LogInjectionChecker(LogContext{}, "watcher", "mcp_tool_description", "", "", "", true, true)

	ev := sink.onlyEvent(t)
	if ev.Fields["watch"] != true || ev.Fields["dropped"] != true {
		t.Fatalf("watch/dropped = %v/%v", ev.Fields["watch"], ev.Fields["dropped"])
	}
	for _, key := range []string{"mode", "state", "reason", "transport", "mcp_server"} {
		if _, ok := ev.Fields[key]; ok {
			t.Errorf("empty field %s was emitted", key)
		}
	}
}
