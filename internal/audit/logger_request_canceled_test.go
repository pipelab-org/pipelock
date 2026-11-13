// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/emit"
)

func TestLogRequestCanceledEmitsInfoEvent(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)

	logger.LogRequestCanceled(LogContext{method: testMethodGet, url: "https://api.vendor.example/v1", clientIP: "192.0.2.7", requestID: testReqID}, "context canceled")
	event, ok := sink.lastEvent()
	if !ok {
		t.Fatal("expected an emitted cancellation event")
	}
	if event.Type != string(EventRequestCanceled) || event.Severity != emit.SeverityInfo {
		t.Fatalf("event type/severity = %q/%v", event.Type, event.Severity)
	}
	for field, want := range map[string]any{
		"method": testMethodGet, "client_ip": "192.0.2.7", "request_id": testReqID, "reason": "context canceled",
	} {
		if got := event.Fields[field]; got != want {
			t.Errorf("field %s = %v, want %v", field, got, want)
		}
	}
}

// A cancellation is not a block, so turning blocked events off keeps it.
func TestLogRequestCanceledIgnoresBlockedFilter(t *testing.T) {
	dir := t.TempDir()
	logger, err := New("json", "file", dir+"/test.log", true, false)
	if err != nil {
		t.Fatal(err)
	}
	sink := &collectingSink{}
	emitter := emit.NewEmitter("test-instance", sink)
	logger.SetEmitter(emitter)
	t.Cleanup(logger.Close)
	t.Cleanup(func() { _ = emitter.Close() })

	logger.LogRequestCanceled(NewRequestLogContext(testReqID), "context canceled")
	if event, ok := sink.lastEvent(); !ok || event.Type != string(EventRequestCanceled) {
		t.Fatalf("cancellation dropped with blocked events disabled: %+v ok=%v", event, ok)
	}
}

func TestLogRequestCanceledNilLogger(t *testing.T) {
	var logger *Logger
	logger.LogRequestCanceled(NewRequestLogContext(testReqID), "context canceled")
}
