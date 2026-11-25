// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import "testing"

func TestLogTLSCRLWarning(t *testing.T) {
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()
	logger.LogTLSCRLWarning()
	ev, ok := sink.lastEvent()
	if !ok || ev.Type != string(EventConfigReload) || ev.Fields["status"] != "warning" {
		t.Fatalf("event = %#v", ev)
	}
}
