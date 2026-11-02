// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiveRunRefusesPacketWhenCloseCannotBeRecorded(t *testing.T) {
	lr, err := StartLiveRun(t.Context(), LiveRunOpts{ScenarioID: LiveDemoScenarioID, RunNonce: "closed-recorder"})
	if err != nil {
		t.Fatal(err)
	}
	defer lr.Close()
	if lr.receipts == nil || lr.rec == nil {
		t.Fatal("test requires the real live recorder and receipt emitter")
	}
	if err := lr.rec.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	report, err := lr.AssembleAndVerify(dir)
	if err == nil || !strings.Contains(err.Error(), "session_close receipt:") || report.OK {
		t.Fatalf("report=%+v err=%v; want a close-receipt refusal", report, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "packet", "packet.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed close must not publish a packet: %v", err)
	}
}
