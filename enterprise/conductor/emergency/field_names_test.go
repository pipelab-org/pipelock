//go:build enterprise

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package emergency

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

func TestPersistedMessageFieldNames(t *testing.T) {
	msg, resolver := signedRemoteKill(t, 12, conductor.KillSwitchActive)
	path := filepath.Join(t.TempDir(), "state.json")
	fresh := func(ks *captureKillSwitch) *RemoteKillApplier {
		return &RemoteKillApplier{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1", Resolver: resolver, KillSwitch: ks, StatePath: path, Now: func() time.Time { return testNow }}
	}
	if err := fresh(&captureKillSwitch{}).Apply(msg); err != nil {
		t.Fatal(err)
	}
	canonical := &captureKillSwitch{}
	if err := fresh(canonical).RestorePersistedState(); err != nil || !canonical.active {
		t.Fatalf("canonical restart: %v", err)
	}
	state, err := readDurableRemoteKillState(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(state.SignedMessage, []byte(`"state":`), []byte(`"State":`), 1)
	if bytes.Equal(changed, state.SignedMessage) {
		t.Fatal("missing state field")
	}
	state.SignedMessage = changed
	if err := writeRemoteKillState(path, state); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	retained := &captureKillSwitch{active: true, message: "retained"}
	if err := fresh(retained).RestorePersistedState(); err == nil {
		t.Fatal("accepted noncanonical persisted message")
	}
	if !retained.active || retained.message != "retained" {
		t.Fatal("rejection changed active stop")
	}
	after, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejection rewrote replay state")
	}
}
