// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestRepairGroupTransitionCommand(t *testing.T) {
	dir := t.TempDir()
	_, key := genKey(t)
	keyFile := filepath.Join(t.TempDir(), "opening.key")
	run := func(groupID string) (string, error) {
		cmd := Cmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"repair-group-transition", "--dir", dir, "--group", groupID, "--key-file", keyFile})
		err := cmd.ExecuteContext(t.Context())
		return out.String(), err
	}
	if _, err := run("invalid"); !errors.Is(err, os.ErrNotExist) || !strings.HasPrefix(err.Error(), "load opening key: ") {
		t.Fatalf("missing opening key error = %v", err)
	}
	if err := signing.SavePrivateKey(key, keyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := run("invalid"); err == nil || err.Error() != "invalid receipt group ID" {
		t.Fatalf("invalid group error = %v", err)
	}

	newRecorder := func() *recorder.Recorder {
		t.Helper()
		r, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		})
		return r
	}
	r := newRecorder()
	cfg := receipt.EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testPolicyHash, Principal: testPrincipal, Actor: "worker"}
	initial, err := receipt.OpenInitialReceiptShardSet(cfg, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, emitter := range initial.Emitters() {
		if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := initial.PublishClose(); err != nil {
		t.Fatal(err)
	}
	first, _ := initial.Opening()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	r = newRecorder()
	cfg.Recorder = r
	successor, err := receipt.OpenSuccessorReceiptShardSet(cfg, "proxy", 2, 0, first.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := successor.Opening()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	name, err := receipt.ReceiptGroupFileName(open.GroupID, "transition")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	out, err := run(open.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	result := receipt.VerifyReceiptGroup(dir, open.GroupID, []string{open.SignerKey})
	if result.Verdict != receipt.GroupIncomplete || result.Error != "receipt group has no signed close manifest" {
		t.Fatalf("repaired group verdict = %s, error = %q", result.Verdict, result.Error)
	}
	const prefix = "Published receipt group transition "
	if !strings.HasPrefix(out, prefix) || !strings.HasSuffix(out, "\n") {
		t.Fatalf("repair output = %q", out)
	}
}
