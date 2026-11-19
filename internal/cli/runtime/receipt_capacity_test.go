// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestSingleReceiptRestartRefusesOverLimitNativePredecessor(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "evidence")
	keyPath := filepath.Join(root, "receipt.key")
	_, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	options := func(evidenceDir string) ServerOpts {
		return ServerOpts{
			ConfigFile: writeServerTestConfig(t, fmt.Sprintf("mode: balanced\nflight_recorder:\n  enabled: true\n  require_receipts: true\n  dir: %q\n  signing_key_path: %q\n", evidenceDir, keyPath)),
			Stdout:     io.Discard, Stderr: io.Discard,
		}
	}

	opts := options(dir)
	first, err := NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	firstSession := first.receiptEmitter.Session()
	signer := first.receiptEmitter.SignerKeyHex()
	first.sealTranscriptRoot()
	first.cleanup()
	paths, err := filepath.Glob(filepath.Join(dir, "ael", "*", "recorders", "*.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("native streams = %v, err = %v", paths, err)
	}
	run := filepath.Base(filepath.Dir(filepath.Dir(paths[0])))
	if _, err := ael.VerifyRun(dir, run, signer); err != nil {
		t.Fatalf("original predecessor did not verify: %v", err)
	}
	if err := os.Truncate(paths[0], (256<<20)+1); err != nil {
		t.Fatal(err)
	}

	refused, err := NewServer(opts)
	if refused != nil {
		refused.cleanup()
		t.Fatal("opened a successor over an oversized predecessor")
	}
	if !errors.Is(err, ael.ErrStreamTooLarge) || !strings.Contains(err.Error(), "set flight_recorder.dir to a new empty directory") {
		t.Fatalf("startup refusal = %v", err)
	}
	t.Logf("startup refusal = %v", err)
	if _, _, err := runMCPProxyCommand(t, opts.ConfigFile); !errors.Is(err, ael.ErrStreamTooLarge) {
		t.Fatalf("standalone MCP startup refusal = %v", err)
	}
	next, err := NewServer(options(filepath.Join(root, "new-evidence")))
	if err != nil {
		t.Fatalf("new recorder directory did not restore startup: %v", err)
	}
	defer next.cleanup()
	if next.receiptEmitter.Session() == firstSession {
		t.Fatal("new recorder directory reused the refused session")
	}
	next.sealTranscriptRoot()
}

func TestReceiptHeartbeatCapacityLeavesEmitterSealable(t *testing.T) {
	const ceiling = 1300
	capacity := ael.NewCapacity(ceiling)
	dir := t.TempDir()
	_, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: key, NativeCapacity: capacity})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	var log bytes.Buffer
	startReceiptHeartbeat(ctx, &wg, time.Hour, func() *receipt.Emitter { return e }, &log, true, func(err error) {
		t.Errorf("capacity treated as a persistence failure: %v", err)
	})
	cancel()
	wg.Wait()
	if e.HealthError() != nil || !strings.Contains(log.String(), ael.ErrCapacity.Error()) {
		t.Fatalf("health = %v, heartbeat log = %q", e.HealthError(), log.String())
	}
	if err := emitSessionCloseAndTranscriptRoot(e, e.Session()); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "ael", "*"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("native runs = %v, error = %v", paths, err)
	}
	if head, err := ael.VerifyRun(dir, filepath.Base(paths[0]), e.SignerKeyHex()); err != nil || head.RecordCount != 2 {
		t.Fatalf("verifiable close: head=%+v err=%v", head, err)
	}
}
