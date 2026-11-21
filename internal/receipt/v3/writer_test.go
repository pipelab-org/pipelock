// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func writerTestOptions(dir string) StreamWriterOptions {
	seed := sha256.Sum256([]byte("stream writer example"))
	return StreamWriterOptions{
		Dir: dir, SigningKey: ed25519.NewKeyFromSeed(seed[:]),
		Coverage: Coverage{
			ReceiptsRequired: true,
			Surfaces:         []string{"forward", "fetch"},
			RedactionRuleset: Ruleset{Hash: Digest([]byte("example rules")), ID: "example", Version: "1"},
		},
		Identity:   Writer{Instance: "instance\u2028and\u2029literal\\u2028", Product: "example", Version: "1"},
		PolicyHash: Digest([]byte("example policy")),
	}
}

func requireWriter(t *testing.T, opts StreamWriterOptions, storage writerStorage) *StreamWriter {
	t.Helper()
	writer, err := openStreamWriter(t.Context(), opts, storage)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close(context.Background(), nil) })
	return writer
}

func verifyWritten(t *testing.T, dir string, keys ...ed25519.PublicKey) Result {
	t.Helper()
	result, err := VerifyPaths(t.Context(), []string{dir}, Options{Directory: true, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	if result.Integrity == "failed" || len(result.Histories) != 1 {
		t.Fatalf("unexpected written history: %+v", result)
	}
	return result
}

func TestStreamWriterLifecycleAndRotation(t *testing.T) {
	dir := t.TempDir()
	opts := writerTestOptions(dir)
	writer := requireWriter(t, opts, localWriterStorage())
	if _, err := OpenStreamWriter(t.Context(), opts); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("second writer must be refused by lock, got %v", err)
	}
	active := writer.active.id

	// Force the next append into a newly published file.
	writer.fileBytes = writer.active.bytes + maxLineBytes
	if err := writer.WriteHeartbeat(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, writerFilename(active, 1))); err != nil {
		t.Fatal(err)
	}
	if err := writer.Rollover(t.Context()); err != nil {
		t.Fatal(err)
	}
	if writer.active.id == active || writer.active.confirmed.Seq != 0 {
		t.Fatal("rollover did not open a new stream")
	}
	if err := writer.WriteHeartbeat(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}

	public := opts.SigningKey.Public().(ed25519.PublicKey)
	nextSeed := sha256.Sum256([]byte("next example signer"))
	opts.SigningKey = ed25519.NewKeyFromSeed(nextSeed[:])
	if _, err := OpenStreamWriter(t.Context(), opts); err == nil || !strings.Contains(err.Error(), codeTrust) ||
		!strings.Contains(err.Error(), Digest(public)) {
		t.Fatalf("restart without previous trust should name failing stream: %v", err)
	}
	opts.PriorSignerKeys = []ed25519.PublicKey{public}
	restarted := requireWriter(t, opts, localWriterStorage())
	if err := restarted.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result := verifyWritten(t, dir, public, opts.SigningKey.Public().(ed25519.PublicKey))
	if result.Verdict != "VALID" || len(result.Histories[0].Streams) != 3 || len(result.Trust.Keys) != 2 {
		t.Fatalf("expected three closed streams and both trust keys: %+v", result)
	}
}

type errorWriterFile struct {
	StreamFile
	writeErr error
	syncErr  error
}

func (f errorWriterFile) Write(line []byte) (int, error) {
	if f.writeErr != nil {
		n, err := f.StreamFile.Write(line[:len(line)/2])
		return n, errors.Join(err, f.writeErr)
	}
	return f.StreamFile.Write(line)
}

func (f errorWriterFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.StreamFile.Sync()
}

func TestStreamWriterNeverConfirmsFailedTail(t *testing.T) {
	for _, operation := range []string{"write", "flush", "directory", "close"} {
		t.Run(operation, func(t *testing.T) {
			dir := t.TempDir()
			opts := writerTestOptions(dir)
			storage := localWriterStorage()
			writer := requireWriter(t, opts, storage)
			first, confirmed := writer.active.id, writer.active.confirmed
			fault := errors.New("injected storage failure")
			switch operation {
			case "write":
				writer.active.file = errorWriterFile{StreamFile: writer.active.file, writeErr: fault}
			case "flush", "close":
				writer.active.file = errorWriterFile{StreamFile: writer.active.file, syncErr: fault}
			case "directory":
				writer.fileBytes = writer.active.bytes + maxLineBytes
				writer.storage.syncDir = func(string) error {
					writer.storage.syncDir = storage.syncDir
					return fault
				}
			}
			if operation == "close" {
				if err := writer.Close(t.Context(), nil); !errors.Is(err, fault) {
					t.Fatalf("want close flush failure, got %v", err)
				}
			} else {
				if err := writer.WriteHeartbeat(t.Context()); !errors.Is(err, fault) {
					t.Fatalf("want heartbeat storage failure, got %v", err)
				}
				if err := writer.WriteHeartbeat(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
			}
			result := verifyWritten(t, dir, opts.SigningKey.Public().(ed25519.PublicKey))
			for _, stream := range result.Histories[0].Streams {
				if stream.Stream == first {
					if stream.End != "superseded_write_error" || stream.Tip == nil || *stream.Tip != confirmed {
						t.Fatalf("failed stream retained the wrong records: %+v", stream)
					}
					return
				}
			}
			t.Fatal("failed stream is missing")
		})
	}
}

func TestStreamWriterStartupRequiresNameFlushAndCompletedScan(t *testing.T) {
	fault := errors.New("injected directory flush failure")
	dir := t.TempDir()
	opts := writerTestOptions(dir)
	storage := localWriterStorage()
	syncDir := storage.syncDir
	storage.syncDir = func(path string) error {
		if path == dir {
			return fault
		}
		return syncDir(path)
	}
	if _, err := openStreamWriter(t.Context(), opts, storage); !errors.Is(err, fault) {
		t.Fatalf("want directory flush failure, got %v", err)
	}
	found, err := DirectoryHasV3(dir)
	if err != nil || !found {
		t.Fatalf("linked name should remain visible, got %v, %v", found, err)
	}
	storage = localWriterStorage()
	reflushed := false
	storage.syncFile = func(path string) error {
		reflushed = true
		return syncWriterFile(path)
	}
	writer := requireWriter(t, opts, storage)
	if !reflushed {
		t.Fatal("restart did not re-flush the surviving predecessor")
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}

	dir = t.TempDir()
	opts = writerTestOptions(dir)
	opts.Coverage.ContentScan = true
	if _, err := OpenStreamWriter(t.Context(), opts); err == nil {
		t.Fatal("writer accepted content scanning with no detector")
	}
	opts.Detector = func(context.Context, string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Incomplete: true}
	}
	if _, err := OpenStreamWriter(t.Context(), opts); !errors.Is(err, scanner.ErrTextDLPIncomplete) {
		t.Fatalf("want incomplete inspection failure, got %v", err)
	}
	opts.Detector = func(context.Context, string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: true}
	}
	// A cancelled scan must not publish the opening record.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := OpenStreamWriter(ctx, opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("want cancelled startup, got %v", err)
	}
	found, err = DirectoryHasV3(dir)
	if err != nil || found {
		t.Fatalf("cancelled startup published evidence: %v, %v", found, err)
	}
}

func TestStreamWriterRefusesUnflushedEvidenceDirectory(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "evidence")
	opts := writerTestOptions(dir)
	storage := localWriterStorage()
	errSync := errors.New("injected parent flush failure")
	realSync := storage.syncDir
	storage.syncDir = func(path string) error {
		if path == parent {
			return errSync
		}
		return realSync(path)
	}
	for range 2 {
		if _, err := openStreamWriter(t.Context(), opts, storage); !errors.Is(err, errSync) {
			t.Fatalf("writer did not refuse an unconfirmed directory name: %v", err)
		}
		hasV3, err := DirectoryHasV3(dir)
		if err != nil || hasV3 {
			t.Fatalf("unconfirmed directory has v3 evidence: %t, %v", hasV3, err)
		}
	}
	w := requireWriter(t, opts, localWriterStorage())
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestStreamWriterScheduledHeartbeat(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	opts.Heartbeat = 0
	w := requireWriter(t, opts, localWriterStorage())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ticks := make(chan time.Time)
	flushed := make(chan struct{})
	w.active.file = syncCallbackFile{
		StreamFile: w.active.file,
		syncCallback: sync.OnceFunc(func() {
			close(flushed)
		}),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.runHeartbeats(ctx, ticks, nil)
	}()
	deadline, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	select {
	case ticks <- time.Now():
	case <-done:
		t.Fatal("heartbeat loop stopped before receiving a tick")
	case <-deadline.Done():
		t.Fatal("heartbeat loop did not receive a tick")
	}
	select {
	case <-flushed:
	case <-done:
		t.Fatal("heartbeat loop stopped before flushing")
	case <-deadline.Done():
		t.Fatal("heartbeat did not flush")
	}
	cancel()
	<-done
	if w.active.beat != 1 || w.active.confirmed.Seq != 1 {
		t.Fatalf("heartbeat was not confirmed: beat=%d seq=%d", w.active.beat, w.active.confirmed.Seq)
	}
}

func TestStreamWriterRestartRequiresPredecessorFlush(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	opts.Heartbeat = 0
	first := requireWriter(t, opts, localWriterStorage())
	if err := first.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	predecessor := filepath.Join(opts.Dir, writerFilename(first.active.id, 0))
	stale := filepath.Join(opts.Dir, writerTempPrefix+"interrupted")
	if err := os.WriteFile(stale, []byte("partial record"), 0o600); err != nil {
		t.Fatal(err)
	}
	fault := errors.New("restart storage barrier failed")
	for _, stage := range []string{"cleanup", "file flush", "directory flush"} {
		t.Run(stage, func(t *testing.T) {
			storage := localWriterStorage()
			switch stage {
			case "cleanup":
				storage.remove = func(path string) error {
					if path == stale {
						return fault
					}
					return os.Remove(path)
				}
			case "file flush":
				storage.syncFile = func(path string) error {
					if path != predecessor {
						t.Errorf("flushed %s, want verified predecessor %s", path, predecessor)
					}
					return fault
				}
			case "directory flush":
				syncDir := storage.syncDir
				storage.syncDir = func(path string) error {
					if path == opts.Dir {
						return fault
					}
					return syncDir(path)
				}
			}
			writer, err := openStreamWriter(t.Context(), opts, storage)
			if err == nil {
				_ = writer.Close(t.Context(), nil)
			}
			if !errors.Is(err, fault) {
				t.Fatalf("restart error = %v, want %v", err, fault)
			}
			result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
			if result.Verdict != "VALID" || len(result.Histories[0].Streams) != 1 {
				t.Fatalf("failed restart changed the verified history: %+v", result)
			}
		})
	}
	restarted := requireWriter(t, opts, localWriterStorage())
	if err := restarted.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if result.Verdict != "VALID" || len(result.Histories[0].Streams) != 2 {
		t.Fatalf("restart after retry did not extend the history: %+v", result)
	}
}

func TestStreamWriterFailedRolloverPinsLastConfirmedRecord(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	opts.Heartbeat = 0
	w := requireWriter(t, opts, localWriterStorage())
	if err := w.WriteHeartbeat(t.Context()); err != nil {
		t.Fatal(err)
	}
	predecessor, tip := w.active.id, w.active.confirmed
	w.active.file = errorWriterFile{StreamFile: w.active.file, syncErr: errWriterReplay}
	effects := make(chan string, 2)
	admit := func(id string) error {
		if err := w.Rollover(t.Context()); err != nil {
			return err
		}
		if err := w.WriteAction(t.Context(), writerTestIntent(id), CapturePolicy(opts.PolicyHash)); err != nil {
			return err
		}
		effects <- id
		return nil
	}
	if err := admit("failed"); !errors.Is(err, errWriterReplay) || len(effects) != 0 {
		t.Fatalf("failed close: error = %v, effects = %d", err, len(effects))
	}
	if err := w.WriteAction(t.Context(), writerTestIntent("successor"), CapturePolicy(opts.PolicyHash)); err != nil {
		t.Fatalf("successor intent: %v", err)
	}
	effects <- "successor"
	if got := <-effects; got != "successor" {
		t.Fatalf("first effect = %q, want successor", got)
	}
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	streams := result.Histories[0].Streams
	var previous, successor StreamResult
	for _, stream := range streams {
		switch stream.Stream {
		case predecessor:
			previous = stream
		case w.active.id:
			successor = stream
		}
	}
	if len(streams) != 2 || previous.Tip == nil || *previous.Tip != tip ||
		previous.End != "superseded_write_error" || successor.Previous != predecessor || successor.End != endedClosed {
		t.Fatalf("rollover retained the wrong history: %+v", streams)
	}
	if err := w.WriteHeartbeat(t.Context()); !errors.Is(err, ErrWriterUnavailable) {
		t.Fatalf("closed stream accepted heartbeat: %v", err)
	}
	if err := w.Rollover(t.Context()); !errors.Is(err, ErrWriterUnavailable) {
		t.Fatalf("closed stream accepted rollover: %v", err)
	}
}

func TestStreamWriterHeartbeatCallbackCanClose(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	w.active.file = errorWriterFile{StreamFile: w.active.file, syncErr: errWriterReplay}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ticks := make(chan time.Time, 1)
	ticks <- time.Now()
	done := make(chan struct{})
	w.stopHeartbeat = func() {
		cancel()
		<-done
	}
	reported := make(chan error, 1)
	go func() {
		defer close(done)
		w.runHeartbeats(ctx, ticks, func(error) {
			reported <- w.Close(t.Context(), nil)
		})
	}()
	select {
	case err := <-reported:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat callback could not close the writer")
	}
}

func TestStreamWriterReportsScheduledHeartbeatFlushFailure(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	opts.Heartbeat = 0
	opts.Coverage.ContentScan = true
	opts.Detector = func(context.Context, string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: true}
	}
	w := requireWriter(t, opts, localWriterStorage())
	w.active.file = errorWriterFile{StreamFile: w.active.file, syncErr: errWriterReplay}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ticks := make(chan time.Time, 1)
	ticks <- time.Now()
	reported := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.runHeartbeats(ctx, ticks, func(err error) { reported <- err })
	}()
	defer func() {
		cancel()
		<-done
	}()
	select {
	case err := <-reported:
		if !errors.Is(err, errWriterReplay) {
			t.Fatalf("heartbeat callback = %v, want failed flush", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat failure was not reported")
	}
	if err := w.WriteHeartbeat(t.Context()); err != nil {
		t.Fatalf("heartbeat did not recover on the successor: %v", err)
	}
}
