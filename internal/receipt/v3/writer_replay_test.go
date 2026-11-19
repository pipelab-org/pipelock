// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

const (
	replayWrite = "write"
	replayFlush = "flush"
	replayDir   = "directory"
	replayLink  = "link"
)

type writerReplayStep struct {
	Op           string
	Action       Action
	File         string
	Keep         int64
	FaultAt      int
	ExtraFaultAt int
	Landing      string
}

type writerReplayObservation struct {
	Calls        []string
	Error        string
	Files        map[string][]byte
	Verification Result
	VerifyError  string
}

type writerReplayFault struct {
	step  writerReplayStep
	calls []string
}

var errWriterReplay = errors.New("injected receipt storage error")

func (f *writerReplayFault) trip(operation string) bool {
	f.calls = append(f.calls, operation)
	return f.step.FaultAt == len(f.calls) || f.step.ExtraFaultAt == len(f.calls)
}

func (f *writerReplayFault) call(operation string, fn func() error) error {
	if f.trip(operation) {
		return errWriterReplay
	}
	return fn()
}

type writerReplayFile struct {
	StreamFile
	fault *writerReplayFault
}

func (f writerReplayFile) Write(data []byte) (int, error) {
	if !f.fault.trip(replayWrite) {
		return f.StreamFile.Write(data)
	}
	switch f.fault.step.Landing {
	case "full":
	case "torn":
		data = data[:len(data)/2]
	default:
		return 0, errWriterReplay
	}
	n, err := f.StreamFile.Write(data)
	return n, errors.Join(err, errWriterReplay)
}

func (f writerReplayFile) Sync() error {
	return f.fault.call(replayFlush, f.StreamFile.Sync)
}

func (f *writerReplayFault) storage(dir string) writerStorage {
	local := localWriterStorage()
	return writerStorage{
		createTemp: func(dir, prefix string) (StreamFile, error) {
			file, err := local.createTemp(dir, prefix)
			if err != nil {
				return nil, err
			}
			return writerReplayFile{file, f}, nil
		},
		link: func(oldPath, newPath string) error {
			return f.call(replayLink, func() error { return local.link(oldPath, newPath) })
		},
		rename: func(oldPath, newPath string) error {
			return f.call("rename", func() error { return local.rename(oldPath, newPath) })
		},
		remove: local.remove,
		syncDir: func(path string) error {
			if path != dir {
				return local.syncDir(path)
			}
			return f.call(replayDir, func() error { return local.syncDir(path) })
		},
		syncFile: func(path string) error {
			return f.call("reflush", func() error { return local.syncFile(path) })
		},
	}
}

// TestStreamWriterReplay accepts a JSON stream of operation arrays and writes
// one observation array per input. FaultAt is the one-based storage call
// within a step. ExtraFaultAt can fail a second storage call. Truncate and
// remove select the bytes and names left by a crash.
func TestStreamWriterReplay(t *testing.T) {
	input := os.Getenv("PIPELOCK_RECEIPT_REPLAY_INPUT")
	if input == "" {
		t.Skip("no replay cases supplied")
	}
	in, err := os.Open(filepath.Clean(input))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(os.Getenv("PIPELOCK_RECEIPT_REPLAY_OUTPUT"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	decoder, encoder := json.NewDecoder(in), json.NewEncoder(out)
	base := t.TempDir()
	for {
		var steps []writerReplayStep
		if err := decoder.Decode(&steps); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if err := encoder.Encode(runWriterReplay(t, base, steps)); err != nil {
			t.Fatal(err)
		}
	}
}

func runWriterReplay(t *testing.T, base string, steps []writerReplayStep) []writerReplayObservation {
	t.Helper()
	dir, err := os.MkdirTemp(base, "case-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	}()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	opts := writerTestOptions(dir)
	opts.Heartbeat = 0
	result := make([]writerReplayObservation, 0, len(steps))
	var fault writerReplayFault
	storage := fault.storage(dir)
	var w *StreamWriter
	defer func() { _ = abandonWriterReplay(w) }()
	for _, step := range steps {
		fault = writerReplayFault{step: step}
		w, err = applyWriterReplayStep(t.Context(), opts, storage, w, step, root)
		if len(fault.calls) < max(step.FaultAt, step.ExtraFaultAt) {
			t.Fatalf("unreached storage fault %+v: %v", step, fault.calls)
		}
		observation := observeWriterReplay(t, opts, root)
		observation.Calls = fault.calls
		if err != nil {
			observation.Error = err.Error()
		}
		result = append(result, observation)
	}
	return result
}

func applyWriterReplayStep(ctx context.Context, opts StreamWriterOptions, storage writerStorage, w *StreamWriter, step writerReplayStep, root *os.Root) (*StreamWriter, error) {
	if step.Op == "open" {
		if w != nil {
			return w, errors.New("writer is already open")
		}
		return openStreamWriter(ctx, opts, storage)
	}
	switch step.Op {
	case "drop":
		return nil, abandonWriterReplay(w)
	case "verify":
		return w, nil
	case "remove":
		return w, root.Remove(step.File)
	case "truncate":
		file, err := root.OpenFile(step.File, os.O_WRONLY, 0)
		if err != nil {
			return w, err
		}
		return w, errors.Join(file.Truncate(step.Keep), file.Close())
	}
	if w == nil {
		return nil, errors.New("writer is not open")
	}
	switch step.Op {
	case "close":
		return nil, w.Close(ctx, nil)
	case "rollover":
		return w, w.Rollover(ctx)
	case "action":
		return w, w.WriteAction(ctx, step.Action, PolicySnapshot{})
	default:
		return w, fmt.Errorf("unknown receipt replay operation %q", step.Op)
	}
}

func abandonWriterReplay(w *StreamWriter) error {
	if w == nil {
		return nil
	}
	var err error
	if w.active.file != nil {
		err = w.active.file.Close()
	}
	return errors.Join(err, w.lock.Close())
}

func observeWriterReplay(t *testing.T, opts StreamWriterOptions, root *os.Root) writerReplayObservation {
	t.Helper()
	entries, err := os.ReadDir(opts.Dir)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte)
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		data, err := root.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = data
	}
	settings := Options{Directory: true, Keys: []ed25519.PublicKey{opts.SigningKey.Public().(ed25519.PublicKey)}}
	result, err := VerifyPaths(t.Context(), []string{opts.Dir}, settings)
	observation := writerReplayObservation{Files: files, Verification: result}
	if err != nil {
		observation.VerifyError = err.Error()
	}
	return observation
}
