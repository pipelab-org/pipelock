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
	"slices"
	"sync"
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
	mu                sync.Mutex
	step              writerReplayStep
	calls             []string
	additionalFaultAt int
}

var errWriterReplay = errors.New("injected receipt storage error")

func (f *writerReplayFault) reset(step writerReplayStep, additional int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.step, f.additionalFaultAt, f.calls = step, additional, nil
}

func (f *writerReplayFault) failNext() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.additionalFaultAt = len(f.calls) + 1
}

func (f *writerReplayFault) operations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *writerReplayFault) trip(operation string) (failed bool, landing string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, operation)
	count := len(f.calls)
	return f.step.FaultAt == count || f.step.ExtraFaultAt == count || f.additionalFaultAt == count, f.step.Landing
}

func (f *writerReplayFault) call(operation string, fn func() error) error {
	if failed, _ := f.trip(operation); failed {
		return errWriterReplay
	}
	return fn()
}

type writerReplayFile struct {
	StreamFile
	fault *writerReplayFault
}

func (f writerReplayFile) Write(data []byte) (int, error) {
	failed, landing := f.fault.trip(replayWrite)
	if !failed {
		return f.StreamFile.Write(data)
	}
	switch landing {
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
// one observation array per input. FaultAt and ExtraFaultAt are one-based
// positions in Calls: writes, file syncs, links, renames, file re-flushes, and
// evidence directory syncs. Temporary file creation and ancestor directory
// syncs are uncounted. Truncate and remove select what survives a crash.
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
	out, err := openWriterReplayOutput(in, os.Getenv("PIPELOCK_RECEIPT_REPLAY_OUTPUT"))
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

func openWriterReplayOutput(in *os.File, path string) (_ *os.File, err error) {
	input, err := in.Stat()
	if err != nil {
		return nil, err
	}
	out, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, out.Close())
		}
	}()
	output, err := out.Stat()
	if err != nil {
		return nil, err
	}
	if os.SameFile(input, output) {
		return nil, errors.New("receipt replay output refers to its input")
	}
	if err := out.Truncate(0); err != nil {
		return nil, err
	}
	return out, nil
}

func TestStreamWriterReplayRejectsInputAsOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "replay.jsonl")
	const replay = "[]\n"
	if err := os.WriteFile(path, []byte(replay), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias.jsonl")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	for _, output := range []string{path, alias} {
		out, err := openWriterReplayOutput(in, output)
		if err == nil {
			_ = out.Close()
			t.Errorf("replay accepted %q as output", filepath.Base(output))
		}
	}
	remaining, err := io.ReadAll(in)
	if err != nil || string(remaining) != replay {
		t.Fatalf("input contents = %q, error = %v", remaining, err)
	}
}

func runWriterReplay(t *testing.T, base string, steps []writerReplayStep) []writerReplayObservation {
	t.Helper()
	base, err := filepath.Abs(base)
	if err != nil {
		t.Fatal(err)
	}
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
		fault.reset(step, 0)
		w, err = applyWriterReplayStep(t.Context(), opts, storage, w, step, root)
		calls := fault.operations()
		if len(calls) < max(step.FaultAt, step.ExtraFaultAt) {
			t.Fatalf("unreached storage fault %+v: %v", step, calls)
		}
		observation := observeWriterReplay(t, opts, root)
		observation.Calls = calls
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
	w.closeOnce.Do(func() {
		close(w.closeRequested)
		if w.stopHeartbeat != nil {
			w.stopHeartbeat()
		}
		close(w.flushStop)
		<-w.flushDone
		var err error
		if w.active.file != nil {
			err = w.active.file.Close()
		}
		w.closeErr = errors.Join(err, w.lock.Close())
		close(w.closeDone)
	})
	return w.closeErr
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
