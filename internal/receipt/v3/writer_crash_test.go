// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
)

const (
	crashModeKey      = "PIPELOCK_RECEIPT_CRASH_MODE"
	crashDirKey       = "PIPELOCK_RECEIPT_CRASH_DIR"
	crashEndpointKey  = "PIPELOCK_RECEIPT_CRASH_ENDPOINT"
	crashProcessExit  = 71
	crashBeforeEffect = "confirmed-intent"
	crashBeforeRepair = "failed-intent"
	crashBeforeName   = "unflushed-name"
	crashControl      = "control"
)

func TestReceiptWriterCrashChild(t *testing.T) {
	mode := os.Getenv(crashModeKey)
	if mode == "" {
		return
	}
	opts := writerTestOptions(os.Getenv(crashDirKey))
	storage := localWriterStorage()
	if mode == crashBeforeName {
		realSync := storage.syncDir
		storage.syncDir = func(path string) error {
			if path == opts.Dir {
				os.Exit(crashProcessExit)
			}
			return realSync(path)
		}
	}
	w, err := openStreamWriter(t.Context(), opts, storage)
	if err != nil {
		t.Fatal(err)
	}
	if mode == crashBeforeName {
		t.Fatal("directory flush checkpoint was skipped")
	}

	syncFault := errors.New("injected flush failure")
	if mode == crashBeforeRepair {
		w.active.file = errorWriterFile{writerFile: w.active.file, syncErr: syncFault}
		w.storage.createTemp = func(string, string) (writerFile, error) {
			os.Exit(crashProcessExit)
			return nil, nil
		}
	}
	intent := writerTestIntent("request")
	policy := CapturePolicy(Digest([]byte("fixture snapshot")))
	err = w.WriteAction(t.Context(), intent, policy)
	if mode == crashBeforeRepair && errors.Is(err, syncFault) {
		os.Exit(crashProcessExit)
	}
	if err != nil {
		t.Fatal(err)
	}
	if mode == crashBeforeEffect {
		os.Exit(crashProcessExit)
	}
	if mode != crashControl {
		t.Fatalf("unexpected crash checkpoint %q", mode)
	}
	server := os.Getenv(crashEndpointKey)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req) //nolint:gosec // Controlled loopback endpoint from the parent test.
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	outcome := intent
	outcome.Phase, outcome.EffectRelation, outcome.OutcomeClass = phaseOutcome, relationAfter, "completed"
	if err := w.WriteAction(t.Context(), outcome, policy); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestStreamWriterCrashAndPowerLoss(t *testing.T) {
	const (
		keep = "keep"
		lose = "lose"
	)
	for _, tc := range []struct {
		name, mode, storage, state string
		hits                       int64
	}{
		{"control", crashControl, keep, "completed", 1},
		{"kill between flush and effect", crashBeforeEffect, keep, "outcome_unknown", 0},
		{"kill after failed flush, keep bytes", crashBeforeRepair, keep, "outcome_unknown", 0},
		{"kill after failed flush, lose bytes", crashBeforeRepair, lose, "", 0},
		{"keep new name at power loss", crashBeforeName, keep, "", 0},
		{"lose new name at power loss", crashBeforeName, lose, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var hits atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(upstream.Close)
			runWriterCrashChild(t, dir, tc.mode, upstream.URL)
			if got := hits.Load(); got != tc.hits {
				t.Fatalf("upstream observed %d effects, want %d", got, tc.hits)
			}
			if tc.storage == lose {
				simulateWriterPowerLoss(t, dir, tc.mode)
			}
			opts := writerTestOptions(dir)
			for range 2 {
				w := requireWriter(t, opts, localWriterStorage())
				if w.active.confirmed.Seq != 0 {
					t.Fatal("restart fabricated an outcome")
				}
				if err := w.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
			}
			result := verifyWritten(t, dir, opts.SigningKey.Public().(ed25519.PublicKey))
			if tc.state != "" {
				if writerTestCount(t, result, tc.state) != 1 {
					t.Fatalf("decision did not verify as %q: %+v", tc.state, result)
				}
			} else if result.Counts.Decisions == nil || len(*result.Counts.Decisions) != 0 {
				t.Fatalf("a lost or unwritten intent changed the decision history: %+v", result)
			}
		})
	}
}

func runWriterCrashChild(t *testing.T, dir, mode, endpoint string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestReceiptWriterCrashChild$") //nolint:gosec // Re-executes this test binary.
	cmd.Env = append(os.Environ(), crashModeKey+"="+mode, crashDirKey+"="+dir, crashEndpointKey+"="+endpoint)
	out, err := cmd.CombinedOutput()
	if mode == crashControl {
		if err != nil {
			t.Fatalf("writer control process: %v\n%s", err, out)
		}
		return
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != crashProcessExit {
		t.Fatalf("writer did not reach crash point: %v\n%s", err, out)
	}
}

func simulateWriterPowerLoss(t *testing.T, dir, mode string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*"+layoutFileSuffix))
	if err != nil || len(files) != 1 {
		t.Fatalf("expected one stream file, got %v, %v", files, err)
	}
	if mode == crashBeforeName {
		if err := os.Remove(files[0]); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(filepath.Clean(files[0]))
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.IndexByte(data, '\n')
	if at < 0 {
		t.Fatal("no complete opening record")
	}
	if err := os.Truncate(files[0], int64(at+1)); err != nil {
		t.Fatal(err)
	}
}
