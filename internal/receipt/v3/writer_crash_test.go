// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

const (
	crashModeKey            = "PIPELOCK_RECEIPT_CRASH_MODE"
	crashDirKey             = "PIPELOCK_RECEIPT_CRASH_DIR"
	crashEndpointKey        = "PIPELOCK_RECEIPT_CRASH_ENDPOINT"
	crashProcessExit        = 71
	crashBeforeEffect       = "confirmed-intent"
	crashBeforeRepair       = "failed-intent"
	crashBeforeOutcomeFlush = "observed-unconfirmed-outcome"
	crashBeforeName         = "unflushed-name"
	crashControl            = "control"
)

func TestReceiptWriterCrashChild(t *testing.T) {
	mode := os.Getenv(crashModeKey)
	if mode == "" {
		return
	}
	dir, err := filepath.Abs(os.Getenv(crashDirKey))
	if err != nil {
		t.Fatal(err)
	}
	opts := writerTestOptions(dir)
	opts.Heartbeat = 0
	if mode == crashBeforeOutcomeFlush {
		long := time.Hour
		opts.idleFlushDelay = &long
	}
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
	if w.stopHeartbeat != nil {
		t.Fatal("heartbeat can consume the crash checkpoint fault")
	}

	var intentFlushed bool
	if mode == crashBeforeEffect {
		w.active.file = observedCrashSync{StreamFile: w.active.file, flushed: &intentFlushed}
	}
	syncFault := errors.New("injected flush failure")
	if mode == crashBeforeRepair {
		w.active.file = errorWriterFile{StreamFile: w.active.file, syncErr: syncFault}
		w.storage.createTemp = func(string, string) (StreamFile, error) {
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
		if !intentFlushed {
			t.Fatal("intent returned before the file was flushed")
		}
		os.Exit(crashProcessExit)
	}
	if mode != crashControl && mode != crashBeforeOutcomeFlush {
		t.Fatalf("unexpected crash checkpoint %q", mode)
	}
	endpoint, err := netip.ParseAddrPort(os.Getenv(crashEndpointKey))
	if err != nil || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 {
		t.Fatal("expected a loopback crash-test endpoint")
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+endpoint.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected crash-test response status %d", res.StatusCode)
	}
	if mode == crashBeforeOutcomeFlush {
		token := &EffectToken{gate: NewEffectGate(w), actions: []Action{intent}, policy: policy}
		if err := token.ConfirmDelivery(t.Context(), func() (bool, error) { return true, nil }); err != nil {
			t.Fatal(err)
		}
		w.gate <- struct{}{}
		queued := w.active.appended.Seq == 2 && w.active.confirmed.Seq == 1
		w.release()
		if !queued {
			t.Fatal("observed outcome was not acknowledged as an unconfirmed append")
		}
		os.Exit(crashProcessExit)
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

type observedCrashSync struct {
	StreamFile
	flushed *bool
}

func (f observedCrashSync) Sync() error {
	if err := f.StreamFile.Sync(); err != nil {
		return err
	}
	*f.flushed = true
	return nil
}

func TestStreamWriterCrashAndPowerLoss(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const (
		keep = "keep"
		lose = "lose"
	)
	for _, tc := range []struct {
		name, mode, storage, state string
		hits                       int64
	}{
		{"control", crashControl, keep, "completed", 1},
		{"observed outcome survives", crashBeforeOutcomeFlush, keep, "completed", 1},
		{"observed outcome lost", crashBeforeOutcomeFlush, lose, "outcome_unknown", 1},
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
			runWriterCrashChild(t, executable, dir, tc.mode, upstream.Listener.Addr().String())
			if got := hits.Load(); got != tc.hits {
				t.Fatalf("upstream observed %d effects, want %d", got, tc.hits)
			}
			var opening string
			if tc.mode == crashBeforeName {
				files, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, file := range files {
					if segment, ok := identify(file.Name()); ok && segment.start == 0 {
						if opening != "" {
							t.Fatal("crash left more than one opening record")
						}
						opening = segment.stream
					}
				}
				if opening == "" {
					t.Fatal("crash did not reach the published opening record")
				}
			}
			if tc.storage == lose {
				simulateWriterPowerLoss(t, dir, tc.mode)
			}
			opts := writerTestOptions(dir)
			var firstRestart string
			for restart := range 2 {
				w := requireWriter(t, opts, localWriterStorage())
				if restart == 0 {
					firstRestart = w.active.id
				}
				if w.active.confirmed.Seq != 0 {
					t.Fatal("restart fabricated an outcome")
				}
				if err := w.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
			}
			result := verifyWritten(t, dir, opts.SigningKey.Public().(ed25519.PublicKey))
			if opening != "" {
				var wantPrevious string
				if tc.storage == keep {
					wantPrevious = opening
				}
				var first StreamResult
				for _, stream := range result.Histories[0].Streams {
					if stream.Stream == firstRestart {
						first = stream
					}
				}
				if first.Stream == "" || first.Stream == opening || first.Previous != wantPrevious {
					t.Fatalf("first restart = %+v, want a new stream with predecessor %q", first, wantPrevious)
				}
			}
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

func runWriterCrashChild(t *testing.T, executable, dir, mode, endpoint string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestReceiptWriterCrashChild$")
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
	if mode == crashBeforeOutcomeFlush {
		next := bytes.IndexByte(data[at+1:], '\n')
		if next < 0 {
			t.Fatal("no complete intent record")
		}
		at += next + 1
	}
	if err := os.Truncate(files[0], int64(at+1)); err != nil {
		t.Fatal(err)
	}
}
