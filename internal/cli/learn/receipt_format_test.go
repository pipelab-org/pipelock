// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestLearnRefusesV3BeforeWriting(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, dir, path string) {
		out := filepath.Join(dir, "receipts.jsonl")
		report := filepath.Join(t.TempDir(), "report.json")
		cmd := &cobra.Command{}
		_, compileErr := resolveCompileInputs(config.Defaults(), compileFlags{inputGlob: path})
		testreceipt.RequiresV3Refusal(t, compileErr, "learn compile", "contract inference")
		for _, tc := range []struct {
			name string
			err  error
		}{
			{"shadow", runShadow(cmd, shadowFlags{recorderDir: dir, outJSONPath: report})},
			{"ratify", runRatify(cmd, ratifyFlags{receiptOut: out})},
			{"forget", runForget(cmd, forgetFlags{receiptOut: out})},
			{"promote", runPromote(cmd, lifecycleFlags{receiptOut: out})},
			{"rollback", runRollback(cmd, lifecycleFlags{storeDir: dir})},
		} {
			testreceipt.RequiresV3Refusal(t, tc.err, "learn "+tc.name, "learn lifecycle receipts")
		}
		for _, p := range []string{out, report, filepath.Join(dir, defaultLifecycleReceiptOut)} {
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				t.Fatalf("refused command created %s: %v", p, err)
			}
		}
	})
}

func TestLearnReceiptWritesUseCeremonyLock(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux evidence directory locking")
	}
	dir := t.TempDir()
	lock, err := recorder.AcquireEvidenceCeremonyLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	called := false
	write := func() error {
		called = true
		return nil
	}
	out := filepath.Join(dir, "receipts.jsonl")
	if err := withLegacyReceiptOutput("learn ratify", out, "", write); err == nil || called || !strings.Contains(err.Error(), "receipt ceremonies") {
		t.Fatalf("write called=%t while ceremony held lock: %v", called, err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := withLegacyReceiptOutput("learn ratify", out, "", write); err != nil || !called {
		t.Fatalf("ordinary legacy write called=%t: %v", called, err)
	}
}

func TestLearnCompileAgentRefusesV3SessionDir(t *testing.T) {
	captureRoot := t.TempDir()
	v3Session := filepath.Join(captureRoot, "agent-a")
	legacySession := filepath.Join(captureRoot, "agent-a-legacy")
	if err := os.Mkdir(v3Session, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(legacySession, 0o750); err != nil {
		t.Fatal(err)
	}
	testreceipt.V3(t, v3Session, false)
	// Put a valid legacy capture entry in the sibling directory so skipping the
	// v3 session directory silently succeeds on the sibling.
	rec, err := recorder.New(recorder.Config{Dir: legacySession, Enabled: true}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Record(recorder.Entry{
		SessionID: "agent-a-legacy",
		Type:      capture.EntryTypeCapture,
		Detail:    []byte(`{"agent":"agent-a"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Learn.CaptureDir = captureRoot
	_, compileErr := resolveCompileInputs(cfg, compileFlags{agent: "agent-a", since: time.Hour})
	testreceipt.RequiresV3Refusal(t, compileErr, "learn compile", "contract inference")
}

func TestLearnCompileAgentRefusesNestedAndRenamedV3(t *testing.T) {
	for _, tc := range []struct {
		name, session string
		nested        bool
	}{
		{"nested exact session", "agent-a", true},
		{"nested prefixed session", "agent-a|example", true},
		{"renamed exact session", "agent-a", false},
		{"renamed prefixed session", "agent-a|example", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			session := filepath.Join(root, tc.session)
			if tc.nested {
				session = filepath.Join(session, "child")
			}
			if err := os.MkdirAll(session, 0o750); err != nil {
				t.Fatal(err)
			}
			path, _ := testreceipt.V3(t, session, false)
			if !tc.nested {
				if err := os.Rename(path, filepath.Join(session, "evidence-v3.jsonl")); err != nil {
					t.Fatal(err)
				}
			}
			_, err := resolveAgentCaptureInputs(root, "agent-a")
			testreceipt.RequiresV3Refusal(t, err, "learn compile", "contract inference")
		})
	}
}

func TestLearnReceiptOutputFormatAndLock(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux evidence directory locking")
	}
	for _, tc := range []struct {
		name        string
		output      string
		content     string
		missing     bool
		wantRefusal bool
	}{
		{"reserved name", "stream.receipt-v3.jsonl", "", false, true},
		{"renamed content", "custom.jsonl", "{\"payloadType\":\"application/vnd.pipelock.receipt.v3\"}\n", false, true},
		{"new directory", "ordinary.jsonl", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.missing {
				dir = filepath.Join(dir, "new")
			}
			output := filepath.Join(dir, tc.output)
			if tc.content != "" {
				if err := os.WriteFile(output, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			write := func() error {
				called = true
				lock, lockErr := recorder.AcquireEvidenceCeremonyLock(dir)
				if lockErr == nil {
					_ = lock.Close()
					t.Error("write ran without the ceremony lock")
				} else if !strings.Contains(lockErr.Error(), "still in use") {
					t.Errorf("cannot verify lock: %v", lockErr)
				}
				return nil
			}
			var err error
			if tc.missing {
				err = withLegacyReceiptDirectory("learn ratify", dir, write)
			} else {
				err = withLegacyReceiptOutput("learn ratify", output, "", write)
			}
			if tc.wantRefusal {
				testreceipt.RequiresV3Refusal(t, err, "learn ratify", "learn lifecycle receipts")
				if !strings.Contains(err.Error(), "pipelock verify-receipt --chain") {
					t.Fatalf("missing directory verifier guidance: %v", err)
				}
				if called {
					t.Fatal("write called for receipt profile")
				}
			} else if err != nil || !called {
				t.Fatalf("write called=%t, err=%v", called, err)
			}
		})
	}
}
