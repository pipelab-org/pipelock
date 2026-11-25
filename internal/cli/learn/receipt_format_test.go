// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

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
