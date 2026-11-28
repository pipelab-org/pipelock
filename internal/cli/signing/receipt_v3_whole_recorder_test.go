// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestVerifyReceiptV3RefusesWholeRecorderOptions(t *testing.T) {
	for _, fixture := range []string{"g01-valid-line", "g01-damaged-first-line"} {
		t.Run(fixture, func(t *testing.T) {
			dir := filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "v3", fixture)
			for _, flag := range []string{"--whole-recorder", "--require-seal"} {
				t.Run(flag, func(t *testing.T) {
					cmd := VerifyReceiptCmd()
					cmd.SetArgs([]string{"--chain", dir, flag})
					err := cmd.Execute()
					if err == nil || cliutil.ExitCodeOf(err) != cliutil.ExitConfig ||
						!strings.Contains(err.Error(), flag+": receipt v3 has no whole-recorder proof in this release") ||
						!strings.Contains(err.Error(), "checking the log against that root is not offered yet") ||
						strings.Contains(err.Error(), "--expect-head") {
						t.Fatalf("unexpected error: %v", err)
					}
				})
			}
		})
	}
}

func TestReceiptRotationEndorseRefusesV3(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, dir, _ string) {
		output := filepath.Join(t.TempDir(), "endorsement.json")
		cmd := receiptRotationEndorseCmd(time.Now)
		cmd.SetArgs([]string{
			"--chain", dir, "--prior-key-file", "prior.key", "--new-key-file", "new.key",
			"--root-key", "root.pub", "--out", output,
		})
		testreceipt.RequiresV3Refusal(t, cmd.Execute(), "receipt rotation endorse", "legacy receipt rotation")
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatalf("refused rotation created output: %v", err)
		}
	})
}

func TestReceiptRotationEndorseRefusesV3InResolvedSubdir(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "location-a")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	testreceipt.V3(t, sub, false)
	if err := os.WriteFile(filepath.Join(sub, "evidence-proxy-0.jsonl"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "endorsement.json")
	cmd := receiptRotationEndorseCmd(time.Now)
	cmd.SetArgs([]string{
		"--chain", root, "--session", "proxy",
		"--prior-key-file", "prior.key", "--new-key-file", "new.key",
		"--root-key", "root.pub", "--out", output,
	})
	testreceipt.RequiresV3Refusal(t, cmd.Execute(), "receipt rotation endorse", "legacy receipt rotation")
}

// TestTranscriptRootRefusesV3 holds transcript-root to the same rule as the
// other legacy readers. A directory is v3 from the moment it holds a v3 file, so
// a legacy chain beside one must not print a root that silently omits the v3
// evidence.
func TestTranscriptRootRefusesV3(t *testing.T) {
	const command, reader = "transcript-root", "transcript root"
	_, pub := buildChainJSONL(t, 1)
	key := hex.EncodeToString(pub)
	run := func(t *testing.T, args ...string) (string, error) {
		t.Helper()
		var out bytes.Buffer
		cmd := TranscriptRootCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(append(args, "--key", key))
		err := cmd.Execute()
		return out.String(), err
	}
	mixedRoot := func(t *testing.T) (root, legacyKey string) {
		t.Helper()
		dir, legacyPub := buildRestartChainDir(t, 2, 1)
		// The v3 file is copied in: a v3 writer would refuse to cut over this
		// fixture chain, and the directory a reader meets is just the two sets.
		v3Path, _ := testreceipt.V3(t, t.TempDir(), false)
		data, err := os.ReadFile(filepath.Clean(v3Path))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(v3Path)), data, 0o600); err != nil {
			t.Fatal(err)
		}
		return dir, hex.EncodeToString(legacyPub)
	}

	testreceipt.EachV3(t, func(t *testing.T, dir, path string) {
		for _, args := range [][]string{{"--chain", dir}, {path}} {
			out, err := run(t, args...)
			testreceipt.RequiresV3Refusal(t, err, command, reader)
			if strings.Contains(out, "Transcript Root") {
				t.Fatalf("refused input printed a root: %s", out)
			}
		}
	})

	t.Run("legacy chain beside a v3 file", func(t *testing.T) {
		root, legacyKey := mixedRoot(t)
		var out bytes.Buffer
		cmd := TranscriptRootCmd()
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"--chain", root, "--key", legacyKey})
		testreceipt.RequiresV3Refusal(t, cmd.Execute(), command, reader)
		if strings.Contains(out.String(), "Transcript Root") {
			t.Fatalf("mixed directory printed a root: %s", out.String())
		}
	})

	t.Run("v3 file in the resolved location", func(t *testing.T) {
		root := t.TempDir()
		sub := filepath.Join(root, "location-a")
		if err := os.Mkdir(sub, 0o750); err != nil {
			t.Fatal(err)
		}
		mixed, legacyKey := mixedRoot(t)
		entries, err := os.ReadDir(mixed)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Clean(filepath.Join(mixed, entry.Name())))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(sub, entry.Name()), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cmd := TranscriptRootCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetArgs([]string{"--chain", root, "--key", legacyKey})
		testreceipt.RequiresV3Refusal(t, cmd.Execute(), command, reader)
	})

	t.Run("explicit location holding v3", func(t *testing.T) {
		root := t.TempDir()
		clean, _ := buildRestartChainDir(t, 2, 1)
		if err := os.Rename(clean, filepath.Join(root, "clean")); err != nil {
			t.Fatal(err)
		}
		mixed, mixedKey := mixedRoot(t)
		if err := os.Rename(mixed, filepath.Join(root, "mixed")); err != nil {
			t.Fatal(err)
		}
		cmd := TranscriptRootCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetArgs([]string{"--chain", root, "--location", "mixed", "--key", mixedKey})
		testreceipt.RequiresV3Refusal(t, cmd.Execute(), command, reader)
	})

	t.Run("v3 root with a legacy sub-location", func(t *testing.T) {
		root := t.TempDir()
		legacy, legacyKey := mixedRoot(t)
		// mixedRoot's directory holds a v3 file; keep only its legacy shards in
		// the sub-location so that only the root itself claims v3.
		sub := filepath.Join(root, "operational")
		if err := os.Mkdir(sub, 0o750); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(legacy)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.Contains(entry.Name(), ".receipt-v3.") {
				continue
			}
			data, err := os.ReadFile(filepath.Clean(filepath.Join(legacy, entry.Name())))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(sub, entry.Name()), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		v3Path, _ := testreceipt.V3(t, t.TempDir(), false)
		data, err := os.ReadFile(filepath.Clean(v3Path))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, filepath.Base(v3Path)), data, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := TranscriptRootCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetArgs([]string{"--chain", root, "--key", legacyKey})
		testreceipt.RequiresV3Refusal(t, cmd.Execute(), command, reader)
	})

	t.Run("missing path keeps the decoder error", func(t *testing.T) {
		_, err := run(t, filepath.Join(t.TempDir(), "missing.jsonl"))
		if err == nil || strings.Contains(err.Error(), "receipt v3") || !strings.Contains(err.Error(), "extracting receipts") {
			t.Fatalf("missing file: %v", err)
		}
	})
}
