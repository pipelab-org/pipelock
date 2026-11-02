// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestVerifyRecorderEnd(t *testing.T) {
	const fixtures = "../../../sdk/conformance/testdata/end-proof"
	for _, tc := range []struct {
		name   string
		proven bool
		broken bool
	}{
		{name: "v2-closed", proven: true},
		{name: "v2-tail-cut"},
		{name: "v2-no-checkpoint"},
		{name: "v2-bad-seal", broken: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries, err := recorder.ReadHistoryEntries(filepath.Join(fixtures, tc.name+".jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			// The fixture's action signer is independently pinned by the
			// shared manifest; use that same seeded signer here.
			keyData, err := os.ReadFile(filepath.Join(fixtures, "expect.json"))
			if err != nil {
				t.Fatal(err)
			}
			var manifest struct{ Key string }
			if err := json.Unmarshal(keyData, &manifest); err != nil {
				t.Fatal(err)
			}
			proven, err := VerifyRecorderEnd(entries, []string{manifest.Key})
			if proven != tc.proven || (err != nil) != tc.broken {
				t.Fatalf("proven=%v err=%v, want proven=%v broken=%v", proven, err, tc.proven, tc.broken)
			}
			if tc.broken && !strings.Contains(err.Error(), "transcript_root does not match") {
				t.Fatalf("wrong failure stage: %v", err)
			}
			if tc.proven {
				if unpinned, err := VerifyRecorderEnd(entries, nil); err != nil || !unpinned {
					t.Fatalf("structural mode must still authenticate the recorder against its declared signer: proven=%v err=%v", unpinned, err)
				}
				if wrongKey, err := VerifyRecorderEnd(entries, []string{strings.Repeat("0", 64)}); err == nil || wrongKey {
					t.Fatalf("wrong trusted key must fail: proven=%v err=%v", wrongKey, err)
				}
			}
		})
	}
}
