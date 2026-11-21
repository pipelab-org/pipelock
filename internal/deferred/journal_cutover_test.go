// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"testing/iotest"
)

func TestInspectJournalCutover(t *testing.T) {
	const (
		held     = `{"defer_id":"call","state":"deferred_held"}` + "\n"
		rejected = `{"defer_id":"call","state":"admission_rejected"}` + "\n"
		release  = `{"defer_id":"call","state":"deferred_held","release_pending":true}` + "\n"
		refusal  = `{"defer_id":"call","state":"admission_rejected","refusal_pending":true}` + "\n"
		allow    = `{"defer_id":"call","state":"resolved_allow"}` + "\n"
		block    = `{"defer_id":"call","state":"resolved_block"}` + "\n"
		torn     = `{"defer_id":`
	)
	for _, tc := range []struct {
		name, journal, retained string
		pending                 int
		torn, delimiter         bool
	}{
		{name: "empty journal"},
		{name: "duplicate rejection keeps hold", journal: held + rejected, retained: held + rejected, pending: 1},
		{name: "release interrupted", journal: held + release + torn, retained: held + release, pending: 1, torn: true},
		{name: "refusal after pending release", journal: held + release + refusal, retained: held + release + refusal, pending: 1},
		{name: "refusal after committed allow", journal: held + allow + refusal, retained: held + allow + refusal, pending: 1},
		{name: "settled refusal without delimiter", journal: held + allow + refusal + strings.TrimSuffix(block, "\n"), retained: held + allow + refusal + block, delimiter: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := InspectJournalCutover(strings.NewReader(tc.journal))
			digest := sha256.Sum256([]byte(tc.retained))
			keep := int64(len(tc.retained))
			if tc.delimiter {
				keep--
			}
			want := JournalCutover{
				Digest: "sha256:" + hex.EncodeToString(digest[:]), KeepBytes: keep,
				Torn: tc.torn, NeedsDelimiter: tc.delimiter, Pending: tc.pending,
			}
			if err != nil || got != want {
				t.Fatalf("inspect = %+v, %v, want %+v", got, err, want)
			}
		})
	}

	for _, tc := range []struct{ name, journal, diagnostic string }{
		{"torn line with delimiter", held + torn + "\n", "parse defer journal"},
		{"invalid complete last entry", held + `{"defer_id":false}`, "parse defer journal"},
		{"refusal without allow", held + refusal, "refusal_pending without a prior allow"},
		{"release without hold", release, "release_pending without a prior hold"},
		{"release on terminal entry", `{"defer_id":"call","state":"resolved_allow","release_pending":true}`, "release_pending on state"},
		{"new hold after settlement", held + block + held, "held entry after terminal state"},
		{"unknown state", `{"defer_id":"call","state":"unknown"}`, "unknown state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := InspectJournalCutover(strings.NewReader(tc.journal))
			if err == nil || !strings.Contains(err.Error(), tc.diagnostic) || got != (JournalCutover{}) {
				t.Fatalf("inspect = %+v, %v, want %q and no inventory", got, err, tc.diagnostic)
			}
		})
	}

	t.Run("interrupted read", func(t *testing.T) {
		readErr := errors.New("journal read failed")
		got, err := InspectJournalCutover(iotest.ErrReader(readErr))
		if !errors.Is(err, readErr) || got != (JournalCutover{}) {
			t.Fatalf("inspect = %+v, %v, want read failure and no inventory", got, err)
		}
	})
}
