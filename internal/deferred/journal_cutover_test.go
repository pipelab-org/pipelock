// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestInspectJournalCutover(t *testing.T) {
	held := journalEntry{DeferID: "hold", State: StateHeld}
	releasing := held
	releasing.ReleasePending = true
	refusal := journalEntry{DeferID: held.DeferID, State: StateAdmissionRejected, RefusalPending: true}
	allow := journalEntry{DeferID: held.DeferID, State: StateResolvedAllow}
	rejected := journalEntry{DeferID: held.DeferID, State: StateAdmissionRejected}
	for _, tc := range []struct {
		name            string
		entries         []journalEntry
		suffix          string
		pending         int
		torn, delimiter bool
	}{
		{name: "empty"},
		{name: "duplicate audit preserves hold", entries: []journalEntry{held, rejected}, pending: 1},
		{name: "release in progress preserves hold", entries: []journalEntry{held, releasing}, pending: 1},
		{name: "refusal after release starts", entries: []journalEntry{held, releasing, refusal}, pending: 1},
		{name: "refusal after committed allow", entries: []journalEntry{held, allow, refusal}, pending: 1},
		{name: "committed allow", entries: []journalEntry{held, allow}},
		{name: "committed block", entries: []journalEntry{held, {DeferID: held.DeferID, State: StateResolvedBlock}}},
		{name: "committed step up", entries: []journalEntry{held, {DeferID: held.DeferID, State: StateResolvedStepUp}}},
		{name: "torn tail", entries: []journalEntry{held}, suffix: `{"state":`, pending: 1, torn: true},
		{name: "complete tail needs delimiter", entries: []journalEntry{held}, pending: 1, delimiter: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			canonical := cutoverJournalBytes(t, tc.entries)
			retained := canonical
			if tc.delimiter {
				retained = canonical[:len(canonical)-1]
			}
			source := append(bytes.Clone(retained), tc.suffix...)
			got, err := InspectJournalCutover(bytes.NewReader(source))
			want := JournalCutover{
				Digest: fmt.Sprintf("sha256:%x", sha256.Sum256(canonical)), KeepBytes: int64(len(retained)),
				Torn: tc.torn, NeedsDelimiter: tc.delimiter, Pending: tc.pending,
			}
			if err != nil || got != want {
				t.Fatalf("inspection = %+v, %v, want %+v", got, err, want)
			}
		})
	}
}

func TestInspectJournalCutoverRejectsInvalidEntries(t *testing.T) {
	held := journalEntry{DeferID: "hold", State: StateHeld}
	allow := journalEntry{DeferID: held.DeferID, State: StateResolvedAllow}
	for _, tc := range []struct {
		name         string
		entries      []journalEntry
		suffix, want string
	}{
		{name: "release on terminal", entries: []journalEntry{{DeferID: held.DeferID, State: StateResolvedAllow, ReleasePending: true}}, want: "release_pending on state"},
		{name: "release without hold", entries: []journalEntry{{DeferID: held.DeferID, State: StateHeld, ReleasePending: true}}, want: "release_pending without a prior hold"},
		{name: "refusal without allow", entries: []journalEntry{held, {DeferID: held.DeferID, State: StateAdmissionRejected, RefusalPending: true}}, want: "refusal_pending without a prior allow"},
		{name: "hold after terminal", entries: []journalEntry{held, allow, held}, want: "held entry after terminal state"},
		{name: "unknown state", entries: []journalEntry{{DeferID: held.DeferID, State: "unknown"}}, want: "unknown state"},
		{name: "malformed complete line", entries: []journalEntry{held}, suffix: "{\n", want: "parse defer journal for cutover"},
		{name: "invalid undelimited suffix", entries: []journalEntry{held}, suffix: "!", want: "parse defer journal for cutover"},
		{name: "oversized entry", suffix: strings.Repeat(" ", maxJournalLineBytes), want: "read defer journal for cutover"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := io.MultiReader(bytes.NewReader(cutoverJournalBytes(t, tc.entries)), strings.NewReader(tc.suffix))
			got, err := InspectJournalCutover(source)
			if err == nil || !strings.Contains(err.Error(), tc.want) || got != (JournalCutover{}) {
				t.Fatalf("inspection = %+v, %v, want no cutover and error containing %q", got, err, tc.want)
			}
		})
	}
}

func cutoverJournalBytes(t *testing.T, entries []journalEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	for _, entry := range entries {
		if err := encoder.Encode(entry); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}
