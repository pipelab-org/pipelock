// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestProfileFilenameVersion(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]string{
		"evidence-proxy-0.jsonl":             "",
		"evidence-proxy-0.receipt-v3.jsonl":  "3",
		"evidence-proxy-0.receipt-v40.jsonl": "40",
	} {
		if got := ProfileFilenameVersion(name); got != want {
			t.Errorf("ProfileFilenameVersion(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestHasProfileEnvelope(t *testing.T) {
	t.Parallel()
	readErr := errors.New("profile prefix read failed")
	for _, tc := range []struct {
		name string
		in   io.Reader
		want bool
		err  error
	}{
		{name: "envelope", in: strings.NewReader(ProfileEnvelopePrefix + "v3+json"), want: true},
		{name: "legacy", in: strings.NewReader(strings.Repeat("x", len(ProfileEnvelopePrefix)))},
		{name: "partial", in: strings.NewReader(ProfileEnvelopePrefix[:len(ProfileEnvelopePrefix)-1])},
		{name: "empty", in: strings.NewReader("")},
		{name: "read error", in: iotest.ErrReader(readErr), err: readErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := HasProfileEnvelope(tc.in)
			if got != tc.want || !errors.Is(err, tc.err) {
				t.Fatalf("HasProfileEnvelope = (%v, %v), want (%v, %v)", got, err, tc.want, tc.err)
			}
		})
	}
}
