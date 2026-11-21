// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package command

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

const (
	streamID    = "11111111111111111111111111111111"
	receiptName = streamID + "-0000000000000000.receipt-v3.jsonl"
)

func TestDetectScope(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	claimedDir := filepath.Join("..", "..", "..", "..", "sdk", "conformance", "testdata", "v3", "g01-valid-line")
	for _, tc := range []struct {
		name    string
		flags   Flags
		paths   []string
		dir     string
		claim   bool
		errText string
	}{
		{name: "explicit file", flags: Flags{Format: "v3"}, paths: []string{"example.jsonl"}, claim: true},
		{name: "unsupported format", flags: Flags{Format: "v4"}, paths: []string{"example.jsonl"}, errText: "requires exactly one explicit file"},
		{name: "explicit directory", flags: Flags{Format: "v3"}, dir: dir, errText: "requires exactly one explicit file"},
		{name: "claimed file", paths: []string{receiptName}, claim: true},
		{name: "claimed directory", dir: claimedDir, claim: true},
		{name: "unclaimed directory", dir: dir},
		{name: "required directory", flags: Flags{DiskIndex: true}, dir: missing, errText: "evidence directory"},
		{name: "required file", flags: Flags{DiskIndex: true}, paths: []string{missing}, errText: "open evidence file"},
		{name: "options without evidence", flags: Flags{DiskIndex: true}, dir: dir, errText: "require v3 evidence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claim, err := tc.flags.Detect(tc.paths, tc.dir, SeqFlag{})
			if claim != tc.claim || (err == nil) != (tc.errText == "") || err != nil && !strings.Contains(err.Error(), tc.errText) {
				t.Fatalf("claim %t, error %v, want claim %t and error %q", claim, err, tc.claim, tc.errText)
			}
		})
	}
}

func TestSequenceFlag(t *testing.T) {
	var seq SeqFlag
	want := streamID + ":4"
	if err := seq.Set(want); err != nil || seq.String() != want || seq.Type() != "sequence" {
		t.Fatalf("v3 sequence: %q (%s), %v", seq.String(), seq.Type(), err)
	}
	if err := seq.Set(streamID + ":04"); err == nil {
		t.Fatal("accepted a noncanonical sequence")
	}
	if err := seq.Set("7"); err != nil || seq.String() != "7" || seq.Legacy != 7 || seq.V3 != "" {
		t.Fatalf("legacy sequence: %+v, %v", seq, err)
	}
	var flags Flags
	cmd := &cobra.Command{}
	flags.Bind(cmd)
	if err := cmd.ParseFlags([]string{
		"--format", "v3", "--expect-lineage", streamID,
		"--accept-discontinuity", "example", "--allow-partial-history", streamID, "--disk-index",
	}); err != nil {
		t.Fatal(err)
	}
	if flags.Format != "v3" || flags.Lineage != streamID || len(flags.Discontinuity) != 1 || len(flags.Partial) != 1 || !flags.DiskIndex {
		t.Fatalf("flags not bound: %+v", flags)
	}
}

type refusingWriter struct{}

func (refusingWriter) Write([]byte) (int, error) { return 0, iotest.ErrTimeout }

func TestRunRefusesInvalidOptions(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name    string
		in      Input
		errText string
	}{
		{"legacy option", Input{LegacyOptions: true}, "apply only to legacy evidence"},
		{"invalid key", Input{Keys: []string{"gg"}}, "decode public key"},
		{"invalid v3 head", Input{Directory: dir, Head: streamID + ":1:bad"}, "expected head must"},
		{"legacy head in directory", Input{Directory: dir, Head: "example"}, "require exactly one legacy chain"},
		{"legacy sequence in directory", Input{Directory: dir, SeqSet: true, Seq: SeqFlag{Legacy: 7}}, "require exactly one legacy chain"},
		{"invalid v3 sequence", Input{SeqSet: true}, "expected sequence must"},
		{"unreadable explicit path", Input{Paths: []string{filepath.Join(dir, receiptName)}}, "resolve evidence path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&out)
			cmd.SetContext(t.Context())
			err := (Flags{}).Run(cmd, tc.in)
			if err == nil || !strings.Contains(err.Error(), tc.errText) || out.Len() != 0 {
				t.Fatalf("error %v, output %q, want %q", err, out.String(), tc.errText)
			}
		})
	}
}

func TestRunReportsVerifierOutcome(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "sdk", "conformance", "testdata", "v3", "g01-valid-line", receiptName)
	in := Input{Paths: []string{path}, SeqSet: true, Seq: SeqFlag{V3: streamID + ":1"}}
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	cmd.SetOut(&out)
	if err := (Flags{}).Run(cmd, in); err == nil || err.Error() != "SELF-CONSISTENT ONLY" {
		t.Fatalf("unpinned error: %v", err)
	}
	var result v3.Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.ExitCode != 1 ||
		len(result.Accepted) != 1 || result.Accepted[0].Kind != "expect-seq" {
		t.Fatalf("result %+v, error %v", result, err)
	}
	in.AllowUnpinned = true
	in.Head = streamID + ":1:" + result.Histories[0].Streams[0].Tip.Record
	cmd.SetOut(refusingWriter{})
	if err := (Flags{}).Run(cmd, in); !errors.Is(err, iotest.ErrTimeout) {
		t.Fatalf("output failure: %v", err)
	}
	cmd.SetOut(&out)
	out.Reset()
	if err := (Flags{}).Run(cmd, in); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.ExitCode != 0 {
		t.Fatalf("result %+v, error %v", result, err)
	}
}
