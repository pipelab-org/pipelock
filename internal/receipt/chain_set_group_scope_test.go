// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// writeGateShard writes the first shard of a group-owned session: a sequence
// zero recorder file whose first entry is the group gate.
func writeGateShard(t *testing.T, dir, session string) {
	t.Helper()
	detail := json.RawMessage(`{"group_id":"` + "aa" + session[len(session)-30:] + `"}`)
	entry := recorder.Entry{
		Version: 1, Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), SessionID: session,
		Type: recorder.GroupGateEntryType, Transport: "mcp", Summary: "gate",
		PrevHash: recorder.GenesisHash, Detail: detail, RawDetail: detail,
	}
	entry.Hash = recorder.ComputeHash(entry)
	line, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	name := "evidence-" + session + "-0.jsonl"
	if err := os.WriteFile(filepath.Join(dir, name), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func verifyBaseWithGroupOpenedDuringReads(t *testing.T, session string) BaseReport {
	t.Helper()
	src := filepath.Join(walkConformanceTestdata, "run-chains", "valid")
	keys := corpusKeys(src)
	dir := copyShardDir(t, src)
	called := false
	prev := betweenVerificationReads
	betweenVerificationReads = func(d string) {
		if d == dir {
			called = true
			writeGateShard(t, dir, session)
		}
	}
	t.Cleanup(func() { betweenVerificationReads = prev })
	report, err := VerifyBase(dir, "proxy", BaseVerifyOptions{TrustedKeys: keys, ExcludeReceiptGroupSessions: true})
	if err != nil {
		t.Fatalf("VerifyBase: %v", err)
	}
	if !called {
		t.Fatal("seam after the reads was not reached")
	}
	return report
}

// A group another base opens during verification changes nothing the proxy
// report read, so it must not void the report.
func TestVerifyBaseIgnoresUnrelatedGroupOpenedDuringVerification(t *testing.T) {
	report := verifyBaseWithGroupOpenedDuringReads(t, "other.run.0123456789abcdef0123456789abcdef")
	if !report.Healthy() {
		t.Fatalf("an unrelated group voided the proxy report: %+v", report.Findings)
	}
}

// A group session of the base itself leaves its report, so the report is void.
func TestVerifyBaseRejectsOwnGroupOpenedDuringVerification(t *testing.T) {
	report := verifyBaseWithGroupOpenedDuringReads(t, "proxy.run.0123456789abcdef0123456789abcdef")
	if report.Healthy() {
		t.Fatal("a group opened for the base during verification left the report healthy")
	}
}

// The first recorder entry is the first non-blank line, so a leading blank
// line does not hide a group gate from the ordinary resolver.
func TestFirstGroupEvidenceEntrySkipsLeadingBlankLines(t *testing.T) {
	dir := t.TempDir()
	session := "other.run.0123456789abcdef0123456789abcdef"
	writeGateShard(t, dir, session)
	path := filepath.Join(dir, "evidence-"+session+"-0.jsonl")
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte("\n\n"), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	first, seen, err := firstGroupEvidenceEntry(path)
	if err != nil || !seen || first.Type != recorder.GroupGateEntryType {
		t.Fatalf("first entry = %+v seen=%t err=%v", first, seen, err)
	}
}
