// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package evidencename

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

func TestReceiptProfileVersion(t *testing.T) {
	for name, want := range map[string]string{
		"s.receipt-v3.jsonl":     "3",
		"s.receipt-v4.jsonl":     "4",
		"s.receipt-v0012.jsonl":  "0012",
		"s.receipt-v3.jsonl.bak": "",
		"s.receipt-v.jsonl":      "",
		"receipt-v3.jsonl":       "",
		"evidence-a-0.jsonl":     "",
	} {
		got, ok := ReceiptProfileVersion(name)
		if got != want || ok != (want != "") {
			t.Errorf("ReceiptProfileVersion(%q) = %q, %t; want %q", name, got, ok, want)
		}
	}
}

func TestClaimsReceiptContent(t *testing.T) {
	if !ClaimsReceiptContent([]byte(" \t\n" + ReceiptProfilePrefix + "v3+json\"}")) {
		t.Error("profile prefix not claimed")
	}
	for _, data := range []string{"", "{\"v\":1}"} {
		if ClaimsReceiptContent([]byte(data)) {
			t.Errorf("ClaimsReceiptContent(%q) = true", data)
		}
	}
}

func TestCutoverInventoryHash(t *testing.T) {
	hash := strings.Repeat("0f", 32)
	if got, ok := CutoverInventoryHash("receipt-v3-cutover-" + hash + ".json"); !ok || got != hash {
		t.Errorf("valid inventory = %q, %t", got, ok)
	}
	for _, name := range []string{
		"receipt-v3-cutover-" + hash + ".jsonl",
		"receipt-v3-cutover-" + strings.ToUpper(hash) + ".json",
		"receipt-v3-cutover-" + hash[:62] + ".json",
		"receipt-v3-cutover-.json",
		hash + ".json",
	} {
		if _, ok := CutoverInventoryHash(name); ok {
			t.Errorf("CutoverInventoryHash(%q) accepted", name)
		}
	}
}

func TestIsLegacyReceiptCandidate(t *testing.T) {
	for name, want := range map[string]bool{
		"evidence-proxy-0.jsonl":      true,
		"receipt-group-a.json":        true,
		"activation-receipts.jsonl":   true,
		"redaction-receipts.jsonl":    true,
		"ratification-receipts.jsonl": true,
		"evidence-v3.jsonl":           false,
		"notes.txt":                   false,
		"receipt-group-a.jsonl":       false,
	} {
		if got := IsLegacyReceiptCandidate(name); got != want {
			t.Errorf("IsLegacyReceiptCandidate(%q) = %t, want %t", name, got, want)
		}
	}
}

func TestProbeReceiptContentWhitespaceLimit(t *testing.T) {
	const limit = 64 << 10
	for _, tc := range []struct {
		name, whitespace string
		want             bool
	}{
		{"at limit", strings.Repeat(" ", limit), true},
		{"past limit", strings.Repeat(" ", limit+1), false},
		{"unicode past byte limit", strings.Repeat("\u2002", limit/3+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claimed, err := ProbeReceiptContent(strings.NewReader(tc.whitespace + ReceiptProfilePrefix))
			if err != nil || claimed != tc.want {
				t.Fatalf("claimed=%t, err=%v, want %t", claimed, err, tc.want)
			}
		})
	}
	const size = 1 << 20
	r := strings.NewReader(strings.Repeat(" ", size))
	claimed, err := ProbeReceiptContent(r)
	if err != nil || claimed || size-r.Len() > limit+len(ReceiptProfilePrefix) {
		t.Fatalf("claimed=%t, err=%v, read %d bytes; want a bounded negative probe", claimed, err, size-r.Len())
	}
}

func TestReceiptProfileEntryIgnoresDirectories(t *testing.T) {
	dir := t.TempDir()
	const name = "empty.receipt-v3.jsonl"
	if err := os.Mkdir(filepath.Join(dir, name), 0o750); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := ReceiptProfileEntry(entries); got != "" {
		t.Fatalf("directory claimed its parent as %q", got)
	}
}

func TestProbeReceiptContentErrorsAndShortInput(t *testing.T) {
	readErr := errors.New("profile prefix read failed")
	for _, tc := range []struct {
		name  string
		input io.Reader
		want  bool
		err   error
	}{
		{"envelope", strings.NewReader(ReceiptProfilePrefix + "v3+json"), true, nil},
		{"legacy", strings.NewReader(strings.Repeat("x", len(ReceiptProfilePrefix))), false, nil},
		{"partial", strings.NewReader(ReceiptProfilePrefix[:len(ReceiptProfilePrefix)-1]), false, nil},
		{"empty", strings.NewReader(""), false, nil},
		{"read error", iotest.ErrReader(readErr), false, readErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ProbeReceiptContent(tc.input)
			if got != tc.want || !errors.Is(err, tc.err) {
				t.Fatalf("got (%v, %v), want (%v, %v)", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestRefuseReceiptNameNormalizesPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stream.receipt-v3.jsonl") + string(filepath.Separator) + "."
	if err := RefuseReceiptName(path); !errors.Is(err, ErrReceiptProfile) {
		t.Fatalf("RefuseReceiptName(%q) = %v, want receipt refusal", path, err)
	}
}
