// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package fileinspect

import (
	"bytes"
	"strings"
	"testing"
)

// Readers accept data before an archive: Info-ZIP unzip, Python zipfile, Go
// archive/zip and libarchive extract a stub followed by a ZIP, and unzip also
// extracts one followed by trailing data past the end-record search window.
func TestKindPrefixedArchive(t *testing.T) {
	archive := archiveFixture(t, map[string][]byte{"note.txt": []byte("AKIA" + "Q9W8E7R6T5Y4U3I2")})
	stub := []byte("#!/bin/sh\nexit 0\n")
	prefixed := append(bytes.Clone(stub), archive...)
	empty := append(bytes.Clone(stub), "PK\x05\x06"+strings.Repeat("\x00", 18)...)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"stub", prefixed},
		{"stub and trailing data", append(bytes.Clone(prefixed), make([]byte, 70000)...)},
		{"local header only", append(bytes.Clone(stub), archive[:bytes.Index(archive, []byte("PK\x01\x02"))]...)},
		{"end record only", empty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Kind(tc.data); got != "ZIP" {
				t.Fatalf("Kind = %q, want ZIP", got)
			}
			r := Inspect(t.Context(), tc.data, Limits{1 << 20, 64})
			if !r.Recognized || r.Complete || r.Reason == "" {
				t.Fatalf("recognized=%t complete=%t reason=%q", r.Recognized, r.Complete, r.Reason)
			}
		})
	}
	// An end record is searched for only in the final 65535+22 bytes.
	far := append([]byte("xPK\x05\x06"), make([]byte, 65535+22)...)
	if got := Kind(far); got != "" {
		t.Fatalf("end record outside the comment bound: Kind = %q", got)
	}
	for _, data := range [][]byte{[]byte("ordinary text"), []byte("\x89PNG\r\n\x1a\nIDAT")} {
		if got := Kind(data); got != "" {
			t.Fatalf("Kind(%q) = %q", data, got)
		}
	}
	// No tested 7z or RAR reader opens an archive behind a stub that is not an
	// executable, so those signatures are recognized only at the start.
	if got := Kind(append(bytes.Clone(stub), '7', 'z', 0xbc, 0xaf, 0x27, 0x1c)); got != "" {
		t.Fatalf("prefixed 7z: Kind = %q", got)
	}
}

// A published signature at offset zero says nothing about the bytes after it.
// Archive signatures inside an accepted image leave the member unread.
func TestInspectBinaryMemberEmbeddedArchive(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	clean := archiveFixture(t, map[string][]byte{"word/media/image1.png": png})
	if r := Inspect(t.Context(), clean, Limits{1 << 20, 64}); !r.Complete {
		t.Fatalf("clean PNG member: %s", r.Reason)
	}
	pad := make([]byte, 65535+22)
	for _, tc := range []struct {
		name     string
		appended []byte
	}{
		{"local header", []byte("PK\x03\x04")},
		{"end record", append([]byte("PK\x05\x06"), make([]byte, 18)...)},
		{"end record outside the search window", append(append([]byte("PK\x05\x06"), make([]byte, 18)...), pad...)},
		{"7z", []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}},
		{"RAR 4", []byte("Rar!\x1a\x07\x00")},
		{"RAR 5", []byte("Rar!\x1a\x07\x01\x00")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			member := append(bytes.Clone(png), tc.appended...)
			r := Inspect(t.Context(), archiveFixture(t, map[string][]byte{"word/media/image1.png": member}), Limits{1 << 20, 64})
			if r.Complete || r.Reason == "" {
				t.Fatalf("complete=%t reason=%q", r.Complete, r.Reason)
			}
		})
	}
}
