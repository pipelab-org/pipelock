// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package fileinspect

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"
)

func archiveFixture(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for name, data := range members {
		f, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestInspectArchive(t *testing.T) {
	plain := archiveFixture(t, map[string][]byte{"data.txt": []byte("ordinary text")})
	crc := bytes.Clone(plain)
	central := bytes.Index(crc, []byte("PK\x01\x02"))
	crc[central+16] ^= 1
	encrypted := bytes.Clone(plain)
	encrypted[central+8] |= 1
	method := bytes.Clone(plain)
	binary.LittleEndian.PutUint16(method[central+10:], 99)
	for _, tc := range []struct {
		name   string
		data   []byte
		limits Limits
		reason string
		kind   string
	}{
		{"text", []byte("hello"), Limits{4096, 8}, "", ""},
		{"PDF raw", []byte("%PDF-1.7 arbitrary"), Limits{4096, 8}, "", ""},
		{"zip", plain, Limits{4096, 8}, "", "ZIP"},
		{"empty", archiveFixture(t, nil), Limits{4096, 8}, "", "ZIP"},
		{"encrypted", encrypted, Limits{4096, 8}, "encrypted", "ZIP"},
		{"checksum", crc, Limits{4096, 8}, "checksum", "ZIP"},
		{"method", method, Limits{4096, 8}, "compression method", "ZIP"},
		{"trailer", plain[:len(plain)-1], Limits{4096, 8}, "trailer", "ZIP"},
		{"tail", append(bytes.Clone(plain), 'x'), Limits{4096, 8}, "trailer", "ZIP"},
		{"size", plain, Limits{12, 8}, "max_body_bytes", "ZIP"},
		{"bomb", archiveFixture(t, map[string][]byte{"data.txt": bytes.Repeat([]byte("a"), 8192)}), Limits{4096, 8}, "compression-ratio", "ZIP"},
		{"depth", archiveFixture(t, map[string][]byte{"nested.bin": plain}), Limits{4096, 1}, "depth", "ZIP"},
		{"invalid budget", plain, Limits{}, "budget", "ZIP"},
		{"7z", []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, Limits{4096, 8}, "no upload reader", "7z"},
		{"RAR4", []byte("Rar!\x1a\x07\x00"), Limits{4096, 8}, "no upload reader", "RAR"},
		{"RAR5", []byte("Rar!\x1a\x07\x01\x00"), Limits{4096, 8}, "no upload reader", "RAR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Inspect(t.Context(), tc.data, tc.limits)
			if r.Type != tc.kind {
				t.Fatalf("type %q want %q", r.Type, tc.kind)
			}
			if tc.kind == "" {
				if r.Recognized {
					t.Fatal("unexpected reader")
				}
				return
			}
			if (tc.reason == "") != r.Complete || (tc.reason != "" && !strings.Contains(r.Reason, tc.reason)) {
				t.Fatalf("complete=%t reason=%q want=%q", r.Complete, r.Reason, tc.reason)
			}
		})
	}
}

func TestInspectOfficeViews(t *testing.T) {
	secret := "AKIA" + "Q9W8E7R6T5Y4U3I2"
	for _, tc := range []struct {
		name, xml string
		image     bool
	}{
		{"word/document.xml", `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>AKIAQ9W8E7</w:t></w:r><w:r><w:t>R6T5Y4U3I2</w:t></w:r></w:p></w:body></w:document>`, false},
		{"ppt/notesSlides/notesSlide1.xml", `<a:p xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:r><a:t>` + secret + `</a:t></a:r></a:p>`, false},
		{"content.xml", `<text:p xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"><text:span>AKIAQ9W8E7</text:span><text:span>R6T5Y4U3I2</text:span></text:p>`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			members := map[string][]byte{tc.name: []byte(tc.xml)}
			if tc.image {
				members["Thumbnails/thumbnail.png"] = []byte("\x89PNG\r\n\x1a\n\xff")
			}
			data := archiveFixture(t, members)
			r := Inspect(t.Context(), data, Limits{4096, 64})
			if !r.Complete || !strings.Contains(strings.Join(r.Texts, "\n"), secret) {
				t.Fatalf("complete=%t reason=%q missing joined text", r.Complete, r.Reason)
			}
		})
	}
}

func TestInspectCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r := Inspect(ctx, archiveFixture(t, map[string][]byte{"x": []byte("a")}), Limits{4096, 64})
	if r.Complete || !strings.Contains(r.Reason, "canceled") {
		t.Fatalf("%+v", r)
	}
}
