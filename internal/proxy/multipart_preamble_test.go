// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"testing"
)

// multipartPreamble must end exactly where Go's mime/multipart reader starts
// the first part or ends the form. Ending earlier would leave preamble bytes
// unchecked; ending later would treat a part's file as preamble.
func TestMultipartPreambleMatchesReader(t *testing.T) {
	skipped := "PK\x03\x04 stub\r\n" +
		"--Bx\r\n" + // a longer boundary is not a delimiter
		" --B\r\n" + // a delimiter starts the line
		"--B x\r\n" + // only space or tab may follow the boundary
		"--B--\n" + // CRLF mode: a final delimiter needs CRLF or EOF
		"--B--x\r\n"
	part := "--B \t\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nvalue\r\n--B--\r\n"
	for _, tc := range []struct {
		name, body, preamble string
		parts                int
	}{
		{"delimiter after near misses", skipped + part, skipped, 1},
		{"LF delimiter", "x\n--B\nContent-Disposition: form-data; name=\"a\"\n\nv\n--B--\n", "x\n", 1},
		{"final delimiter", skipped + "--B--\r\n", skipped, 0},
		{"final delimiter at EOF", skipped + "--B--", skipped, 0},
		{"no preamble", part, "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(multipartPreamble([]byte(tc.body), "B")); got != tc.preamble {
				t.Fatalf("preamble = %q, want %q", got, tc.preamble)
			}
			reader := multipart.NewReader(bytes.NewReader([]byte(tc.body)), "B")
			parts := 0
			for {
				p, err := reader.NextPart()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("reader: %v", err)
				}
				_ = p.Close()
				parts++
			}
			if parts != tc.parts {
				t.Fatalf("reader parts = %d, want %d", parts, tc.parts)
			}
		})
	}
}

// multipartEpilogue must start exactly where Go's mime/multipart reader stops.
// Bytes after the reader's final delimiter are never a part, and part bytes
// that only look like a final delimiter are never the epilogue.
func TestMultipartEpilogueMatchesReader(t *testing.T) {
	part := "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nvalue\r\n"
	for _, tc := range []struct {
		name, body, epilogue string
	}{
		{"after final delimiter", part + "--B--\r\ntrailing bytes", "trailing bytes"},
		{"final delimiter with space", part + "--B-- \t\r\ntrailing", "trailing"},
		{"LF form", "--B\nContent-Disposition: form-data; name=\"a\"\n\nv\n--B--\nafter", "after"},
		{"no parts", "preamble\r\n--B--\r\nafter", "after"},
		{"nothing after", part + "--B--", ""},
		{"bare LF final inside CRLF part", "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\n--B--extra\r\nmore\r\n--B--\r\nafter", "after"},
		{"bare LF final line inside CRLF part", "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\n--B--\r\nmore\r\n--B--\r\nafter", "after"},
		{"bare LF final inside CRLF part, no epilogue", "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\n--B--\r\nmore\r\n--B--\r\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			preamble := multipartPreamble([]byte(tc.body), "B")
			if got := string(multipartEpilogue([]byte(tc.body), "B", len(preamble))); got != tc.epilogue {
				t.Fatalf("epilogue = %q, want %q", got, tc.epilogue)
			}
			reader := multipart.NewReader(bytes.NewReader([]byte(tc.body)), "B")
			for {
				p, err := reader.NextPart()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("reader: %v", err)
				}
				data, err := io.ReadAll(p)
				if err != nil {
					t.Fatalf("reader: %v", err)
				}
				if tc.epilogue != "" && bytes.Contains(data, []byte(tc.epilogue)) {
					t.Fatalf("reader returned epilogue bytes in a part: %q", data)
				}
			}
		})
	}
}
