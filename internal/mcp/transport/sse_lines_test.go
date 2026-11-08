// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

// The reader must see the events a conforming client sees: lines end at CRLF,
// LF or a lone CR, and one leading byte order mark is ignored.
func TestSSEReaderLineEndingsMatchEventStreamFormat(t *testing.T) {
	const bom = "\xef\xbb\xbf"
	for _, tc := range []struct {
		name, in string
		want     []string
		wantType string
	}{
		{name: "lf", in: "data: a\n\ndata: b\n\n", want: []string{"a", "b"}},
		{name: "crlf", in: "data: a\r\n\r\ndata: b\r\n\r\n", want: []string{"a", "b"}},
		{name: "lone_cr", in: "data: a\r\rdata: b\r\r", want: []string{"a", "b"}},
		{name: "mixed", in: "data: a\r\ndata: b\rdata: c\n\n", want: []string{"a\nb\nc"}},
		{name: "comment_then_lone_cr", in: ": note\rdata: a\n\n", want: []string{"a"}},
		{name: "event_then_lone_cr", in: "event: x\rdata: a\n\n", want: []string{"a"}, wantType: "x"},
		{name: "cr_at_eof", in: "data: a\r", want: []string{"a"}},
		{name: "leading_bom", in: bom + "data: a\n\n", want: []string{"a"}},
		{name: "leading_bom_alone", in: bom + "\ndata: a\n\n", want: []string{"a"}},
		{name: "only_first_bom_ignored", in: bom + "data: a\n\n" + bom + "data: b\n\n", want: []string{"a"}},
		{name: "bom_inside_value_kept", in: "data: " + bom + "a\n\n", want: []string{bom + "a"}},
	} {
		for _, oneByte := range []bool{false, true} {
			name := tc.name
			if oneByte {
				name += "/one_byte_reads"
			}
			t.Run(name, func(t *testing.T) {
				var r io.Reader = strings.NewReader(tc.in)
				if oneByte {
					r = iotest.OneByteReader(r)
				}
				sr := NewSSEReader(r)
				var got []string
				for {
					msg, err := sr.ReadMessage()
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						t.Fatalf("ReadMessage: %v", err)
					}
					got = append(got, string(msg))
					if len(got) == 1 && sr.LastEventType() != tc.wantType {
						t.Fatalf("event type = %q, want %q", sr.LastEventType(), tc.wantType)
					}
				}
				if strings.Join(got, "|") != strings.Join(tc.want, "|") {
					t.Fatalf("events = %q, want %q", got, tc.want)
				}
			})
		}
	}
}

// A CR at the end of one read sets a pending-LF flag; the next read must clear
// it even when it does not start with LF. A stale flag would swallow the next
// real blank line, merging two events.
func TestSSELineSplitterClearsPendingLF(t *testing.T) {
	in := "data: a\rdata: b\n\ndata: c\n\n"
	sc := bufio.NewScanner(iotest.OneByteReader(strings.NewReader(in)))
	sc.Split(newSSELineSplitter())
	var got []string
	for sc.Scan() {
		got = append(got, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{"data: a", "data: b", "", "data: c", ""}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("lines = %q, want %q", got, want)
	}
}

func TestLineEndIndex(t *testing.T) {
	for in, want := range map[string]int{"": -1, "abc": -1, "a\nb": 1, "a\rb": 1, "ab\r\n": 2, "a\nb\r": 1, "\r": 0, "\n": 0} {
		if got := lineEndIndex([]byte(in)); got != want {
			t.Errorf("lineEndIndex(%q) = %d, want %d", in, got, want)
		}
	}
}
