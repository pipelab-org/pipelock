// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import "bytes"

// utf8BOM is the encoded U+FEFF byte order mark.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// newSSELineSplitter returns a bufio.SplitFunc that ends lines the way the
// event-stream format defines them, so the scanner sees the same events a
// conforming client does. Source: WHATWG HTML, "Parsing an event stream": a
// line ends at CRLF, at LF, or at a CR not followed by LF, and one leading
// U+FEFF byte order mark is ignored.
//
// bufio.ScanLines differs on both points: it does not end a line at a lone CR,
// and it keeps a leading BOM as part of the first field name. Either makes the
// reader's view of fields and event boundaries diverge from the client's.
func newSSELineSplitter() func(data []byte, atEOF bool) (int, []byte, error) {
	first := true
	pendingLF := false
	return func(data []byte, atEOF bool) (int, []byte, error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		skip := 0
		if first {
			if len(data) < len(utf8BOM) && !atEOF && bytes.HasPrefix(utf8BOM, data) {
				return 0, nil, nil // could still be a BOM; read more
			}
			first = false
			if bytes.HasPrefix(data, utf8BOM) {
				skip = len(utf8BOM)
			}
		}
		if pendingLF {
			pendingLF = false
			if len(data) > skip && data[skip] == '\n' {
				skip++
			}
		}
		rest := data[skip:]
		if len(rest) == 0 && skip > 0 {
			return skip, nil, nil
		}
		if i := bytes.IndexAny(rest, "\r\n"); i >= 0 {
			if rest[i] == '\n' {
				return skip + i + 1, rest[:i], nil
			}
			// Emit CR immediately; a following LF belongs to this line
			// ending even if it arrives in a later read.
			if i+1 < len(rest) && rest[i+1] == '\n' {
				return skip + i + 2, rest[:i], nil
			}
			if i+1 == len(rest) {
				pendingLF = true
			}
			return skip + i + 1, rest[:i], nil
		}
		if atEOF {
			return len(data), rest, nil
		}
		return skip, nil, nil
	}
}
