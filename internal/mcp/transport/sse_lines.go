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
		rest := data[skip:]
		if i := bytes.IndexAny(rest, "\r\n"); i >= 0 {
			if rest[i] == '\n' {
				return skip + i + 1, rest[:i], nil
			}
			// CR: a CRLF pair is one line end, so wait for the next byte
			// unless the stream has ended.
			if i+1 < len(rest) {
				if rest[i+1] == '\n' {
					return skip + i + 2, rest[:i], nil
				}
				return skip + i + 1, rest[:i], nil
			}
			if atEOF {
				return skip + i + 1, rest[:i], nil
			}
			// Keep the BOM decision: consume it now so it is not
			// re-examined, then ask for more data.
			return skip, nil, nil
		}
		if atEOF {
			return len(data), rest, nil
		}
		return skip, nil, nil
	}
}
