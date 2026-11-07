// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

type watchChunkReader struct{ chunks [][]byte }

func (r *watchChunkReader) ReadMessage() ([]byte, error) {
	if len(r.chunks) == 0 {
		return nil, io.EOF
	}
	chunk := r.chunks[0]
	r.chunks = r.chunks[1:]
	return chunk, &transport.UninspectedMessageChunkError{Final: len(r.chunks) == 0}
}

func TestWatchUninspectedMessage(t *testing.T) {
	for _, secret := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "split credential"}[secret], func(t *testing.T) {
			first, last := []byte(strings.Repeat("ordinary ", 100)), []byte("last\r\n")
			if secret {
				key := fakeAWSKey()
				first = append(first, key[:8]...)
				last = []byte(key[8:] + "\n")
			}
			reader := &watchChunkReader{chunks: [][]byte{last}}
			var out bytes.Buffer
			opts := testOpts(testInputScanner(t))
			opts.WatchOnly = true
			opts.watchInbound = !secret
			err := forwardWatchUninspected(first, &transport.UninspectedMessageChunkError{}, reader, transport.NewStdioWriter(&out), opts)
			if secret {
				if err == nil || strings.Contains(out.String(), fakeAWSKey()) {
					t.Fatalf("split floor escaped: %v", err)
				}
			} else if err != nil || !bytes.Equal(out.Bytes(), append(first, last...)) {
				t.Fatalf("message changed: %v", err)
			}
		})
	}
}
