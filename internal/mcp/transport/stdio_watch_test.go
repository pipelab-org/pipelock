// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestWatchStdioReaderLimit(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "enforce", true: "watch"}[enabled], func(t *testing.T) {
			wire := "  " + strings.Repeat("a", 10000) + "\r\nnext\n"
			r := NewWatchStdioReader(strings.NewReader(wire), func() bool { return enabled })
			r.limit = 128
			var out bytes.Buffer
			for {
				msg, err := r.ReadMessage()
				if errors.Is(err, io.EOF) {
					break
				}
				var chunk *UninspectedMessageChunkError
				if errors.As(err, &chunk) {
					out.Write(msg)
					continue
				}
				if err != nil {
					if enabled {
						t.Fatal(err)
					}
					return
				}
				out.Write(msg)
				out.WriteByte('\n')
			}
			if !enabled {
				t.Fatal("oversized message admitted while enforcing")
			}
			if out.String() != wire {
				t.Fatal("oversized message bytes changed")
			}
		})
	}
}
