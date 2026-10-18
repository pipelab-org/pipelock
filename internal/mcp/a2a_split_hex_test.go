// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestScanA2ABody_HexCredentialSplitAcrossStrings(t *testing.T) {
	sc := scanner.MustNew(config.Defaults())
	defer sc.Close()
	cfg := &config.A2AScanning{Enabled: true, Action: config.ActionWarn}
	h := hex.EncodeToString([]byte("AKIA" + "IOSFODNN7" + "EXAMPLQ"))
	a, b := h[:20], h[20:]
	cases := map[string]string{
		"text parts":      fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","messageId":"m","parts":[{"kind":"text","text":%q},{"kind":"text","text":%q}]}}}`, a, b),
		"metadata values": fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","messageId":"m","parts":[{"kind":"text","text":"hi"}],"metadata":{"a":%q,"b":%q}}}}`, a, b),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			r := scanA2ABody(context.Background(), []byte(body), sc, cfg, nil)
			if r.Clean || r.Action != config.ActionBlock {
				t.Fatalf("split hex credential must block under warn: clean=%v action=%q reason=%q", r.Clean, r.Action, r.Reason)
			}
		})
	}
}
