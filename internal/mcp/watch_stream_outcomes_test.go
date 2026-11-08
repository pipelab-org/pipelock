// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func TestWatchLongSeparatedCredentialFloor(t *testing.T) {
	// Use the long carrier from TestProxy_ReloadConfiguredSeparatedPatterns to
	// exercise the shared decoder beyond its short-input path.
	encoded := base64.StdEncoding.EncodeToString([]byte(fakeAWSKey()))
	var carrier strings.Builder
	carrier.WriteString(strings.Repeat("a!", 4200))
	for _, c := range encoded {
		carrier.WriteRune(c)
		carrier.WriteByte('!')
	}
	for _, watch := range []bool{false, true} {
		for _, secret := range []bool{false, true} {
			opts := testOpts(testInputScanner(t))
			opts.WatchOnly = watch
			opts.InputCfg = &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock}
			value := "ordinary request"
			if secret {
				value = carrier.String()
			}
			msg, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "echo", "arguments": map[string]string{"value": value}}})
			if err != nil {
				t.Fatal(err)
			}
			result := scanHTTPInputDecision(msg, io.Discard, "session", "session", opts)
			refused := result.Blocked != nil || result.Synthetic != nil
			if refused != secret {
				t.Fatalf("watch=%t secret=%t blocked=%v synthetic=%v", watch, secret, result.Blocked, result.Synthetic)
			}
			if !secret && string(result.ForwardMessage) != string(msg) {
				t.Fatalf("ordinary request changed: %s", result.ForwardMessage)
			}
		}
	}
}

type watchMessageOnlyWriter struct{}

func (watchMessageOnlyWriter) WriteMessage([]byte) error {
	return errors.New("unexpected framed write")
}

func TestWatchStreamFailureOutcomes(t *testing.T) {
	sentinel := errors.New("write interrupted")
	for _, kind := range []string{"unsupported writer", "wrong chunk error", "kill", "identity", "receipt", "write", "short write", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			opts := testOpts(testInputScanner(t))
			opts.WatchOnly, opts.watchInbound = true, true
			output := &watchCoverageWriter{limit: -1}
			var writer transport.MessageWriter = &syncWriter{w: output}
			var firstErr error = &transport.UninspectedMessageChunkError{Final: true}
			message := []byte("complete response\n")
			var reader transport.MessageReader = &watchChunkReader{}
			switch kind {
			case "unsupported writer":
				writer = watchMessageOnlyWriter{}
			case "wrong chunk error":
				firstErr = io.ErrUnexpectedEOF
			case "kill":
				cfg := config.Defaults()
				cfg.KillSwitch.Enabled = true
				opts.KillSwitch = killswitch.New(cfg)
			case "identity":
				opts.ServerIdentityFn = func() ServerIdentity { return ServerIdentity{Refusal: "revoked"} }
			case "receipt":
				opts.RequireReceipts = true
			case "write":
				output.limit = 3
				output.err = sentinel
			case "short write":
				output.limit = 3
			case "truncated":
				firstErr = &transport.UninspectedMessageChunkError{}
				message = []byte(strings.Repeat("ordinary ", 100))
			}
			logs := watchCoverageExtraLogger(t, &opts)
			err := forwardWatchUninspected(message, firstErr, reader, writer, opts)
			if err == nil {
				t.Fatal("failed stream reported success")
			}
			switch kind {
			case "write":
				if !errors.Is(err, sentinel) || output.Len() != 3 {
					t.Fatalf("bytes=%d err=%v", output.Len(), err)
				}
			case "short write":
				if !errors.Is(err, io.ErrShortWrite) || output.Len() != 3 {
					t.Fatalf("bytes=%d err=%v", output.Len(), err)
				}
			case "truncated":
				if !errors.Is(err, io.EOF) || output.Len() >= len(message) {
					t.Fatalf("truncated tail released: bytes=%d err=%v", output.Len(), err)
				}
			default:
				if output.Len() != 0 {
					t.Fatalf("refused stream leaked %d bytes", output.Len())
				}
			}
			if output.Len() > len(message) || output.String() != string(message[:output.Len()]) {
				t.Fatalf("stream prefix changed: %q", output.String())
			}
			if (kind == "kill" || kind == "identity") && !strings.Contains(logs.String(), "watch_only_enforced") {
				t.Fatalf("missing refusal event: %s", logs.String())
			}
		})
	}
}
