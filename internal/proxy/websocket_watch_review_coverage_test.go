// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/gobwas/ws"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

type watchReviewAccessReader struct {
	source *strings.Reader
	change func()
}

func (r *watchReviewAccessReader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	r.change()
	return n, err
}

func TestWatchWebSocketAccessChangesDuringRead(t *testing.T) {
	for _, kind := range []string{"identity", "kill"} {
		t.Run(kind, func(t *testing.T) {
			relay := watchReviewRelay(t, nil)
			relay.proxy.ks = killswitch.New(relay.cfg)
			reader := &watchFrameReader{relay: relay, Reader: &watchReviewAccessReader{source: strings.NewReader("undelivered"), change: func() {
				if kind == "kill" {
					relay.proxy.ks.SetAPI(true)
				} else {
					next := *relay.cfg
					next.DefaultAgentIdentity = "new-agent"
					relay.proxy.cfgPtr.Store(&next)
				}
			}}}
			if n, err := reader.Read(make([]byte, 16)); n != 0 || err == nil {
				t.Fatalf("revocation during read delivered n=%d err=%v", n, err)
			}
		})
	}
}

type watchReviewWriteFailureConn struct {
	cancelPayloadConn
	failAt int
	short  bool
}

func (c *watchReviewWriteFailureConn) Write(p []byte) (int, error) {
	if c.writes == c.failAt {
		if c.short {
			return len(p) - 1, nil
		}
		return 0, io.ErrClosedPipe
	}
	return c.cancelPayloadConn.Write(p)
}

func TestWatchWebSocketFragmentDeliveryErrors(t *testing.T) {
	for _, failure := range []string{"header", "short_write", "cancelled", "negative_length"} {
		t.Run(failure, func(t *testing.T) {
			relay := watchReviewRelay(t, nil)
			relay.scanText = false
			payload := []byte("ordinary")
			sink := &watchReviewWriteFailureConn{failAt: 0}
			relay.clientConn = sink
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			onRead := func() {}
			hdr := ws.Header{OpCode: ws.OpText, Fin: false, Length: int64(len(payload))}
			if failure == "short_write" {
				sink.failAt = 1
				sink.short = true
			}
			if failure == "cancelled" {
				sink.failAt = -1
				onRead = cancel
			}
			if failure == "negative_length" {
				hdr.Length = -1
			}
			relay.upstreamConn = &cancelPayloadConn{reader: bytes.NewReader(payload), cancel: onRead}
			var tail []byte
			n, err := relay.forwardWatchResponseFragment(ctx, hdr, ws.OpText, &tail)
			if err == nil {
				t.Fatal("delivery failure was lost")
			}
			if failure == "short_write" {
				if !errors.Is(err, io.ErrShortWrite) || n != int64(len(payload)-1) {
					t.Fatalf("short write n=%d err=%v", n, err)
				}
			} else if n != 0 {
				t.Fatalf("failed fragment delivered %d bytes", n)
			}
		})
	}
}

func TestWatchWebSocketRawHeaderFailure(t *testing.T) {
	relay := watchReviewRelay(t, nil)
	n, err := relay.forwardUninspectedFrame(&cancelPayloadConn{reader: bytes.NewReader([]byte("payload")), cancel: func() {}}, &watchReviewWriteFailureConn{}, ws.Header{OpCode: ws.OpText, Fin: true, Length: 7}, "oversized")
	if n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("header failure n=%d err=%v", n, err)
	}
}

func TestWatchWebSocketMaskedExemptFragment(t *testing.T) {
	relay := watchReviewRelay(t, func(cfg *config.Config) { cfg.ResponseScanning.ExemptDomains = []string{"api.vendor.example"} })
	frame := ws.MaskFrameInPlace(ws.NewFrame(ws.OpText, false, []byte(watchReviewInjection)))
	relay.upstreamConn = &cancelPayloadConn{reader: bytes.NewReader(frame.Payload), cancel: func() {}}
	var tail []byte
	n, err := relay.forwardWatchResponseFragment(t.Context(), frame.Header, ws.OpText, &tail)
	if err != nil || n != int64(len(frame.Payload)) {
		t.Fatalf("fragment n=%d err=%v", n, err)
	}
	got, err := ws.ReadFrame(&relay.clientConn.(*cancelPayloadConn).written)
	if err != nil || got.Header != frame.Header || !bytes.Equal(got.Payload, frame.Payload) {
		t.Fatal("original masked frame changed")
	}
	assertWatchReviewEvent(t, relay.proxy.metrics, responseScanLayer, config.ActionWarn, true)
	assertWatchReviewEvent(t, relay.proxy.metrics, responseScanLayer, config.ActionStrip, false)
}

func TestWatchWebSocketNoncoreScoring(t *testing.T) {
	for _, body := range []bool{false, true} {
		for _, warn := range []bool{false, true} {
			t.Run(fmt.Sprintf("body=%t/warn=%t", body, warn), func(t *testing.T) {
				relay := watchReviewRelay(t, nil)
				matches := []scanner.TextDLPMatch{{PatternName: "custom-pattern", Severity: config.SeverityMedium, Warn: warn}}
				var blocked bool
				if body {
					action := config.ActionBlock
					if warn {
						action = config.ActionWarn
					}
					blocked = relay.handleClientMessageBodyResult(relay.proxy.logger, []byte("matching data"), BodyScanResult{DLPMatches: matches, Action: action})
				} else {
					blocked = relay.handleClientTextFindings(relay.proxy.logger, matches, nil)
				}
				if blocked {
					t.Fatal("noncore watch finding blocked")
				}
				observed := relay.rec.(*SessionState).watchAdaptive
				want := session.SignalPoints[session.SignalBlock]
				if warn {
					want = session.SignalPoints[session.SignalWarning]
				}
				if observed == nil || observed.ScopedThreatScore(adaptiveScopeForHost(relay.hostname)) != want {
					t.Fatal("noncore finding lost its simulation signal")
				}
			})
		}
	}
}

func TestWatchWebSocketNilScannerAndReadError(t *testing.T) {
	sc, release, ok := pinWebSocketScanner(nil)
	release()
	if sc != nil || ok {
		t.Fatal("missing scanner was admitted")
	}
	relay := watchReviewRelay(t, nil)
	reader := &watchFrameReader{Reader: strings.NewReader(""), relay: relay, classifyRead: true}
	_, err := reader.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) || err.Error() != io.EOF.Error() {
		t.Fatalf("source error not retained: %v", err)
	}
}
