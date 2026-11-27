// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestWSRelayClientScanCancellationIsNotBlocked(t *testing.T) {
	for _, tc := range []struct {
		name     string
		op       ws.OpCode
		messages []string
		redact   bool
		target   string
	}{
		{"text", ws.OpText, []string{"ordinary message"}, false, ""},
		{"control", ws.OpPing, []string{"ordinary ping"}, false, ""},
		{"cross_message", ws.OpText, []string{"first message", "second message"}, false, ""},
		{"labeled", ws.OpText, []string{"part1: first message", "part2: second message"}, false, ""},
		{"numbers", ws.OpText, []string{`{"value":12}`, `{"value":34}`}, false, ""},
		{"redaction_cross_message", ws.OpText, []string{`{"text":"part1: first message"}`, `{"text":"part2: second message"}`}, true, ""},
		// A heartbeat carries no credential. A cancelled Identify frame cannot
		// verify its carrier allowance, so its token stays a policy block; see
		// TestWSRelayClientTextResultKeepsFindingsAfterContextEnds.
		{"gateway", ws.OpText, []string{`{"op":1,"d":null}`}, false, "wss://gateway.discord.gg/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testScannerConfig()
			cfg.DLP.ScanEnv = false
			cfg.RequestBodyScanning.Enabled = false
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p := newTestProxyWithConfig(t, cfg)
			var wire bytes.Buffer
			for _, message := range tc.messages {
				if err := ws.WriteFrame(&wire, ws.MaskFrameInPlace(ws.NewFrame(tc.op, true, []byte(message)))); err != nil {
					t.Fatal(err)
				}
			}
			// Measure reachable checkpoints using a complete control run. Each
			// cancellation then checks teardown during inspection.
			var checks int32
			completed := 0
			for checkpoint := int32(0); checkpoint <= checks; checkpoint++ {
				t.Run(fmt.Sprint(checkpoint), func(t *testing.T) {
					base, cancel := context.WithCancel(t.Context())
					defer cancel()
					ctx := &bodyScanCheckpointContext{Context: base, cancel: cancel, after: checkpoint}
					source := &cancelPayloadConn{reader: bytes.NewReader(wire.Bytes()), cancel: func() {}}
					sink := &cancelPayloadConn{}
					relay := &wsRelay{proxy: p, cfg: cfg, scanner: sc, clientConn: source, upstreamConn: sink, maxMsg: 1024, scanText: true, targetURL: "wss://api.vendor.example/events"}
					if tc.target != "" {
						relay.targetURL = tc.target
					}
					if tc.redact {
						relay.redaction = &redactionRuntime{required: true}
					}
					n, _, _, blocked := relay.clientToUpstream(ctx, func() {}, time.Second)
					if checkpoint == 0 {
						checks = ctx.checks.Load() - 1 // final check follows inspection
						if checks < 1 || n == 0 || blocked {
							t.Fatalf("complete control: checks=%d bytes=%d blocked=%v", checks, n, blocked)
						}
						return
					}
					if base.Err() == nil || blocked || relay.panicked.Load() || source.writes != 0 {
						t.Fatalf("cancellation counted as a block: canceled=%v bytes=%d blocked=%v panic=%v writes=%d", base.Err(), n, blocked, relay.panicked.Load(), source.writes)
					}
					if len(tc.messages) == 1 && (n != 0 || sink.writes != 0) {
						t.Fatalf("cancelled frame forwarded: bytes=%d writes=%d", n, sink.writes)
					}
					if n != 0 && n != int64(len(tc.messages[0])) {
						t.Fatalf("cancelled final frame forwarded: bytes=%d", n)
					}
					p.recordWSRelayCompletion(wsRelayStats{blocked: blocked}, false)
					completed++
					assertMetricsNotContain(t, p.metrics, `pipelock_ws_connections_total{result="blocked"} 1`)
					assertMetricsContain(t, p.metrics, fmt.Sprintf(`pipelock_ws_connections_total{result="completed"} %d`, completed))
				})
			}
		})
	}
}

// Cancel at payload completion, after the loop's initial context check.
func TestWSRelayCancellationAfterPayloadRead(t *testing.T) {
	for _, clientDirection := range []bool{false, true} {
		t.Run(map[bool]string{true: "client", false: "upstream"}[clientDirection], func(t *testing.T) {
			cfg := testScannerConfig()
			cfg.Internal = nil
			sc := scanner.MustNew(cfg)
			p, err := New(cfg, audit.NewNop(), sc, metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			frame := ws.NewTextFrame([]byte("plain message"))
			if clientDirection {
				frame = ws.MaskFrameInPlace(frame)
			}
			var wire bytes.Buffer
			if err := ws.WriteFrame(&wire, frame); err != nil {
				t.Fatal(err)
			}
			source := &cancelPayloadConn{reader: bytes.NewReader(wire.Bytes()), cancel: cancel}
			sink := &cancelPayloadConn{}
			relay := &wsRelay{proxy: p, scanner: sc, cfg: cfg, clientConn: sink, upstreamConn: source, maxMsg: 1024, scanText: true}
			pump := relay.upstreamToClient
			if clientDirection {
				relay.clientConn, relay.upstreamConn = source, sink
				pump = relay.clientToUpstream
			}
			n, _, _, blocked := pump(ctx, cancel, time.Second)
			if ctx.Err() == nil || blocked || relay.panicked.Load() || n != 0 || source.writes != 0 || sink.writes != 0 {
				t.Fatalf("cancelled payload was forwarded or classified as policy: bytes=%d blocked=%v panic=%v writes=%d/%d", n, blocked, relay.panicked.Load(), source.writes, sink.writes)
			}
		})
	}
}

// Response scan cancellation is teardown, not an incomplete-response finding.
func TestWSRelayCancelledResponseScan(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	relay := &wsRelay{scanner: sc, cfg: cfg, scanText: true}
	payload, blocked := relay.enforceUpstreamTextPayload(ctx, audit.NewNop(), []byte("plain response"), true)
	if blocked || payload != nil {
		t.Fatal("cancelled scan produced a policy result")
	}
}

func TestWSRelayClientCloseDoesNotForwardData(t *testing.T) {
	for _, op := range []ws.OpCode{ws.OpText, ws.OpPing} {
		t.Run(opCodeLabel(op), func(t *testing.T) {
			cfg := testScannerConfig()
			p := newTestProxyWithConfig(t, cfg)
			var wire bytes.Buffer
			if err := ws.WriteFrame(&wire, ws.NewFrame(op, true, []byte("after close"))); err != nil {
				t.Fatal(err)
			}
			if err := ws.WriteFrame(&wire, ws.NewFrame(op, true, []byte("another discarded frame"))); err != nil {
				t.Fatal(err)
			}
			if err := ws.WriteFrame(&wire, ws.NewCloseFrame(ws.NewCloseFrameBody(ws.StatusNormalClosure, "done"))); err != nil {
				t.Fatal(err)
			}
			source := &cancelPayloadConn{reader: bytes.NewReader(wire.Bytes()), cancel: func() {}}
			sink := &cancelPayloadConn{}
			relay := &wsRelay{proxy: p, cfg: cfg, upstreamConn: source, clientConn: sink, maxMsg: 1024}
			relay.clientClosing.Store(true)
			n, _, _, blocked := relay.upstreamToClient(t.Context(), func() {}, time.Second)
			if n != 0 || blocked || relay.panicked.Load() || relay.upstreamCancelled || sink.writes != 1 {
				t.Fatalf("data after client close: bytes=%d blocked=%v panic=%v cancelled=%v writes=%d", n, blocked, relay.panicked.Load(), relay.upstreamCancelled, sink.writes)
			}
			frame, err := ws.ReadFrame(&sink.written)
			if err != nil {
				t.Fatal(err)
			}
			code, _ := ws.ParseCloseFrameData(frame.Payload)
			if frame.Header.OpCode != ws.OpClose || code != ws.StatusNormalClosure {
				t.Fatalf("discarded frame reached client: %+v", frame)
			}
			if len(source.deadlines) != 6 {
				t.Fatalf("read deadlines: %v", source.deadlines)
			}
			for i := 3; i < len(source.deadlines); i += 2 {
				if !source.deadlines[i].Equal(source.deadlines[1]) {
					t.Fatal("intervening frame extended the close grace")
				}
			}
			// RFC 6455 section 5.5.2: until upstream's Close arrives, each Ping
			// is answered upstream with a masked Pong echoing its payload; no
			// other frame produces an upstream write.
			var pongs []string
			for source.written.Len() > 0 {
				reply, err := ws.ReadFrame(&source.written)
				if err != nil {
					t.Fatal(err)
				}
				if reply.Header.OpCode != ws.OpPong || !reply.Header.Masked {
					t.Fatalf("unexpected upstream frame during close grace: %+v", reply.Header)
				}
				pongs = append(pongs, string(ws.UnmaskFrame(reply).Payload))
			}
			want := []string(nil)
			if op == ws.OpPing {
				want = []string{"after close", "another discarded frame"}
			}
			if !slices.Equal(pongs, want) {
				t.Fatalf("upstream Pongs = %q, want %q", pongs, want)
			}
		})
	}
}

type cancelPayloadConn struct {
	net.Conn
	reader         *bytes.Reader
	cancel         context.CancelFunc
	writes         int
	written        bytes.Buffer
	deadlines      []time.Time
	writeDeadlines []time.Time
}

func TestWSRelayClosingPingHonorsStopAfterPayload(t *testing.T) {
	for _, stop := range []string{"cancel", "kill_switch", "capacity"} {
		t.Run(stop, func(t *testing.T) {
			cfg := testScannerConfig()
			p := newTestProxyWithConfig(t, cfg)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var shard receipt.EmitOpts
			stopRelay := cancel
			switch stop {
			case "kill_switch":
				p.ks = killswitch.New(cfg)
				stopRelay = func() { p.ks.SetAPI(true) }
			case "capacity":
				_, emitter, _ := newNativeCapacityProxy(t, 16)
				lease, err := emitter.ReserveNativeRecords(1)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(lease.Release)
				shard.NativeLease = lease
				stopRelay = func() {
					if excess, err := emitter.ReserveNativeRecords(32); err == nil {
						excess.Release()
						t.Fatal("capacity reservation unexpectedly succeeded")
					}
					if !lease.Stopping() {
						t.Fatal("capacity did not stop")
					}
				}
			}
			var wire bytes.Buffer
			if err := ws.WriteFrame(&wire, ws.NewPingFrame([]byte("close grace"))); err != nil {
				t.Fatal(err)
			}
			source := &cancelPayloadConn{reader: bytes.NewReader(wire.Bytes()), cancel: stopRelay}
			relay := &wsRelay{proxy: p, cfg: cfg, upstreamConn: source, clientConn: &cancelPayloadConn{}, maxMsg: 1024, receiptShard: shard}
			relay.clientClosing.Store(true)
			_, _, _, blocked := relay.upstreamToClient(ctx, cancel, time.Second)
			if relay.panicked.Load() || blocked != (stop == "kill_switch") {
				t.Fatalf("unexpected stop outcome: blocked=%v panic=%v", blocked, relay.panicked.Load())
			}
			for source.written.Len() > 0 {
				frame, err := ws.ReadFrame(&source.written)
				if err != nil {
					t.Fatal(err)
				}
				if frame.Header.OpCode != ws.OpClose || stop != "kill_switch" {
					t.Errorf("upstream received opcode %v after %s", frame.Header.OpCode, stop)
				}
			}
		})
	}
}

func TestWSRelayClientCloseWriteUsesGraceDeadline(t *testing.T) {
	cfg := testScannerConfig()
	p := newTestProxyWithConfig(t, cfg)
	var wire bytes.Buffer
	if err := ws.WriteFrame(&wire, ws.MaskFrameInPlace(ws.NewCloseFrame(nil))); err != nil {
		t.Fatal(err)
	}
	source := &cancelPayloadConn{reader: bytes.NewReader(wire.Bytes()), cancel: func() {}}
	sink := &cancelPayloadConn{}
	relay := &wsRelay{proxy: p, cfg: cfg, clientConn: source, upstreamConn: sink, maxMsg: 1024}
	_, _, _, blocked := relay.clientToUpstream(t.Context(), func() {}, time.Second)
	if blocked || relay.panicked.Load() || sink.writes != 1 || !relay.clientClosing.Load() {
		t.Fatalf("client Close did not start the closing handshake: blocked=%v writes=%d", blocked, sink.writes)
	}
	if len(sink.writeDeadlines) == 0 || !sink.writeDeadlines[0].Equal(relay.closeGraceDeadline()) {
		t.Fatalf("Close write deadlines = %v, want first deadline %v", sink.writeDeadlines, relay.closeGraceDeadline())
	}
}

func TestWSRelayClientCloseGraceExpired(t *testing.T) {
	cfg := testScannerConfig()
	p := newTestProxyWithConfig(t, cfg)
	sink := &cancelPayloadConn{}
	relay := &wsRelay{proxy: p, cfg: cfg, clientConn: sink}
	deadline := time.Now().Add(-time.Second)
	relay.clientCloseDeadline.Store(&deadline)
	relay.clientClosing.Store(true)
	n, _, _, blocked := relay.upstreamToClient(t.Context(), func() {}, time.Minute)
	if n != 0 || blocked || relay.panicked.Load() || !relay.upstreamCancelled || sink.writes != 0 {
		t.Fatal("expired close grace did not terminate before reading or forwarding")
	}
}

func (c *cancelPayloadConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if c.reader.Len() == 0 {
		c.cancel()
	}
	return n, err
}

func (c *cancelPayloadConn) Write(p []byte) (int, error) { c.writes++; return c.written.Write(p) }

func (c *cancelPayloadConn) SetReadDeadline(d time.Time) error {
	c.deadlines = append(c.deadlines, d)
	return nil
}
func (c *cancelPayloadConn) SetWriteDeadline(d time.Time) error {
	c.writeDeadlines = append(c.writeDeadlines, d)
	return nil
}
func (*cancelPayloadConn) Close() error { return nil }

// A credential collected before the scan context ended is still a policy
// block. Only a cancel with nothing found is a quiet teardown, and a deadline
// counts as a block like the relay loop's own timeout path.
func TestWSRelayClientTextResultKeepsFindingsAfterContextEnds(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p := newTestProxyWithConfig(t, cfg)
	secret := []byte("key=" + "AKIA" + "IOSFODNN7EXAMPLE")
	found := sc.ScanTextForDLP(context.Background(), string(secret))
	if len(found.Matches) == 0 {
		t.Fatal("fixture credential produced no match")
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancelExpired()

	for _, tc := range []struct {
		name        string
		ctx         context.Context
		result      scanner.TextDLPResult
		wantBlocked bool
	}{
		{"match_then_cancel", canceled, scanner.TextDLPResult{Matches: found.Matches, Incomplete: true}, true},
		{"cancel_without_match", canceled, scanner.TextDLPResult{Incomplete: true}, false},
		{"deadline_without_match", expired, scanner.TextDLPResult{Incomplete: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &cancelPayloadConn{}
			relay := &wsRelay{proxy: p, cfg: cfg, scanner: sc, clientConn: client, upstreamConn: &cancelPayloadConn{}, scanText: true, targetURL: "wss://api.vendor.example/events"}
			halt, blocked := relay.handleClientTextResult(tc.ctx, p.logger, secret, tc.result, wsClientTextOptions{})
			if !halt {
				t.Fatal("frame forwarded after the scan context ended")
			}
			if blocked != tc.wantBlocked {
				t.Fatalf("blocked = %v, want %v", blocked, tc.wantBlocked)
			}
		})
	}
}
