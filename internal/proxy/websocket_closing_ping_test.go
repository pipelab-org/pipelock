// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

// closeOnObserveRecorder is a taint recorder whose ObserveRisk runs while the
// relay scans an upstream payload. Tests use it to land the client's Close
// between the relay's two closing checks.
type closeOnObserveRecorder struct {
	onObserve func()
}

func (*closeOnObserveRecorder) RecordSignal(session.SignalType, float64) (bool, string, string) {
	return false, "", ""
}
func (*closeOnObserveRecorder) RecordClean(float64)               {}
func (*closeOnObserveRecorder) EscalationLevel() int              { return 0 }
func (*closeOnObserveRecorder) ThreatScore() float64              { return 0 }
func (*closeOnObserveRecorder) RiskSnapshot() session.SessionRisk { return session.SessionRisk{} }
func (r *closeOnObserveRecorder) ObserveRisk(session.RiskObservation) {
	if r.onObserve != nil {
		r.onObserve()
	}
}

// failingWriteConn accepts reads like cancelPayloadConn and fails every write.
type failingWriteConn struct {
	cancelPayloadConn
}

var errTestUpstreamWrite = errors.New("upstream write failed")

func (c *failingWriteConn) Write([]byte) (int, error) {
	c.writes++
	return 0, errTestUpstreamWrite
}

func wsWire(t *testing.T, frames ...ws.Frame) *bytes.Reader {
	t.Helper()
	var wire bytes.Buffer
	for _, f := range frames {
		if err := ws.WriteFrame(&wire, f); err != nil {
			t.Fatal(err)
		}
	}
	return bytes.NewReader(wire.Bytes())
}

func readUpstreamPongs(t *testing.T, written *bytes.Buffer) []string {
	t.Helper()
	var pongs []string
	for written.Len() > 0 {
		reply, err := ws.ReadFrame(written)
		if err != nil {
			t.Fatal(err)
		}
		if reply.Header.OpCode != ws.OpPong || !reply.Header.Masked {
			t.Fatalf("unexpected upstream frame: %+v", reply.Header)
		}
		pongs = append(pongs, string(ws.UnmaskFrame(reply).Payload))
	}
	return pongs
}

// A Ping read before the client's Close and scanned after it must still be
// answered upstream, from the second closing check, and never reach the client.
func TestWSRelayAnswersPingThatCrossesClientClose(t *testing.T) {
	cfg := testScannerConfig()
	cfg.Taint.Enabled = true
	p := newTestProxyWithConfig(t, cfg)
	source := &cancelPayloadConn{
		reader: wsWire(t,
			ws.NewPingFrame([]byte("crossed")),
			ws.NewCloseFrame(ws.NewCloseFrameBody(ws.StatusNormalClosure, "done")),
		),
		cancel: func() {},
	}
	sink := &cancelPayloadConn{}
	relay := &wsRelay{proxy: p, cfg: cfg, upstreamConn: source, clientConn: sink, maxMsg: 1024}
	observed := 0
	p.taintRecorder = &closeOnObserveRecorder{onObserve: func() {
		observed++
		deadline := time.Now().Add(time.Minute)
		relay.clientCloseDeadline.Store(&deadline)
		relay.clientClosing.Store(true)
	}}

	n, _, _, blocked := relay.upstreamToClient(t.Context(), func() {}, time.Second)
	if observed != 1 {
		t.Fatalf("scan observed %d payloads, want the Ping only", observed)
	}
	if n != 0 || blocked || relay.panicked.Load() || relay.upstreamCancelled {
		t.Fatalf("crossing Ping: bytes=%d blocked=%v panic=%v cancelled=%v", n, blocked, relay.panicked.Load(), relay.upstreamCancelled)
	}
	if got := readUpstreamPongs(t, &source.written); len(got) != 1 || got[0] != "crossed" {
		t.Fatalf("upstream Pongs = %q, want one echoing %q", got, "crossed")
	}
	// The only client write is the Close for upstream's reply; the Ping was
	// not forwarded.
	frame, err := ws.ReadFrame(&sink.written)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Header.OpCode != ws.OpClose || sink.written.Len() != 0 {
		t.Fatalf("client received %+v plus %d more bytes, want only the Close", frame.Header, sink.written.Len())
	}
}

// A masked upstream Ping during close grace is answered with its unmasked
// payload, not the masked bytes on the wire.
func TestWSRelayClosingPongEchoesUnmaskedPing(t *testing.T) {
	cfg := testScannerConfig()
	p := newTestProxyWithConfig(t, cfg)
	source := &cancelPayloadConn{
		reader: wsWire(t,
			ws.MaskFrame(ws.NewPingFrame([]byte("masked ping"))),
			ws.NewCloseFrame(ws.NewCloseFrameBody(ws.StatusNormalClosure, "done")),
		),
		cancel: func() {},
	}
	relay := &wsRelay{proxy: p, cfg: cfg, upstreamConn: source, clientConn: &cancelPayloadConn{}, maxMsg: 1024}
	relay.clientClosing.Store(true)
	relay.upstreamToClient(t.Context(), func() {}, time.Second)
	if relay.upstreamCancelled {
		t.Fatal("relay cancelled while answering a masked Ping")
	}
	if got := readUpstreamPongs(t, &source.written); len(got) != 1 || got[0] != "masked ping" {
		t.Fatalf("upstream Pongs = %q, want one echoing the unmasked payload", got)
	}
}

// When the closing Pong cannot be written, the relay stops and records the
// upstream as cancelled instead of reading on toward the grace deadline.
func TestWSRelayStopsWhenClosingPongWriteFails(t *testing.T) {
	cfg := testScannerConfig()
	p := newTestProxyWithConfig(t, cfg)

	t.Run("helper", func(t *testing.T) {
		upstream := &failingWriteConn{}
		relay := &wsRelay{proxy: p, cfg: cfg, upstreamConn: upstream, clientConn: &cancelPayloadConn{}}
		deadline := time.Now().Add(time.Minute)
		relay.clientCloseDeadline.Store(&deadline)
		relay.clientClosing.Store(true)
		if relay.answerPingDuringClientClose(t.Context(), ws.OpPing, []byte("p")) {
			t.Fatal("helper did not ask the relay to stop after a failed Pong write")
		}
		if !relay.upstreamCancelled || upstream.writes != 1 {
			t.Fatalf("cancelled=%v writes=%d, want cancelled after one write attempt", relay.upstreamCancelled, upstream.writes)
		}
	})

	t.Run("relay", func(t *testing.T) {
		upstream := &failingWriteConn{cancelPayloadConn{
			reader: wsWire(t,
				ws.NewPingFrame([]byte("unanswerable")),
				ws.NewTextFrame([]byte("must not be read")),
			),
			cancel: func() {},
		}}
		sink := &cancelPayloadConn{}
		relay := &wsRelay{proxy: p, cfg: cfg, upstreamConn: upstream, clientConn: sink, maxMsg: 1024}
		relay.clientClosing.Store(true)
		n, _, _, blocked := relay.upstreamToClient(t.Context(), func() {}, time.Second)
		if n != 0 || blocked || !relay.upstreamCancelled || upstream.writes != 1 || sink.writes != 0 {
			t.Fatalf("bytes=%d blocked=%v cancelled=%v upstream writes=%d client writes=%d", n, blocked, relay.upstreamCancelled, upstream.writes, sink.writes)
		}
		if upstream.reader.Len() == 0 {
			t.Fatal("relay kept reading after the Pong write failed")
		}
	})
}

// A crossing Ping whose Pong cannot be written stops the relay from the second
// closing check, with nothing forwarded to the client.
func TestWSRelayCrossingPingStopsWhenPongWriteFails(t *testing.T) {
	cfg := testScannerConfig()
	cfg.Taint.Enabled = true
	p := newTestProxyWithConfig(t, cfg)
	upstream := &failingWriteConn{cancelPayloadConn{
		reader: wsWire(t,
			ws.NewPingFrame([]byte("crossed")),
			ws.NewTextFrame([]byte("must not be read")),
		),
		cancel: func() {},
	}}
	sink := &cancelPayloadConn{}
	relay := &wsRelay{proxy: p, cfg: cfg, upstreamConn: upstream, clientConn: sink, maxMsg: 1024}
	p.taintRecorder = &closeOnObserveRecorder{onObserve: func() {
		deadline := time.Now().Add(time.Minute)
		relay.clientCloseDeadline.Store(&deadline)
		relay.clientClosing.Store(true)
	}}
	n, _, _, blocked := relay.upstreamToClient(t.Context(), func() {}, time.Second)
	if n != 0 || blocked || !relay.upstreamCancelled || upstream.writes != 1 || sink.writes != 0 {
		t.Fatalf("bytes=%d blocked=%v cancelled=%v upstream writes=%d client writes=%d", n, blocked, relay.upstreamCancelled, upstream.writes, sink.writes)
	}
	if upstream.reader.Len() == 0 {
		t.Fatal("relay kept reading after the Pong write failed")
	}
}
