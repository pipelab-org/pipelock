// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func relayTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	peer, err := (&net.Dialer{}).DialContext(t.Context(), "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn.(*net.TCPConn), peer.(*net.TCPConn)
}

func TestBufferedRelayPreservesDirectionalEOF(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		name := "plain"
		if buffered {
			name = "buffered"
		}
		t.Run(name, func(t *testing.T) {
			clientSide, client := relayTCPPair(t)
			targetSide, target := relayTCPPair(t)
			if _, err := io.WriteString(client, "ping"); err != nil {
				t.Fatal(err)
			}
			var relayClient net.Conn = clientSide
			if buffered {
				reader := bufio.NewReader(clientSide)
				if _, err := reader.Peek(4); err != nil {
					t.Fatal(err)
				}
				relayClient = wrapBuffered(clientSide, reader)
			}
			done := make(chan int64, 1)
			go func() { done <- bidirectionalCopy(relayClient, targetSide, time.Hour, time.Time{}, nil) }()
			request := make([]byte, 4)
			if _, err := io.ReadFull(target, request); err != nil || string(request) != "ping" {
				t.Fatalf("request = %q, err = %v", request, err)
			}
			if _, err := io.WriteString(target, "pong"); err != nil {
				t.Fatal(err)
			}
			if err := target.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			// Keep the reverse direction open while waiting for target EOF.
			response, err := io.ReadAll(client)
			if err != nil || string(response) != "pong" {
				t.Fatalf("response = %q, err = %v; want pong followed by EOF", response, err)
			}
			if _, err := io.WriteString(client, "tail"); err != nil {
				t.Fatalf("reverse direction closed with target EOF: %v", err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			tail, err := io.ReadAll(target)
			if err != nil || string(tail) != "tail" {
				t.Fatalf("remaining request = %q, err = %v", tail, err)
			}
			select {
			case total := <-done:
				if total != 12 {
					t.Fatalf("relayed %d bytes, want 12", total)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("relay did not finish after both directions ended")
			}
		})
	}
}

func TestRemoveHopByHopHeadersStripsConnectionList(t *testing.T) {
	t.Parallel()

	h := make(http.Header)
	h.Set("Connection", "X-Foo, close")
	h.Set("X-Foo", "secret")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("X-Keep", "stay")
	removeHopByHopHeaders(h)
	if h.Get("X-Foo") != "" {
		t.Fatal("Connection-listed X-Foo survived")
	}
	if h.Get("Keep-Alive") != "" {
		t.Fatal("standard hop-by-hop Keep-Alive survived")
	}
	if h.Get("Connection") != "" {
		t.Fatal("Connection header survived")
	}
	if h.Get("X-Keep") != "stay" {
		t.Fatalf("end-to-end header dropped: %v", h)
	}
}

func TestBidirectionalCopyRelaysAndCountsBytes(t *testing.T) {
	t.Parallel()

	clientA, clientB := net.Pipe()
	targetA, targetB := net.Pipe()
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
		_ = targetA.Close()
		_ = targetB.Close()
	})

	done := make(chan int64, 1)
	go func() {
		done <- bidirectionalCopy(clientA, targetA, 0, time.Time{}, nil)
	}()

	payload := []byte("ping")
	writeErr := make(chan error, 1)
	go func() {
		_, err := clientB.Write(payload)
		writeErr <- err
		_ = clientB.Close()
	}()

	got := make([]byte, len(payload))
	if err := targetB.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.ReadFull(targetB, got); err != nil {
		t.Fatalf("read relayed bytes: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("relayed = %q, want %q", got, payload)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = targetB.Close()

	select {
	case n := <-done:
		if n != int64(len(payload)) {
			t.Fatalf("copied %d, want %d", n, len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not finish")
	}
}
