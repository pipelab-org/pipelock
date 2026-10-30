// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package checker

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// Exercise the transport, which detaches its dial context from the request.
func TestTransportSetupCancellation(t *testing.T) {
	for _, phase := range []string{"lookup", "dial"} {
		for _, ending := range []string{"cancel", "policy_timeout", "parent_timeout"} {
			t.Run(phase+"/"+ending, func(t *testing.T) {
				client, err := NewClient(Options{Endpoint: "https://api.vendor.example/check"})
				if err != nil {
					t.Fatal(err)
				}
				started := make(chan context.Context, 1)
				release := make(chan struct{})
				defer close(release)
				block := func(ctx context.Context) error {
					started <- ctx
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-release:
						return errors.New("released")
					}
				}
				client.http.Transport.(*http.Transport).DialContext = checkedDial(
					func(ctx context.Context, _ string) ([]net.IPAddr, error) {
						if phase == "lookup" {
							return nil, block(ctx)
						}
						return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("192.0.2.2")}}, nil
					},
					func(ctx context.Context, _, _ string) (net.Conn, error) { return nil, block(ctx) },
				)
				policy := testPolicy()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				want := ReasonCanceled
				if ending != "cancel" {
					want = ReasonTimeout
				}
				if ending == "parent_timeout" {
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(ctx, policy.Timeout)
					defer stop()
					policy.Timeout *= 2
				}
				latest := time.Now().Add(policy.Timeout)
				if d, ok := ctx.Deadline(); ok {
					latest = d
				}
				result := make(chan Assessment, 1)
				go func() { result <- client.Check(ctx, testItem(), policy) }()
				var setup context.Context
				select {
				case setup = <-started:
				case <-time.After(3 * time.Second):
					t.Fatal("setup did not start")
				}
				deadline, bounded := setup.Deadline()
				if ending == "cancel" {
					cancel()
				}
				if got := <-result; got.Reason != want {
					t.Fatalf("assessment: %+v", got)
				}
				if !bounded {
					t.Error("setup lost the whole-call deadline")
				}
				if ending == "parent_timeout" && deadline.After(latest) {
					t.Error("setup extended caller deadline")
				}
				if setup.Err() == nil {
					t.Error("setup is still live after Check returned")
				}
			})
		}
	}
}

func TestTLSSetupCancellation(t *testing.T) {
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	client, err := NewClient(Options{Endpoint: "https://" + listener.Addr().String() + "/check"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan Assessment, 1)
	go func() { result <- client.Check(ctx, testItem(), testPolicy()) }()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		t.Fatal(err)
	}
	// The peer has received TLS setup bytes but never sends a ServerHello.
	cancel()
	if got := <-result; got.Reason != ReasonCanceled {
		t.Fatalf("assessment: %+v", got)
	}
	_, err = io.Copy(io.Discard, conn)
	if err != nil {
		t.Fatalf("TLS connection survived request cancellation: %v", err)
	}
}

func TestUnixPeerCheckCancellation(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "runner.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	started, stopped := make(chan struct{}), make(chan struct{})
	client, err := NewClient(Options{Endpoint: "http://localhost/check", UnixSocket: socket, VerifyPeer: func(conn net.Conn) error {
		defer close(stopped)
		close(started)
		var b [1]byte
		_, readErr := conn.Read(b[:])
		return readErr
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan Assessment, 1)
	go func() { result <- client.Check(ctx, testItem(), testPolicy()) }()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("peer check did not start")
	}
	cancel()
	if got := <-result; got.Reason != ReasonCanceled {
		t.Fatalf("assessment: %+v", got)
	}
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("peer socket read survived cancellation")
	}
}
