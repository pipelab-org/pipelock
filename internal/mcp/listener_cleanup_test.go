// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net"
	"sync"
	"testing"
)

// listenerProxyTestListener owns accepted test connections, including silent
// probes that otherwise spend the server's full shutdown grace period open.
// Production graceful shutdown is exercised with an unwrapped listener.
type listenerProxyTestListener struct {
	net.Listener
	mu      sync.Mutex
	conns   []net.Conn
	stopped bool
}

func newListenerProxyTestListener(t *testing.T) *listenerProxyTestListener {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return &listenerProxyTestListener{Listener: ln}
}

func (l *listenerProxyTestListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopped {
		_ = conn.Close()
	} else {
		l.conns = append(l.conns, conn)
	}
	return conn, nil
}

func (l *listenerProxyTestListener) closeConnections() {
	l.mu.Lock()
	l.stopped = true
	conns := l.conns
	l.conns = nil
	l.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}
