package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// pauseOnceListener pauses the first armed connection write after its bytes
// reach the client, so a test can act while the server is still inside Write.
type pauseOnceListener struct {
	net.Listener
	armed     atomic.Bool
	delivered chan struct{}
	resume    chan struct{}
}

type pauseOnceConn struct {
	net.Conn
	owner *pauseOnceListener
}

func (l *pauseOnceListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &pauseOnceConn{Conn: c, owner: l}, nil
}

func (c *pauseOnceConn) Write(p []byte) (int, error) {
	pause := c.owner.armed.CompareAndSwap(true, false)
	n, err := c.Conn.Write(p)
	if pause {
		close(c.owner.delivered)
		<-c.owner.resume
	}
	return n, err
}

// A legacy-protocol client that has read its tools/list must be able to call a
// listed tool at once. Only current-protocol lists defer the inventory commit
// to delivery; a legacy list commits before it is written.
func TestHTTPListener_LegacyListCommitsBeforeDelivery(t *testing.T) {
	f := &headerStateFixture{}
	f.definitions.Store(headerStateDefs(`{"type":"object"}`, "Echo input"))
	up := httptest.NewServer(http.HandlerFunc(f.serveUpstream))
	t.Cleanup(up.Close)

	ctx, cancel := context.WithCancel(context.Background())
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	wrapped := &pauseOnceListener{Listener: ln, delivered: make(chan struct{}), resume: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(wrapped.resume) }) }

	opts := paramContractOpts(t)
	opts.ToolCfg.BindingNoBaselineAction = "block"
	opts.ToolCfg.BindingUnknownAction = "block"
	done := make(chan error, 1)
	go func() { done <- RunHTTPListenerProxy(ctx, wrapped, up.URL, io.Discard, opts) }()
	t.Cleanup(func() {
		unblock()
		cancel()
		waitForListenerProxyStop(t, done)
	})
	f.url = "http://" + ln.Addr().String()
	waitForHTTPHealth(t, f.url)
	wrapped.armed.Store(true)

	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Proxy-Authorization", headerStateBearer)
	h.Set("Mcp-Protocol-Version", "2025-11-25")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header = h
	// The call below must not queue behind this paused connection.
	req.Close = true
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var list any
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	<-wrapped.delivered

	// Session binding must already admit the call while the list write is
	// still in progress; the upstream sees it before that write returns.
	type callResult struct {
		status int
		body   string
	}
	result := make(chan callResult, 1)
	go func() {
		status, _, body := postWireContractRequest(t, f.url, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`, h)
		result <- callResult{status: status, body: body}
	}()
	var early *callResult
	testwait.For(t, 10*time.Second, func() bool {
		select {
		case r := <-result:
			early = &r
			return true
		default:
			return f.calls.Load() > 0
		}
	}, "call reaching the upstream while the list write was in progress")
	unblock()
	var r callResult
	if early != nil {
		r = *early
	} else {
		r = <-result
	}
	if r.status != http.StatusOK || strings.Contains(r.body, `"error"`) || f.calls.Load() != 1 {
		t.Fatalf("call after reading the list: status=%d upstream=%d body=%s", r.status, f.calls.Load(), r.body)
	}
}
