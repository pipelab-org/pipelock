// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package checker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testItem() Item {
	return Item{ID: "item", Kind: KindText, Surface: "tool_result", Transport: "mcp_stdio", Direction: "response", ExtractionVersion: "text/v1", OriginalBytes: 5, SubmittedBytes: 5, Completeness: &Completeness{Status: Complete}, Parts: []Part{{ID: "part", Role: "content", Representation: "original", Text: "hello"}}}
}

func testPolicy() Policy {
	return Policy{Mode: ModeBlock, Generation: "generation", Revision: Revision{Checker: "checker/v1", Model: "model/v1", Adapter: "adapter/v1"}, Timeout: time.Second, MaxRequestBytes: 16384, MaxResponseBytes: 4096}
}

func testResponse(req Request) Response {
	var item Item
	_ = json.Unmarshal(req.Item, &item)
	return Response{Version: Version, RequestID: req.ID, ItemID: item.ID, InputBinding: req.InputBinding, Revision: testPolicy().Revision, Completeness: &Completeness{Status: Complete}, Status: StatusAssessed, Classification: Benign}
}

func clientFor(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client, err := NewClient(Options{Endpoint: srv.URL, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func goodHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		_ = json.NewEncoder(w).Encode(testResponse(req))
	}
}

func TestNoRedirect(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1); goodHandler(t)(w, r) }))
	defer target.Close()
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			client := clientFor(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, code) })
			client.authorization = "Bearer example-credential"
			got := client.Check(t.Context(), testItem(), testPolicy())
			if got.Reason != ReasonRedirect || got.State != StateNotAssessed || targetCalls.Load() != 0 {
				t.Fatalf("redirect followed or accepted: %+v calls=%d", got, targetCalls.Load())
			}
		})
	}
}

func TestRequestAndConcurrency(t *testing.T) {
	var ids sync.Map
	var calls atomic.Int32
	client := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer example-credential" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("wrong request headers")
		}
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		if req.Version != Version || len(req.ID) != 64 || req.PolicyGeneration != testPolicy().Generation || req.InputBinding != Binding(req.Item) {
			t.Error("invalid request identity")
		}
		if _, loaded := ids.LoadOrStore(req.ID, true); loaded {
			t.Error("reused request ID")
		}
		var item Item
		if err := json.Unmarshal(req.Item, &item); err != nil {
			t.Error(err)
		}
		if item.Parts[0].Text != "hello" {
			t.Error("content changed")
		}
		_ = json.NewEncoder(w).Encode(testResponse(req))
	})
	client.authorization = "Bearer example-credential"
	transport := client.http.Transport.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableKeepAlives || !transport.DisableCompression {
		t.Fatal("ambient transport behavior enabled")
	}
	t.Setenv("HTTP_PROXY", "http://api.vendor.example:1")
	t.Setenv("HTTPS_PROXY", "http://api.vendor.example:1")
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if got := client.Check(t.Context(), testItem(), testPolicy()); got.State != StateBenign {
				t.Errorf("%+v", got)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 8 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestDeadlines(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(map[bool]string{false: "headers", true: "body"}[body], func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			client := clientFor(t, func(w http.ResponseWriter, _ *http.Request) {
				if body {
					_, _ = io.WriteString(w, "{")
					w.(http.Flusher).Flush()
				}
				close(started)
				<-release
			})
			defer close(release)
			policy := testPolicy()
			policy.Timeout = 100 * time.Millisecond
			result := make(chan Assessment, 1)
			go func() { result <- client.Check(t.Context(), testItem(), policy) }()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("server did not receive request")
			}
			select {
			case got := <-result:
				if got.Reason != ReasonTimeout || got.State == StateBenign {
					t.Fatalf("%+v", got)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("deadline did not terminate request")
			}
		})
	}
	client := clientFor(t, goodHandler(t))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := client.Check(ctx, testItem(), testPolicy()); got.Reason != ReasonCanceled {
		t.Fatal(got)
	}
	ctx, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stop()
	if got := client.Check(ctx, testItem(), testPolicy()); got.Reason != ReasonTimeout {
		t.Fatal(got)
	}
}

func TestHTTPFailuresAndSize(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		reason  Reason
		status  Status
	}{
		{"server_error", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }, ReasonUnavailable, StatusNotChecked},
		{"oversized", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, strings.Repeat(" ", 4097)) }, ReasonTooLarge, StatusInvalid},
		{"short_body", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			_, _ = io.WriteString(w, "{")
		}, ReasonUnavailable, StatusNotChecked},
		{"gzip", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write([]byte{31, 139, 0})
		}, ReasonMalformed, StatusInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := clientFor(t, tc.handler)
			got := client.Check(t.Context(), testItem(), testPolicy())
			if got.Reason != tc.reason || got.Status != tc.status {
				t.Fatalf("%+v", got)
			}
		})
	}
	srv := httptest.NewServer(goodHandler(t))
	srv.Close()
	client, err := NewClient(Options{Endpoint: srv.URL, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Check(t.Context(), testItem(), testPolicy()); got.Reason != ReasonUnavailable {
		t.Fatal(got)
	}
	client.endpoint = ":"
	if got := client.Check(t.Context(), testItem(), testPolicy()); got.Status != StatusInvalid {
		t.Fatal(got)
	}
}

func TestNoCall(t *testing.T) {
	client := clientFor(t, func(http.ResponseWriter, *http.Request) { t.Error("unexpected call") })
	tests := []struct {
		name   string
		item   func(*Item)
		policy func(*Policy)
		state  State
		reason Reason
	}{
		{name: "off", policy: func(p *Policy) { p.Mode = ModeOff }, state: StateOff},
		{name: "invalid_policy", policy: func(p *Policy) { p.Timeout = 0 }, state: StateNotAssessed, reason: ReasonPolicy},
		{name: "action", item: func(i *Item) { i.Kind = KindAction }, state: StateNotAssessed, reason: ReasonUnsupported},
		{name: "image", item: func(i *Item) { i.Kind = KindImage }, state: StateNotAssessed, reason: ReasonUnsupported},
		{name: "malformed", item: func(i *Item) { i.Completeness = nil }, state: StateNotAssessed, reason: ReasonMalformed},
		{name: "content_budget", policy: func(p *Policy) { p.MaxRequestBytes = 4 }, state: StateNotAssessed, reason: ReasonOverBudget},
		{name: "envelope_budget", policy: func(p *Policy) { p.MaxRequestBytes = 10 }, state: StateNotAssessed, reason: ReasonOverBudget},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			item, policy := testItem(), testPolicy()
			if tc.item != nil {
				tc.item(&item)
			}
			if tc.policy != nil {
				tc.policy(&policy)
			}
			got := client.Check(t.Context(), item, policy)
			if got.State != tc.state || got.Reason != tc.reason {
				t.Fatal(got)
			}
		})
	}
}

func TestOptions(t *testing.T) {
	credentialURL := &url.URL{Scheme: "https", Host: "api.vendor.example", User: url.UserPassword("example-user", "example-value")}
	for _, opts := range []Options{
		{Endpoint: ":"},
		{Endpoint: "https:///check"},
		{Endpoint: "ftp://api.vendor.example"},
		{Endpoint: credentialURL.String()},
		{Endpoint: "https://api.vendor.example?q=value"},
		{Endpoint: "https://api.vendor.example?"},
		{Endpoint: "https://api.vendor.example#fragment"},
		{Endpoint: "https://api.vendor.example", Authorization: "bad\nheader"},
		{Endpoint: "https://api.vendor.example", Authorization: "bad\x00header"},
		{Endpoint: "https://api.vendor.example", Authorization: "bad\x7fheader"},
		{Endpoint: "https://api.vendor.example", Authorization: "bad\x01header"},
		{Endpoint: "http://127.0.0.1"},
		{Endpoint: "http://localhost", AllowLoopbackHTTP: true},
		{Endpoint: "http://api.vendor.example", AllowLoopbackHTTP: true},
		{Endpoint: "http://localhost", UnixSocket: "relative"},
		{Endpoint: "https://localhost", UnixSocket: "/runner.sock"},
		{Endpoint: "http://api.vendor.example", UnixSocket: "/runner.sock"},
	} {
		// The error is exactly the generic sentinel, so no endpoint,
		// credential or header value can appear in it.
		_, err := NewClient(opts)
		if !errors.Is(err, ErrOptions) || err.Error() != ErrOptions.Error() {
			t.Errorf("unexpected error: %v", err)
		}
	}
	if _, err := NewClient(Options{Endpoint: "https://api.vendor.example/check"}); err != nil {
		t.Fatal(err)
	}
}

func TestCheckedDial(t *testing.T) {
	for _, tc := range []struct {
		name, addr string
		ips        []net.IPAddr
		lookupErr  bool
		wantCall   bool
	}{
		{name: "bad_address", addr: "bad"},
		{name: "lookup_failure", addr: "api.vendor.example:443", lookupErr: true},
		{name: "empty_resolution", addr: "api.vendor.example:443"},
		{name: "metadata", addr: "api.vendor.example:443", ips: []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}},
		{name: "mixed", addr: "api.vendor.example:443", ips: []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("169.254.169.254")}}},
		{name: "nil_ip", addr: "api.vendor.example:443", ips: []net.IPAddr{{}}},
		{name: "zone", addr: "api.vendor.example:443", ips: []net.IPAddr{{IP: net.ParseIP("::1"), Zone: "example"}}},
		{name: "unspecified", addr: "api.vendor.example:443", ips: []net.IPAddr{{IP: net.ParseIP("0.0.0.0")}}},
		{name: "multicast", addr: "api.vendor.example:443", ips: []net.IPAddr{{IP: net.ParseIP("224.0.0.1")}}},
		{name: "container_credentials", addr: "api.vendor.example:443", ips: []net.IPAddr{{IP: net.ParseIP("169.254.170.2")}}},
		{name: "link_local_v6", addr: "api.vendor.example:443", ips: []net.IPAddr{{IP: net.ParseIP("fe80::1")}}},
		{name: "mapped_link_local", addr: "api.vendor.example:443", ips: []net.IPAddr{{IP: net.ParseIP("::ffff:169.254.170.2")}}},
		{name: "nat64_metadata", addr: "api.vendor.example:443", ips: []net.IPAddr{{IP: net.ParseIP("64:ff9b::a9fe:a9fe")}}},
		{name: "bound_ip", addr: "api.vendor.example:443", ips: []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, wantCall: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			dial := checkedDial(func(context.Context, string) ([]net.IPAddr, error) {
				if tc.lookupErr {
					return nil, errors.New("lookup")
				}
				return tc.ips, nil
			}, func(_ context.Context, _, addr string) (net.Conn, error) {
				called = true
				if addr != "192.0.2.1:443" {
					t.Error(addr)
				}
				return nil, errors.New("dial")
			})
			_, err := dial(t.Context(), "tcp", tc.addr)
			if err == nil || called != tc.wantCall {
				t.Fatalf("err=%v called=%v", err, called)
			}
		})
	}
}

func TestCheckedDialFallback(t *testing.T) {
	ips := []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}, {IP: net.ParseIP("192.0.2.1")}}
	lookups := 0
	lookup := func(context.Context, string) ([]net.IPAddr, error) { lookups++; return ips, nil }
	var dialed []string
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	dial := checkedDial(lookup, func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		if addr == "[2001:db8::1]:443" {
			return nil, errors.New("unreachable")
		}
		return client, nil
	})
	conn, err := dial(t.Context(), "tcp", "api.vendor.example:443")
	if err != nil || conn != client || lookups != 1 || strings.Join(dialed, ",") != "[2001:db8::1]:443,192.0.2.1:443" {
		t.Fatalf("conn=%v err=%v lookups=%d dialed=%v", conn, err, lookups, dialed)
	}
	_ = conn.Close()

	// An expired deadline makes no attempt and reports the context error.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	dialed = nil
	if _, err := checkedDial(lookup, func(context.Context, string, string) (net.Conn, error) {
		dialed = append(dialed, "attempt")
		return nil, errors.New("canceled")
	})(ctx, "tcp", "api.vendor.example:443"); !errors.Is(err, context.Canceled) || len(dialed) != 0 {
		t.Fatalf("err=%v attempts=%d", err, len(dialed))
	}

	// A reachable address after several unreachable ones still connects: the
	// call deadline bounds the walk, not an attempt count.
	many := make([]net.IPAddr, 0, 4)
	for _, s := range []string{"2001:db8::1", "2001:db8::2", "2001:db8::3", "192.0.2.4"} {
		many = append(many, net.IPAddr{IP: net.ParseIP(s)})
	}
	dialed = nil
	reachServer, reachClient := net.Pipe()
	defer func() { _ = reachServer.Close() }()
	conn, err = checkedDial(func(context.Context, string) ([]net.IPAddr, error) { return many, nil }, func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		if addr != "192.0.2.4:443" {
			return nil, errors.New("unreachable")
		}
		return reachClient, nil
	})(t.Context(), "tcp", "api.vendor.example:443")
	if err != nil || conn != reachClient || len(dialed) != len(many) {
		t.Fatalf("conn=%v err=%v dialed=%v", conn, err, dialed)
	}
	_ = conn.Close()
}

func TestUnixSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "runner.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(goodHandler(t))
	_ = server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	var peers atomic.Int32
	client, err := NewClient(Options{Endpoint: "http://localhost/check", UnixSocket: socket, VerifyPeer: func(net.Conn) error { peers.Add(1); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if got := client.Check(t.Context(), testItem(), testPolicy()); got.State != StateBenign {
			t.Fatal(got)
		}
	}
	if peers.Load() != 2 {
		t.Fatalf("peer checks=%d", peers.Load())
	}
	client, err = NewClient(Options{Endpoint: "http://localhost/check", UnixSocket: socket, VerifyPeer: func(net.Conn) error { return errors.New("private detail") }})
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Check(t.Context(), testItem(), testPolicy()); got.Reason != ReasonUnavailable {
		t.Fatal(got)
	}
	client, err = NewClient(Options{Endpoint: "http://localhost/check", UnixSocket: socket})
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Check(t.Context(), testItem(), testPolicy()); got.State != StateBenign {
		t.Fatal(got)
	}
	server.Close()
	if got := client.Check(t.Context(), testItem(), testPolicy()); got.Reason != ReasonUnavailable {
		t.Fatal(got)
	}
}

func TestPolicyValidation(t *testing.T) {
	for _, change := range []func(*Policy){
		func(p *Policy) { p.Mode = "unknown" }, func(p *Policy) { p.Generation = "" }, func(p *Policy) { p.Revision.Model = "" },
		func(p *Policy) { p.MaxRequestBytes = 0 }, func(p *Policy) { p.MaxResponseBytes = 0 }, func(p *Policy) { p.MaxResponseBytes = math.MaxInt64 },
		func(p *Policy) { p.Scale = &Scale{} }, func(p *Policy) { p.Scale = &Scale{Name: "scale", CalibrationID: "cal", Min: 0, Max: math.Inf(1)} },
		func(p *Policy) { p.Scale = &Scale{Name: "scale", CalibrationID: "cal", Min: math.NaN(), Max: 1} },
	} {
		p := testPolicy()
		change(&p)
		if validPolicy(p) {
			t.Fatalf("accepted %+v", p)
		}
	}
	p := testPolicy()
	p.Mode = ModeWarn
	if !validPolicy(p) {
		t.Fatal("warn invalid")
	}
	if failure(StatusNotChecked, ReasonTruncated).State != StateIncomplete {
		t.Fatal("truncation lost")
	}
}

func TestResponseBudgetBoundary(t *testing.T) {
	var responseSize atomic.Int64
	client := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		data, _ := json.Marshal(testResponse(req))
		responseSize.Store(int64(len(data)))
		_, _ = w.Write(data)
	})
	policy := testPolicy()
	if got := client.Check(t.Context(), testItem(), policy); got.State != StateBenign {
		t.Fatal(got)
	}
	policy.MaxResponseBytes = responseSize.Load()
	if got := client.Check(t.Context(), testItem(), policy); got.State != StateBenign {
		t.Fatal(got)
	}
	policy.MaxResponseBytes--
	if got := client.Check(t.Context(), testItem(), policy); got.Status != StatusInvalid || got.Reason != ReasonTooLarge {
		t.Fatal(got)
	}
}

func TestExactUTF8AndBinding(t *testing.T) {
	for _, text := range []string{"", "café\x00<>&\"\n", "a\u200bb"} {
		item := testItem()
		item.Parts[0].Text = text
		item.SubmittedBytes = int64(len(text))
		client := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
			var req Request
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
				return
			}
			var received Item
			if err := json.Unmarshal(req.Item, &received); err != nil {
				t.Error(err)
				return
			}
			if received.Parts[0].Text != text || received.SubmittedBytes != int64(len(text)) || req.InputBinding != Binding(req.Item) {
				t.Error("exact bytes or binding changed")
			}
			_ = json.NewEncoder(w).Encode(testResponse(req))
		})
		if got := client.Check(t.Context(), item, testPolicy()); got.State != StateBenign {
			t.Fatal(got)
		}
	}
}
