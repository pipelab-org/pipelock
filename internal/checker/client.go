// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package checker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"

	"golang.org/x/net/http/httpguts"

	"github.com/luckyPipewrench/pipelock/internal/destination"
)

// ErrOptions is deliberately independent of endpoint or credential values.
var ErrOptions = errors.New("invalid checker client options")

// Options is operator-owned. HTTP requires explicit loopback opt-in, or a Unix
// socket. Authorization is a complete Authorization header value, never a URL.
// VerifyPeer is an optional per-connection socket ownership check. Managed local
// runners must supply it once their platform-specific peer checking is wired.
type Options struct {
	Endpoint          string
	Authorization     string
	AllowLoopbackHTTP bool
	UnixSocket        string
	VerifyPeer        func(net.Conn) error
}

// Client uses a fixed endpoint, a private transport and no retries or proxies.
type Client struct {
	endpoint      string
	authorization string
	http          *http.Client
}

// NewClient captures endpoint and credentials once. DNS is resolved and checked
// at every new connection, and the checked IP is the address actually dialed.
func NewClient(opts Options) (*Client, error) {
	u, err := url.Parse(opts.Endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		// net/http refuses invalid header values on every send; reject them
		// here so a bad credential setting is not reported as an outage.
		u.Fragment != "" || u.Opaque != "" || !httpguts.ValidHeaderFieldValue(opts.Authorization) ||
		(u.Scheme != "https" && u.Scheme != "http") {
		return nil, ErrOptions
	}
	if opts.UnixSocket != "" {
		if !filepath.IsAbs(opts.UnixSocket) || u.Scheme != "http" || u.Host != "localhost" {
			return nil, ErrOptions
		}
	} else if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if !opts.AllowLoopbackHTTP || ip == nil || !ip.IsLoopback() {
			return nil, ErrOptions
		}
	}
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy:              nil,
		DisableCompression: true,
		// Disable reuse as well as application retries: net/http can replay a
		// request on a stale reused connection. Each item gets one connection.
		DisableKeepAlives: true,
	}
	if opts.UnixSocket != "" {
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, dialErr := dialer.DialContext(ctx, "unix", opts.UnixSocket)
			if dialErr != nil {
				return nil, dialErr
			}
			if opts.VerifyPeer != nil {
				if peerErr := opts.VerifyPeer(conn); peerErr != nil {
					_ = conn.Close()
					return nil, errors.New("checker peer verification failed")
				}
			}
			return conn, nil
		}
	} else {
		transport.DialContext = checkedDial(net.DefaultResolver.LookupIPAddr, dialer.DialContext)
	}
	return &Client{
		endpoint: u.String(), authorization: opts.Authorization,
		http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}, nil
}

func checkedDial(lookup func(context.Context, string) ([]net.IPAddr, error), dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, ErrOptions
		}
		ips, err := lookup(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("checker resolution failed")
		}
		// The non-overridable floor covers metadata, link-local (including
		// container credential endpoints), multicast and unspecified addresses
		// in every embedded form. Any refused answer refuses the whole lookup.
		for _, ip := range ips {
			if ip.IP == nil || ip.Zone != "" || destination.IsNonOverridableSSRFTarget(ip.IP) {
				return nil, errors.New("checker destination refused")
			}
		}
		// Only checked addresses are dialed, in resolver order, under the one
		// call deadline. No request bytes are sent before a connection exists.
		var lastErr error
		for _, ip := range ips {
			conn, dialErr := dial(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
			if ctx.Err() != nil {
				break
			}
		}
		return nil, lastErr
	}
}

// Check takes a snapshot by serializing the item before sending it. The caller
// must not mutate item or policy concurrently with this method.
func (c *Client) Check(ctx context.Context, item Item, policy Policy) Assessment {
	if policy.Mode == ModeOff {
		return Assessment{State: StateOff}
	}
	if !validPolicy(policy) {
		return failure(StatusInvalid, ReasonPolicy)
	}
	ctx, cancel := context.WithTimeout(ctx, policy.Timeout)
	defer cancel()
	if item.Kind != KindText {
		return failure(StatusNotChecked, ReasonUnsupported)
	}
	if !validItem(item) {
		return failure(StatusInvalid, ReasonMalformed)
	}
	if item.SubmittedBytes > policy.MaxRequestBytes {
		return failure(StatusNotChecked, ReasonOverBudget)
	}
	data, _ := json.Marshal(item)
	var nonce [32]byte
	_, _ = rand.Read(nonce[:]) // crypto/rand.Read always fills or terminates.
	req := Request{
		Version: Version, ID: hex.EncodeToString(nonce[:]),
		PolicyGeneration: policy.Generation, InputBinding: Binding(data), Item: data,
	}
	body, _ := json.Marshal(req)
	if int64(len(body)) > policy.MaxRequestBytes {
		return failure(StatusNotChecked, ReasonOverBudget)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return failure(StatusInvalid, ReasonMalformed)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if c.authorization != "" {
		httpReq.Header.Set("Authorization", c.authorization)
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return transportFailure(ctx)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest {
		return failure(StatusNotChecked, ReasonRedirect)
	}
	if resp.StatusCode != http.StatusOK {
		return failure(StatusNotChecked, ReasonUnavailable)
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, policy.MaxResponseBytes+1))
	if err != nil {
		return transportFailure(ctx)
	}
	if ctx.Err() != nil {
		return transportFailure(ctx)
	}
	if int64(len(data)) > policy.MaxResponseBytes {
		return failure(StatusInvalid, ReasonTooLarge)
	}
	result := DecodeResponse(data, req, item, policy)
	if ctx.Err() != nil {
		return transportFailure(ctx)
	}
	return result
}

func transportFailure(ctx context.Context) Assessment {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return failure(StatusNotChecked, ReasonTimeout)
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return failure(StatusNotChecked, ReasonCanceled)
	}
	return failure(StatusNotChecked, ReasonUnavailable)
}
