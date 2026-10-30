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
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/luckyPipewrench/pipelock/internal/destination"
	"github.com/luckyPipewrench/pipelock/internal/dialfallback"
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
				// Peer checks that read the socket share the call's lifetime.
				stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer stop()
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
		// Checked addresses are tried in RFC 8305 section 4 order (address
		// families interleaved, starting with the resolver's first), bounded
		// by the shared dialfallback.MaxAttempts so the name's owner cannot
		// choose the attempt count. Each attempt gets a share of the remaining
		// call deadline (attemptDeadline) so one silently dropping address
		// cannot starve the rest. No attempt starts after the deadline, and
		// no request bytes are sent before a connection exists.
		candidates := interleaveFamilies(ips)
		if len(candidates) > dialfallback.MaxAttempts {
			candidates = candidates[:dialfallback.MaxAttempts]
		}
		var lastErr error
		for i, ip := range candidates {
			if err := ctx.Err(); err != nil {
				if lastErr == nil {
					lastErr = err
				}
				break
			}
			attemptCtx, cancel := ctx, context.CancelFunc(func() {})
			if deadline, ok := ctx.Deadline(); ok {
				attemptCtx, cancel = context.WithDeadline(ctx, attemptDeadline(time.Now(), deadline, len(candidates)-i))
			}
			conn, dialErr := dial(attemptCtx, network, net.JoinHostPort(ip.IP.String(), port))
			cancel()
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
}

// interleaveFamilies orders addresses as RFC 8305 section 4 describes with a
// First Address Family Count of one: start with the family of the resolver's
// first answer, then alternate families, keeping resolver order within each.
// A name whose leading records are all one unreachable family still reaches
// the other family within the attempt cap.
func interleaveFamilies(ips []net.IPAddr) []net.IPAddr {
	var v4, v6 []net.IPAddr
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	first, second := v6, v4
	if ips[0].IP.To4() != nil {
		first, second = v4, v6
	}
	out := make([]net.IPAddr, 0, len(ips))
	for i := 0; i < len(first) || i < len(second); i++ {
		if i < len(first) {
			out = append(out, first[i])
		}
		if i < len(second) {
			out = append(out, second[i])
		}
	}
	return out
}

// attemptMinimum is the per-address floor Go's own multi-address dialer uses
// (net/dial.go partialDeadline, saneMinimum).
const attemptMinimum = 2 * time.Second

// attemptDeadline mirrors net/dial.go partialDeadline: split the remaining
// call time evenly across the remaining attempts, but give each at least
// attemptMinimum, or all of the remaining time when less is left.
func attemptDeadline(now, deadline time.Time, remaining int) time.Time {
	timeRemaining := deadline.Sub(now)
	timeout := timeRemaining / time.Duration(remaining)
	if timeout < attemptMinimum {
		timeout = min(attemptMinimum, timeRemaining)
	}
	return now.Add(timeout)
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
	// net/http detaches DialContext from the request's cancellation and
	// deadline so it can reuse a late connection. This client forbids reuse:
	// each call owns a transport whose dialer uses the original call context.
	transport := c.http.Transport.(*http.Transport).Clone()
	dial := transport.DialContext
	transport.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
		conn, dialErr := dial(ctx, network, addr)
		if dialErr == nil {
			// TLS setup also uses net/http's detached context. Closing the
			// connection bounds that phase as well as the HTTP exchange.
			context.AfterFunc(ctx, func() { _ = conn.Close() })
		}
		return conn, dialErr
	}
	defer transport.CloseIdleConnections()
	httpClient := *c.http
	httpClient.Transport = transport
	resp, err := httpClient.Do(httpReq)
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
