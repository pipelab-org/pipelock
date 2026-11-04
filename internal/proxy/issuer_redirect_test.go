// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/certgen"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	delegationSourceHost = "api.vendor.example"
	delegationFilesHost  = "files.vendor.example"
	delegationSourcePath = "/v1/items/42/content"
	delegationFilesPath  = "/dl/archive.bin"
)

func delegationFixture() config.IssuedRedirectDelegation {
	return config.IssuedRedirectDelegation{
		Name: "download-route",
		Source: config.RequestPolicyRoute{
			Hosts: []string{delegationSourceHost}, Methods: []string{http.MethodGet}, PathPrefixes: []string{"/v1/items/"},
		},
		TargetOrigins: []string{"https://" + delegationFilesHost},
		Reason:        "operator-reviewed download route",
		Owner:         "platform",
		Expires:       time.Now().UTC().Add(24 * time.Hour).Format(time.DateOnly),
	}
}

// delegationEnv drives the production intercept handler for two authorities
// that share one local TLS server: the delegated source and the file host.
type delegationEnv struct {
	t        *testing.T
	upstream *httptest.Server
	cache    *certgen.CertCache
	pool     *x509.CertPool
	cfg      *config.Config
	sc       *scanner.Scanner
	logger   *audit.Logger
	m        *metrics.Metrics
	p        *Proxy
	rt       http.RoundTripper

	status        atomic.Int64
	locations     atomic.Pointer[[]string]
	fileHits      atomic.Int32
	sourceHit     atomic.Int32
	sourcePayload atomic.Pointer[struct{ contentType, body string }]
}

func newDelegationEnv(t *testing.T, mutate func(*config.Config)) *delegationEnv {
	t.Helper()
	e := &delegationEnv{t: t}
	e.status.Store(http.StatusFound)
	e.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.Split(r.Host, ":")[0] {
		case delegationSourceHost, "elsewhere.vendor.example":
			e.sourceHit.Add(1)
			payload := e.sourcePayload.Load()
			if payload != nil {
				w.Header().Set("Content-Type", payload.contentType)
				w.Header().Set("Content-Length", strconv.Itoa(len(payload.body)))
				if payload.contentType == "application/octet-stream" {
					w.Header().Set("Content-Disposition", "attachment")
				}
			}
			if locs := e.locations.Load(); locs != nil {
				for _, l := range *locs {
					w.Header().Add("Location", l)
				}
			}
			w.WriteHeader(int(e.status.Load()))
			if payload != nil {
				_, _ = io.WriteString(w, payload.body)
			}
		default:
			e.fileHits.Add(1)
			_, _ = io.WriteString(w, "file-bytes")
		}
	}))
	t.Cleanup(e.upstream.Close)

	var base *config.Config
	e.cache, e.pool, base, _, _, e.m = testInterceptSetup(t)
	e.cfg = base
	issuerCookieTestConfig(t, e.cfg)
	e.cfg.FetchProxy.Monitoring.IssuedRedirectDelegations = []config.IssuedRedirectDelegation{delegationFixture()}
	if mutate != nil {
		mutate(e.cfg)
	}
	e.sc = scanner.MustNew(e.cfg)
	t.Cleanup(e.sc.Close)
	e.logger = audit.NewNop()
	var err error
	e.p, err = New(e.cfg, e.logger, e.sc, e.m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.p.Close)

	addr := e.upstream.Listener.Addr().String()
	rt := e.upstream.Client().Transport.(*http.Transport).Clone()
	rt.TLSClientConfig = rt.TLSClientConfig.Clone()
	rt.TLSClientConfig.ServerName = e.upstream.Listener.Addr().(*net.TCPAddr).IP.String()
	rt.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	t.Cleanup(rt.CloseIdleConnections)
	e.rt = rt
	return e
}

func (e *delegationEnv) issue(status int, locations ...string) {
	e.status.Store(int64(status))
	e.locations.Store(&locations)
}

// do sends one request through an intercepted tunnel to host:443 as agent.
func (e *delegationEnv) do(agent, method, rawURL string) int {
	e.t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		e.t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, rawURL, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	resp := interceptAndRequestWithRecorder(e.t, interceptRequestOptions{
		Upstream: e.upstream, TargetHost: u.Hostname(), TargetPort: "443", UpstreamRT: e.rt,
		Cache: e.cache, Pool: e.pool, Config: e.cfg, Scanner: e.sc, Logger: e.logger, Metrics: e.m,
		Request: req, Proxy: e.p, Agent: agent, ActorAuth: envelope.ActorAuthBound,
	})
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func delegationFilesURL(path, query string) string {
	raw := "https://" + delegationFilesHost + path
	if query != "" {
		raw += "?" + query
	}
	return raw
}

func delegationSourceURL() string { return "https://" + delegationSourceHost + delegationSourcePath }

func delegationTicketQuery() string {
	return "tempauth=" + issuedTestToken() + "&ApiVersion=2.0"
}

func TestInterceptIssuedRedirectDeliveryPaths(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body string
		passthrough             bool
	}{
		{"SSE", "text/event-stream", "data: ready\n\n", false},
		{"opaque passthrough", "application/octet-stream", strings.Repeat("x", (1<<20)+1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newDelegationEnv(t, func(c *config.Config) {
				if tc.passthrough {
					c.FetchProxy.MaxResponseMB = 1
					c.TLSInterception.MaxResponseBytes = 1 << 20
					c.ResponseScanning.SizeExemptDomains = []string{delegationSourceHost}
					c.ResponseScanning.UnscannablePassthrough = []config.UnscannablePassthroughEntry{{
						Host: delegationSourceHost, Paths: []string{delegationSourcePath},
						ContentTypes: []string{tc.contentType}, Reason: "operator-approved binary route",
						Expires: delegationFixture().Expires,
					}}
				}
			})
			e.sourcePayload.Store(&struct{ contentType, body string }{tc.contentType, tc.body})
			good := delegationFilesURL(delegationFilesPath, delegationTicketQuery())
			if got := e.do("agent-one", http.MethodGet, good); got != http.StatusForbidden {
				t.Fatalf("unissued target status = %d, want 403", got)
			}
			e.issue(http.StatusFound, good)
			if got := e.issueAndFollow(good); got != http.StatusOK {
				t.Fatalf("delivered redirect target status = %d, want 200", got)
			}
			if got := e.do("agent-two", http.MethodGet, good); got != http.StatusForbidden {
				t.Fatalf("other session status = %d, want 403", got)
			}
		})
	}
}

// issueAndFollow issues a redirect from the source and follows location as
// follow, returning the follow-up status.
func (e *delegationEnv) issueAndFollow(follow string) int {
	e.t.Helper()
	if got := e.do("agent-one", http.MethodGet, delegationSourceURL()); got != int(e.status.Load()) {
		e.t.Fatalf("source status = %d, want %d", got, e.status.Load())
	}
	return e.do("agent-one", http.MethodGet, follow)
}

func TestInterceptIssuedRedirectDelegation(t *testing.T) {
	good := delegationFilesURL(delegationFilesPath, delegationTicketQuery())

	t.Run("baseline: the same URL is blocked without evidence", func(t *testing.T) {
		e := newDelegationEnv(t, nil)
		if got := e.do("agent-one", http.MethodGet, good); got != http.StatusForbidden {
			t.Fatalf("unissued URL status = %d, want 403: the premise of every other case", got)
		}
		if e.fileHits.Load() != 0 {
			t.Fatal("the file host was reached")
		}
	})

	t.Run("exact delivered Location is relieved", func(t *testing.T) {
		e := newDelegationEnv(t, nil)
		e.issue(http.StatusFound, good)
		if got := e.issueAndFollow(good); got != http.StatusOK || e.fileHits.Load() != 1 {
			t.Fatalf("follow-up status = %d, file hits = %d, want 200 and 1", got, e.fileHits.Load())
		}
	})

	t.Run("query order may change; nothing else", func(t *testing.T) {
		e := newDelegationEnv(t, nil)
		e.issue(http.StatusFound, good)
		reordered := delegationFilesURL(delegationFilesPath, "ApiVersion=2.0&tempauth="+issuedTestToken())
		if got := e.issueAndFollow(reordered); got != http.StatusOK {
			t.Fatalf("reordered query status = %d, want 200", got)
		}
	})

	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run("status "+http.StatusText(status), func(t *testing.T) {
			e := newDelegationEnv(t, nil)
			e.issue(status, good)
			if got := e.issueAndFollow(good); got != http.StatusOK {
				t.Fatalf("follow-up status = %d, want 200", got)
			}
		})
	}

	for _, tc := range []struct {
		name      string
		status    int
		locations []string
	}{
		{"multiple choices", http.StatusMultipleChoices, []string{good}},
		{"created", http.StatusCreated, []string{good}},
		{"ok", http.StatusOK, []string{good}},
		{"two Location values", http.StatusFound, []string{good, good}},
		{"Location with a space", http.StatusFound, []string{good + " x"}},
		{"Location with a backslash", http.StatusFound, []string{strings.Replace(good, "/dl/", `\dl\`, 1)}},
		{"empty Location", http.StatusFound, []string{""}},
	} {
		t.Run("no evidence from "+tc.name, func(t *testing.T) {
			e := newDelegationEnv(t, nil)
			e.issue(tc.status, tc.locations...)
			if got := e.issueAndFollow(good); got != http.StatusForbidden {
				t.Fatalf("follow-up status = %d, want 403", got)
			}
		})
	}

	t.Run("relative Location resolves against the request that produced it", func(t *testing.T) {
		e := newDelegationEnv(t, func(c *config.Config) {
			c.FetchProxy.Monitoring.IssuedRedirectDelegations[0].TargetOrigins = []string{"https://" + delegationSourceHost}
		})
		relative := "/dl/archive.bin?" + delegationTicketQuery()
		follow := "https://" + delegationSourceHost + relative
		if got := e.do("agent-one", http.MethodGet, follow); got != http.StatusForbidden {
			t.Fatalf("premise: unissued relative target status = %d, want 403", got)
		}
		e.issue(http.StatusFound, relative)
		// The source answers every path on its own host with the redirect, so
		// reaching it (302, not the proxy's 403) is the relief.
		if got := e.issueAndFollow(follow); got != http.StatusFound {
			t.Fatalf("follow-up status = %d, want 302 from the source", got)
		}
	})

	t.Run("fragment is not part of the request", func(t *testing.T) {
		e := newDelegationEnv(t, nil)
		e.issue(http.StatusFound, good+"#frag")
		if got := e.issueAndFollow(good); got != http.StatusOK {
			t.Fatalf("follow-up status = %d, want 200", got)
		}
	})

	// Every variant of the issued URL is a different request.
	for _, tc := range []struct {
		name, follow string
	}{
		{"changed value", delegationFilesURL(delegationFilesPath, "tempauth="+issuedTestToken()+"X&ApiVersion=2.0")},
		{"added parameter", delegationFilesURL(delegationFilesPath, delegationTicketQuery()+"&extra="+issuedTestToken())},
		{"removed parameter", delegationFilesURL(delegationFilesPath, "tempauth="+issuedTestToken())},
		{"duplicated parameter", delegationFilesURL(delegationFilesPath, delegationTicketQuery()+"&ApiVersion=2.0")},
		{"changed path", delegationFilesURL("/dl/other.bin", delegationTicketQuery())},
		{"longer path", delegationFilesURL(delegationFilesPath+"/x", delegationTicketQuery())},
		{"other origin", "https://other.vendor.example" + delegationFilesPath + "?" + delegationTicketQuery()},
		{"value moved to another key", delegationFilesURL(delegationFilesPath, "ApiVersion="+issuedTestToken()+"&tempauth=2.0")},
	} {
		t.Run("no relief for "+tc.name, func(t *testing.T) {
			e := newDelegationEnv(t, nil)
			e.issue(http.StatusFound, good)
			if got := e.issueAndFollow(tc.follow); got != http.StatusForbidden {
				t.Fatalf("follow-up status = %d, want 403", got)
			}
		})
	}

	t.Run("another session gets nothing", func(t *testing.T) {
		e := newDelegationEnv(t, nil)
		e.issue(http.StatusFound, good)
		if got := e.do("agent-one", http.MethodGet, delegationSourceURL()); got != http.StatusFound {
			t.Fatalf("issue status = %d", got)
		}
		if got := e.do("agent-two", http.MethodGet, good); got != http.StatusForbidden {
			t.Fatalf("other session status = %d, want 403", got)
		}
		if got := e.do("agent-one", http.MethodGet, good); got != http.StatusOK {
			t.Fatalf("issuing session status = %d, want 200", got)
		}
	})

	t.Run("a bare request is not evidence", func(t *testing.T) {
		e := newDelegationEnv(t, nil)
		e.issue(http.StatusFound, good)
		// The agent asked for the URL itself; no redirect was delivered.
		if got := e.do("agent-one", http.MethodGet, good); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	// The source must be the declared route.
	for _, tc := range []struct {
		name   string
		method string
		url    string
	}{
		{"wrong method", http.MethodPost, delegationSourceURL()},
		{"path outside the prefix", http.MethodGet, "https://" + delegationSourceHost + "/v2/items/42/content"},
		{"other source host", http.MethodGet, "https://elsewhere.vendor.example" + delegationSourcePath},
	} {
		t.Run("source mismatch: "+tc.name, func(t *testing.T) {
			e := newDelegationEnv(t, nil)
			e.issue(http.StatusFound, good)
			if got := e.do("agent-one", tc.method, tc.url); got != http.StatusFound {
				t.Fatalf("source status = %d, want 302", got)
			}
			if got := e.do("agent-one", http.MethodGet, good); got != http.StatusForbidden {
				t.Fatalf("follow-up status = %d, want 403", got)
			}
		})
	}

	t.Run("target outside the listed origins mints nothing", func(t *testing.T) {
		e := newDelegationEnv(t, nil)
		other := "https://other.vendor.example" + delegationFilesPath + "?" + delegationTicketQuery()
		e.issue(http.StatusFound, other)
		if got := e.issueAndFollow(other); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("an http target is never delegated", func(t *testing.T) {
		e := newDelegationEnv(t, nil)
		plain := "http://" + delegationFilesHost + delegationFilesPath + "?" + delegationTicketQuery()
		e.issue(http.StatusFound, plain)
		e.do("agent-one", http.MethodGet, delegationSourceURL())
		if _, ok := issuedRedirectLocation(&http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {plain}}, Request: httptest.NewRequestWithContext(context.Background(), http.MethodGet, delegationSourceURL(), nil)}, 0); !ok {
			t.Fatal("premise: the Location parses")
		}
		if (issuedRedirectDelegation{targets: map[string]struct{}{delegationFilesHost + "\x00" + "443": {}}}).admits(
			httptest.NewRequestWithContext(context.Background(), http.MethodGet, delegationSourceURL(), nil), mustIssuerQueryURL(t, plain)) {
			t.Fatal("an http target was admitted")
		}
	})

	t.Run("without a delegation nothing is minted", func(t *testing.T) {
		e := newDelegationEnv(t, func(c *config.Config) { c.FetchProxy.Monitoring.IssuedRedirectDelegations = nil })
		e.issue(http.StatusFound, good)
		if got := e.issueAndFollow(good); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("an expired delegation delegates nothing", func(t *testing.T) {
		e := newDelegationEnv(t, func(c *config.Config) {
			// clock-literal-ok: deliberately expired negative case, independent of future clock changes.
			c.FetchProxy.Monitoring.IssuedRedirectDelegations[0].Expires = "2000-01-01"
		})
		e.issue(http.StatusFound, good)
		if got := e.issueAndFollow(good); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("a malformed delegation delegates nothing", func(t *testing.T) {
		e := newDelegationEnv(t, func(c *config.Config) {
			c.FetchProxy.Monitoring.IssuedRedirectDelegations[0].Source.Hosts = nil
		})
		e.issue(http.StatusFound, good)
		if got := e.issueAndFollow(good); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})
}

// A delegation relieves entropy and nothing else.
func TestInterceptIssuedRedirectDoesNotRelieveOtherControls(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mut   func(*config.Config)
		query string
		path  string
	}{
		{"credential in a value (DLP)", nil, "tempauth=" + issuedTestToken() + "&k=" + issuerUnissuedSecret(), delegationFilesPath},
		{"high-entropy query key", nil, issuedTestToken() + "=1", delegationFilesPath},
		{"destination restriction", func(c *config.Config) {
			c.Mode = config.ModeStrict
			c.APIAllowlist = []string{delegationSourceHost}
		}, delegationTicketQuery(), delegationFilesPath},
		{"blocklist", func(c *config.Config) {
			c.FetchProxy.Monitoring.Blocklist = []string{delegationFilesHost}
		}, delegationTicketQuery(), delegationFilesPath},
		{"URL length", func(c *config.Config) {
			c.FetchProxy.Monitoring.MaxURLLength = 80
		}, delegationTicketQuery(), delegationFilesPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newDelegationEnv(t, tc.mut)
			location := delegationFilesURL(tc.path, tc.query)
			e.issue(http.StatusFound, location)
			if got := e.issueAndFollow(location); got != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: the delegation relieved a control it must not", got)
			}
			if e.fileHits.Load() != 0 {
				t.Fatal("the file host was reached")
			}
		})
	}

	t.Run("cloud metadata target stays refused", func(t *testing.T) {
		e := newDelegationEnv(t, func(c *config.Config) {
			c.FetchProxy.Monitoring.IssuedRedirectDelegations[0].TargetOrigins = []string{"https://169.254.169.254"}
		})
		location := "https://169.254.169.254" + delegationFilesPath + "?" + delegationTicketQuery()
		e.issue(http.StatusFound, location)
		e.do("agent-one", http.MethodGet, delegationSourceURL())
		if got := e.do("agent-one", http.MethodGet, location); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})
}

// The operator's other policy neither disables nor is disabled by a delegation.
func TestInterceptIssuedRedirectCoexistsWithOtherPolicy(t *testing.T) {
	good := delegationFilesURL(delegationFilesPath, delegationTicketQuery())
	e := newDelegationEnv(t, func(c *config.Config) {
		// Shapes a real policy carries: a DLP suppression on the source host,
		// request-policy routes naming the source host, host entropy exclusions
		// and a trusted domain. None of them may withdraw the delegation.
		c.Suppress = []config.SuppressEntry{{Rule: "JSON Web Token", Path: "*" + delegationSourceHost + "*", Reason: "source tokens"}}
		c.RequestPolicy.Enabled = true
		c.RequestPolicy.Rules = []config.RequestPolicyRule{{
			Name: "source-mutations", Action: config.ActionBlock, Reason: "no source mutations",
			Route: config.RequestPolicyRoute{Hosts: []string{delegationSourceHost}, Methods: []string{http.MethodDelete}, PathPrefixes: []string{"/v1/items/"}},
		}}
		c.FetchProxy.Monitoring.SubdomainEntropyExclusions = []string{"unrelated.vendor.example"}
		c.TrustedDomains = []string{"unrelated.vendor.example"}
	})
	e.issue(http.StatusFound, good)
	if got := e.issueAndFollow(good); got != http.StatusOK {
		t.Fatalf("status = %d, want 200: other policy withdrew an explicit delegation", got)
	}
	// And the delegation is the whole of the relief: an ordinary suppression
	// on the source host does not make an unissued URL on it pass.
	if got := e.do("agent-two", http.MethodGet, "https://"+delegationSourceHost+delegationSourcePath+"?x="+issuedTestToken()); got != http.StatusForbidden {
		t.Fatalf("suppression made an unissued path pass: status = %d", got)
	}
}

// A delegation is withdrawn per request, including for sessions that already
// hold evidence.
func TestInterceptIssuedRedirectRevocation(t *testing.T) {
	good := delegationFilesURL(delegationFilesPath, delegationTicketQuery())
	e := newDelegationEnv(t, nil)
	e.issue(http.StatusFound, good)
	if got := e.do("agent-one", http.MethodGet, delegationSourceURL()); got != http.StatusFound {
		t.Fatalf("issue status = %d", got)
	}
	live := e.cfg
	withdrawn := func(mutate func(*config.IssuedRedirectDelegation)) *config.Config {
		c := live.Clone()
		if mutate == nil {
			c.FetchProxy.Monitoring.IssuedRedirectDelegations = nil
		} else {
			mutate(&c.FetchProxy.Monitoring.IssuedRedirectDelegations[0])
		}
		return c
	}
	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{
		{"removed", withdrawn(nil)},
		// clock-literal-ok: deliberately expired negative case, independent of future clock changes.
		{"expired", withdrawn(func(d *config.IssuedRedirectDelegation) { d.Expires = "2000-01-01" })},
		{"source narrowed", withdrawn(func(d *config.IssuedRedirectDelegation) { d.Source.PathPrefixes = []string{"/v1/other/"} })},
		{"target changed", withdrawn(func(d *config.IssuedRedirectDelegation) { d.TargetOrigins = []string{"https://other.vendor.example"} })},
		{"method changed", withdrawn(func(d *config.IssuedRedirectDelegation) { d.Source.Methods = []string{http.MethodPost} })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The request still carries the snapshot that minted the evidence;
			// the live policy has moved.
			e.p.cfgPtr.Store(tc.cfg)
			t.Cleanup(func() { e.p.cfgPtr.Store(live) })
			if got := e.do("agent-one", http.MethodGet, good); got != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 after the live policy %s the delegation", got, tc.name)
			}
		})
	}
	t.Run("restored", func(t *testing.T) {
		e.p.cfgPtr.Store(live)
		if got := e.do("agent-one", http.MethodGet, good); got != http.StatusOK {
			t.Fatalf("status = %d, want 200: revocation must be evaluated per request, not erase evidence", got)
		}
	})
	t.Run("renewed expiry keeps evidence, renamed does too", func(t *testing.T) {
		c := live.Clone()
		c.FetchProxy.Monitoring.IssuedRedirectDelegations[0].Expires = time.Now().UTC().Add(72 * time.Hour).Format(time.DateOnly)
		c.FetchProxy.Monitoring.IssuedRedirectDelegations[0].Name = "renamed-route"
		e.p.cfgPtr.Store(c)
		t.Cleanup(func() { e.p.cfgPtr.Store(live) })
		if got := e.do("agent-one", http.MethodGet, good); got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
	})
}

func TestInterceptIssuedRedirectReceipt(t *testing.T) {
	good := delegationFilesURL(delegationFilesPath, delegationTicketQuery())
	for _, tc := range issuerAllowRequireCases {
		t.Run(tc.name, func(t *testing.T) {
			e := newDelegationEnv(t, func(c *config.Config) { c.FlightRecorder.RequireReceipts = tc.require })
			rph := newReceiptProxyHelperWithMetrics(t, e.m)
			e.p.receiptEmitterPtr.Store(rph.emitter)
			e.issue(http.StatusFound, good)
			if got := e.do("agent-one", http.MethodGet, delegationSourceURL()); got != http.StatusFound {
				t.Fatalf("source status = %d, want 302", got)
			}
			if tc.emitFails {
				if err := rph.rec.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if got := e.do("agent-one", http.MethodGet, good); got != tc.wantStatus {
				t.Fatalf("follow-up status = %d, want %d", got, tc.wantStatus)
			}
			if got := e.fileHits.Load(); got != tc.wantUpstream {
				t.Fatalf("file host hits = %d, want %d", got, tc.wantUpstream)
			}
			if tc.require && !tc.emitFails {
				r := rph.requireReceipt(t, issuerQueryReceiptExtensionKey)
				if !strings.Contains(string(r.Ext), `"`+string(issuerQueryIssuedRedirect)+`"`) {
					t.Fatalf("receipt extension = %s, want %s", r.Ext, issuerQueryIssuedRedirect)
				}
				if strings.Contains(string(r.Ext), "tempauth") || strings.Contains(r.ActionRecord.Target, "tempauth") || strings.Contains(r.ActionRecord.Target, "?") {
					t.Fatalf("receipt leaked the signed URL: target=%q ext=%s", r.ActionRecord.Target, r.Ext)
				}
			}
		})
	}
}

// issuedRedirectTail keeps a response open after its initial body bytes.
type issuedRedirectTail struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *issuedRedirectTail) Read(_ []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return 0, io.EOF
}

func TestInterceptIssuedRedirectWhileStreaming(t *testing.T) {
	for _, mode := range []string{"SSE", "opaque passthrough", "response exempt"} {
		t.Run(mode, func(t *testing.T) {
			contentType, prefix := "application/octet-stream", "prefix"
			if mode == "SSE" {
				contentType, prefix = "text/event-stream", "data: ready\n\n"
			}
			if mode == "opaque passthrough" {
				prefix = strings.Repeat("x", (1<<20)+1)
			}
			e := newDelegationEnv(t, func(c *config.Config) {
				if mode == "response exempt" {
					c.ResponseScanning.Enabled = true
					c.ResponseScanning.ExemptDomains = []string{delegationSourceHost}
				}
				if mode == "opaque passthrough" {
					c.TLSInterception.MaxResponseBytes = 1 << 20
					c.ResponseScanning.SizeExemptDomains = []string{delegationSourceHost}
					c.ResponseScanning.UnscannablePassthrough = []config.UnscannablePassthroughEntry{{
						Host: delegationSourceHost, Paths: []string{delegationSourcePath},
						ContentTypes: []string{contentType}, Reason: "operator-approved binary route", Expires: delegationFixture().Expires,
					}}
				}
			})
			tail := &issuedRedirectTail{entered: make(chan struct{}), release: make(chan struct{})}
			good := delegationFilesURL(delegationFilesPath, delegationTicketQuery())
			rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusFound, Header: http.Header{
					"Location": {good}, "Content-Type": {contentType}, "Content-Disposition": {"attachment"},
				}, ContentLength: int64(len(prefix) + 1), Body: io.NopCloser(io.MultiReader(strings.NewReader(prefix), tail)), Request: r}, nil
			})
			ic := &InterceptContext{
				Proxy: e.p, Config: e.cfg, Scanner: e.sc, Logger: e.logger, Metrics: e.m,
				TargetHost: delegationSourceHost, TargetPort: "443", ClientIP: "10.0.0.1", Agent: "agent-one", ActorAuth: envelope.ActorAuthBound,
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, delegationSourceURL(), nil)
			done := make(chan struct{})
			go func() { defer close(done); newInterceptHandler(ic, rt).ServeHTTP(httptest.NewRecorder(), req) }()
			defer func() { close(tail.release); <-done }()
			select {
			case <-tail.entered:
			case <-done:
				t.Fatal("source response ended before the controlled body tail")
			case <-time.After(10 * time.Second):
				t.Fatal("source never began streaming the body tail")
			}
			if got := e.do("agent-one", http.MethodGet, good); got != http.StatusOK {
				t.Fatalf("follow-up during open source stream = %d, want 200", got)
			}
			if got := e.do("agent-two", http.MethodGet, good); got != http.StatusForbidden {
				t.Fatalf("other session during open source stream = %d, want 403", got)
			}
		})
	}
}

type issuedRedirectFlushWriter struct {
	*httptest.ResponseRecorder
	err              error
	calls            int
	afterFlush       func()
	afterWriteHeader func()
}

func (w *issuedRedirectFlushWriter) WriteHeader(status int) {
	w.ResponseRecorder.WriteHeader(status)
	if w.afterWriteHeader != nil {
		w.afterWriteHeader()
	}
}

func (w *issuedRedirectFlushWriter) FlushError() error {
	w.calls++
	if w.err == nil {
		w.Flush()
	}
	if w.afterFlush != nil {
		w.afterFlush()
	}
	return w.err
}

func TestIssuedRedirectHeaderFlush(t *testing.T) {
	for _, mode := range []string{"success", "failed flush", "adaptive failed flush", "missing emitted Location", "unlisted emitted Location", "not a redirect", "untrusted session", "no delegation", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			e := newDelegationEnv(t, nil)
			ic := &InterceptContext{Proxy: e.p, Config: e.cfg, ClientIP: "10.0.0.1", Agent: "agent-one", ActorAuth: envelope.ActorAuthBound}
			target := delegationFilesURL(delegationFilesPath, delegationTicketQuery())
			source := httptest.NewRequestWithContext(t.Context(), http.MethodGet, delegationSourceURL(), nil)
			response := &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {target}}, Request: source}
			w := &issuedRedirectFlushWriter{ResponseRecorder: httptest.NewRecorder()}
			w.Header().Set("Location", target)
			switch mode {
			case "failed flush", "adaptive failed flush":
				w.err = io.ErrClosedPipe
			case "missing emitted Location":
				w.Header().Del("Location")
			case "unlisted emitted Location":
				w.Header().Set("Location", "https://other.vendor.example/file")
			case "not a redirect":
				response.StatusCode = http.StatusOK
			case "untrusted session":
				ic.ActorAuth = envelope.ActorAuthSelfDeclared
			case "no delegation":
				ic.Config = e.cfg.Clone()
				ic.Config.FetchProxy.Monitoring.IssuedRedirectDelegations = nil
			case "revoked":
				live := e.cfg.Clone()
				live.FetchProxy.Monitoring.IssuedRedirectDelegations = nil
				e.p.cfgPtr.Store(live)
			}
			var writer http.ResponseWriter = w
			if mode == "adaptive failed flush" {
				writer = &adaptiveRefusalWriter{ResponseWriter: w, cfg: &e.cfg.AdaptiveEnforcement, level: func() int { return 0 }}
			}
			err := ic.flushIssuedRedirectHeaders(&interceptTimingWriter{ResponseWriter: writer}, response)
			if mode == "failed flush" || mode == "adaptive failed flush" {
				if !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("flush error = %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			wantCalls := 0
			if mode == "success" || mode == "failed flush" || mode == "adaptive failed flush" {
				wantCalls = 1
			}
			if w.calls != wantCalls {
				t.Fatalf("flush calls = %d, want %d", w.calls, wantCalls)
			}
			want := http.StatusForbidden
			if mode == "success" {
				want = http.StatusOK
			}
			if got := e.do("agent-one", http.MethodGet, target); got != want {
				t.Fatalf("follow-up = %d, want %d", got, want)
			}
		})
	}
	var missing *InterceptContext
	if err := missing.flushIssuedRedirectHeaders(httptest.NewRecorder(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestInterceptIssuedRedirectFlushAndBodyErrors(t *testing.T) {
	for _, failFlush := range []bool{true, false} {
		name := "body fails after headers"
		if failFlush {
			name = "header flush fails"
		}
		t.Run(name, func(t *testing.T) {
			e := newDelegationEnv(t, func(c *config.Config) {
				c.ResponseScanning.Enabled = true
				c.ResponseScanning.ExemptDomains = []string{delegationSourceHost}
			})
			target := delegationFilesURL(delegationFilesPath, delegationTicketQuery())
			rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusFound, Header: http.Header{"Location": {target}},
					Body: io.NopCloser(&errorReader{err: io.ErrUnexpectedEOF}), Request: r,
				}, nil
			})
			ic := &InterceptContext{
				Proxy: e.p, Config: e.cfg, Scanner: e.sc, Logger: e.logger, Metrics: e.m,
				TargetHost: delegationSourceHost, TargetPort: "443", ClientIP: "10.0.0.1", Agent: "agent-one", ActorAuth: envelope.ActorAuthBound,
			}
			w := &issuedRedirectFlushWriter{ResponseRecorder: httptest.NewRecorder()}
			if failFlush {
				w.err = io.ErrClosedPipe
			}
			newInterceptHandler(ic, rt).ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, delegationSourceURL(), nil))
			if w.calls != 1 {
				t.Fatalf("flush calls = %d", w.calls)
			}
			want := http.StatusOK
			if failFlush {
				want = http.StatusForbidden
			}
			if got := e.do("agent-one", http.MethodGet, target); got != want {
				t.Fatalf("follow-up = %d, want %d", got, want)
			}
		})
	}
}

func TestInterceptIssuedRedirectFlushFailurePaths(t *testing.T) {
	for _, mode := range []string{"SSE", "opaque passthrough", "buffered"} {
		t.Run(mode, func(t *testing.T) {
			contentType, body := "text/plain", "body"
			if mode == "SSE" {
				contentType, body = "text/event-stream", "data: ready\n\n"
			}
			if mode == "opaque passthrough" {
				contentType, body = "application/octet-stream", strings.Repeat("x", (1<<20)+1)
			}
			e := newDelegationEnv(t, func(c *config.Config) {
				c.AdaptiveEnforcement.Enabled = true
				if mode == "opaque passthrough" {
					c.TLSInterception.MaxResponseBytes = 1 << 20
					c.ResponseScanning.SizeExemptDomains = []string{delegationSourceHost}
					c.ResponseScanning.UnscannablePassthrough = []config.UnscannablePassthroughEntry{{
						Host: delegationSourceHost, Paths: []string{delegationSourcePath},
						ContentTypes: []string{contentType}, Reason: "operator-approved binary route", Expires: delegationFixture().Expires,
					}}
				}
			})
			target := delegationFilesURL(delegationFilesPath, delegationTicketQuery())
			rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusFound, Header: http.Header{
					"Location": {target}, "Content-Type": {contentType}, "Content-Disposition": {"attachment"},
				}, ContentLength: int64(len(body)), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			ic := &InterceptContext{
				Proxy: e.p, Config: e.cfg, Scanner: e.sc, Logger: e.logger, Metrics: e.m,
				TargetHost: delegationSourceHost, TargetPort: "443", ClientIP: "10.0.0.1", Agent: "agent-one", ActorAuth: envelope.ActorAuthBound,
			}
			w := &issuedRedirectFlushWriter{ResponseRecorder: httptest.NewRecorder(), err: io.ErrClosedPipe}
			newInterceptHandler(ic, rt).ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, delegationSourceURL(), nil))
			if w.calls != 1 {
				t.Fatalf("flush calls = %d, want1", w.calls)
			}
			if w.Body.Len() != 0 {
				t.Fatal("body delivered after header flush failed")
			}
			if got := e.do("agent-one", http.MethodGet, target); got != http.StatusForbidden {
				t.Fatalf("failed-delivery target = %d, want403", got)
			}
		})
	}
}

// Done is observed only once the proof lookup is waiting on a pending delivery.
type issuedRedirectWaitContext struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func (c *issuedRedirectWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestIssuedRedirectPendingDelivery(t *testing.T) {
	for _, transport := range []string{"URL", "CONNECT"} {
		for _, outcome := range []string{"success", "header write", "flush fails", "revoked", "runtime replaced", "cancelled"} {
			t.Run(transport+"/"+outcome, func(t *testing.T) {
				e := newDelegationEnv(t, nil)
				ic := &InterceptContext{Proxy: e.p, Config: e.cfg, ClientIP: "10.0.0.1", Agent: "agent-one", ActorAuth: envelope.ActorAuthBound}
				store := ic.issuerQueryStore()
				target := mustIssuerQueryURL(t, delegationFilesURL(delegationFilesPath, delegationTicketQuery()))
				source := httptest.NewRequestWithContext(t.Context(), http.MethodGet, delegationSourceURL(), nil)
				response := &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {target.String()}}, Request: source}
				entered, release := make(chan struct{}), make(chan struct{})
				w := &issuedRedirectFlushWriter{ResponseRecorder: httptest.NewRecorder(), afterFlush: func() { close(entered); <-release }}
				if outcome == "header write" {
					w.afterWriteHeader, w.afterFlush = w.afterFlush, nil
				}
				w.Header().Set("Location", target.String())
				if outcome == "flush fails" {
					w.err = io.ErrClosedPipe
				}
				flushed := make(chan error, 1)
				go func() { flushed <- ic.flushIssuedRedirectHeaders(w, response) }()
				var releaseOnce sync.Once
				t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
				base, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				select {
				case <-entered:
				case <-base.Done():
					t.Fatal("header write or flush callback did not run")
				}
				ctx := &issuedRedirectWaitContext{Context: base, waiting: make(chan struct{})}
				result := make(chan bool, 1)
				go func() {
					if transport == "CONNECT" {
						_, _, allowed := e.p.connectIssuedHostContext(ctx, e.cfg, target.Hostname(), "443", "agent-one", "10.0.0.1", envelope.ActorAuthBound)
						result <- allowed
					} else {
						result <- ic.issuedLocationAllowedContext(ctx, store, sessionKeyFor(e.cfg, ic.Agent, ic.ClientIP, ic.ActorAuth), target)
					}
				}()
				select {
				case <-ctx.waiting:
				case got := <-result:
					t.Fatalf("follow-up completed before flush: %t", got)
				case <-base.Done():
					t.Fatal("follow-up never waited")
				}
				// No global store lock is held across delivery. Other sessions
				// and altered URLs must promptly remain denied.
				other := mustIssuerQueryURL(t, target.String()+"&changed=1")
				if ic.issuedLocationAllowedContext(base, store, "other-session", target) ||
					ic.issuedLocationAllowedContext(base, store, sessionKeyFor(e.cfg, ic.Agent, ic.ClientIP, ic.ActorAuth), other) {
					t.Fatal("unrelated request gained pending authority")
				}
				switch outcome {
				case "revoked":
					live := e.cfg.Clone()
					live.FetchProxy.Monitoring.IssuedRedirectDelegations = nil
					e.p.cfgPtr.Store(live)
				case "runtime replaced":
					e.p.issuerCookieRuntime.Store(nil)
				case "cancelled":
					cancel()
					if <-result {
						t.Fatal("cancelled follow-up allowed")
					}
				}
				releaseOnce.Do(func() { close(release) })
				if err := <-flushed; (err != nil) != (outcome == "flush fails") {
					t.Fatalf("flush error = %v", err)
				}
				if outcome != "cancelled" {
					if got := <-result; got != (outcome == "success" || outcome == "header write") {
						t.Fatalf("follow-up = %t", got)
					}
				}
				store.mu.Lock()
				pending := len(store.deliveries)
				store.mu.Unlock()
				if pending != 0 {
					t.Fatal("completed delivery leaked pending state")
				}
			})
		}
	}
}

func TestIssuedRedirectPendingCapacityAndDuplicates(t *testing.T) {
	s := delegationTestStore(t)
	target := mustIssuerQueryURL(t, delegationFilesURL(delegationFilesPath, delegationTicketQuery()))
	scope := [32]byte{1}
	scopes := map[[32]byte]struct{}{scope: {}}
	s.rememberIssuedLocation("session", target, scope, time.Now())
	first, err := s.beginIssuedRedirectDelivery("session", target, scopes)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.beginIssuedRedirectDelivery("session", target, scopes)
	if err != nil {
		t.Fatal(err)
	}
	s.finishIssuedRedirectDelivery("session", first)
	if !s.issuedLocation("session", target, scopes) {
		t.Fatal("failed duplicate removed prior proof")
	}
	s.finishIssuedRedirectDelivery("session", second)
	if len(s.deliveries) != 0 {
		t.Fatal("duplicate leaked")
	}
	if _, err := s.beginIssuedRedirectDelivery("session", nil, scopes); err == nil {
		t.Fatal("invalid URL admitted")
	}
	if _, err := s.beginIssuedRedirectDelivery("session", target, nil); err == nil {
		t.Fatal("empty scope admitted")
	}
	// Fill pending capacity without touching delivered-evidence capacity.
	for i := 0; i < issuerCookieMaxSessions; i++ {
		session := strconv.Itoa(i)
		d, err := s.beginIssuedRedirectDelivery(session, target, scopes)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.finishIssuedRedirectDelivery(session, d) })
	}
	if _, err := s.beginIssuedRedirectDelivery("overflow", target, scopes); err == nil {
		t.Fatal("session cap ignored")
	}
	for i := 1; i < issuerCookieMaxEntries; i++ {
		d, err := s.beginIssuedRedirectDelivery("0", target, scopes)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.finishIssuedRedirectDelivery("0", d) })
	}
	if _, err := s.beginIssuedRedirectDelivery("0", target, scopes); err == nil {
		t.Fatal("entry cap ignored")
	}
	if !s.issuedLocation("session", target, scopes) {
		t.Fatal("pending capacity evicted delivered proof")
	}
}

func TestIssuedRedirectPendingFailuresAndGuards(t *testing.T) {
	e := newDelegationEnv(t, nil)
	ic := &InterceptContext{Proxy: e.p, Config: e.cfg, ClientIP: "10.0.0.1", Agent: "agent-one", ActorAuth: envelope.ActorAuthBound}
	s := ic.issuerQueryStore()
	target := mustIssuerQueryURL(t, delegationFilesURL(delegationFilesPath, delegationTicketQuery()))
	session := sessionKeyFor(e.cfg, ic.Agent, ic.ClientIP, ic.ActorAuth)
	scopes := issuedRedirectScopes(e.p.issuedRedirects(e.cfg, time.Now()))
	for _, success := range []bool{false, true} {
		first, err := s.beginIssuedRedirectDelivery(session, target, scopes)
		if err != nil {
			t.Fatal(err)
		}
		second, err := s.beginIssuedRedirectDelivery(session, target, scopes)
		if err != nil {
			t.Fatal(err)
		}
		ctx := &issuedRedirectWaitContext{Context: t.Context(), waiting: make(chan struct{})}
		result := make(chan bool, 1)
		go func() { result <- ic.issuedLocationAllowedContext(ctx, s, session, target) }()
		select {
		case <-ctx.waiting:
		case got := <-result:
			t.Fatalf("premature result %t", got)
		case <-t.Context().Done():
			t.Fatal("lookup did not wait")
		}
		s.finishIssuedRedirectDelivery(session, first)
		if success {
			ic.recordIssuedLocation(s, session, &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {target.String()}}, Request: httptest.NewRequestWithContext(t.Context(), http.MethodGet, delegationSourceURL(), nil)})
		}
		s.finishIssuedRedirectDelivery(session, second)
		if got := <-result; got != success {
			t.Fatalf("concurrent completion = %t, want %t", got, success)
		}
	}
	var missing *InterceptContext
	if missing.issuedLocationAllowedContext(t.Context(), s, session, target) ||
		ic.issuedLocationAllowedContext(t.Context(), nil, session, target) ||
		ic.issuedLocationAllowedContext(t.Context(), s, "", target) ||
		ic.issuedLocationAllowedContext(t.Context(), s, session, nil) {
		t.Fatal("invalid lookup admitted")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if ic.issuedLocationAllowedContext(cancelled, s, session, target) {
		t.Fatal("cancelled existing proof admitted")
	}
	empty := e.cfg.Clone()
	empty.FetchProxy.Monitoring.IssuedRedirectDelegations = nil
	ic.Config = empty
	if ic.issuedLocationAllowedContext(t.Context(), s, session, target) {
		t.Fatal("empty delegation admitted")
	}
	ic.Config = nil
	if ic.issuedLocationAllowedContext(t.Context(), s, session, target) {
		t.Fatal("nil configuration admitted")
	}
	ic.Config = e.cfg
	disabled := &issuerQueryStore{disabled: true}
	if ic.issuedLocationAllowedContext(t.Context(), disabled, session, target) {
		t.Fatal("disabled store admitted")
	}
}

func TestIssuedRedirectAdaptiveFlushCompatibility(t *testing.T) {
	base := &issuedRedirectFlushWriter{ResponseRecorder: httptest.NewRecorder()}
	w := &adaptiveRefusalWriter{ResponseWriter: base, cfg: &config.AdaptiveEnforcement{}, level: func() int { return 0 }}
	w.Flush()
	if !base.Flushed || base.Code != http.StatusOK || base.calls != 1 {
		t.Fatal("http.Flusher did not initialize and flush headers")
	}
	base.err = io.ErrClosedPipe
	if err := http.NewResponseController(w).Flush(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("ResponseController flush error = %v", err)
	}
}

func TestIssuedRedirectPendingScopeCapacity(t *testing.T) {
	s := delegationTestStore(t)
	target := mustIssuerQueryURL(t, delegationFilesURL(delegationFilesPath, "id=7"))
	scopes := make(map[[32]byte]struct{}, issuerCookieMaxEntries)
	for i := 0; i < issuerCookieMaxEntries; i++ {
		scopes[s.digestFields(strconv.Itoa(i))] = struct{}{}
	}
	full, err := s.beginIssuedRedirectDelivery("session", target, scopes)
	if err != nil {
		t.Fatal(err)
	}
	one := map[[32]byte]struct{}{{1}: {}}
	if extra, err := s.beginIssuedRedirectDelivery("session", target, one); err == nil {
		s.finishIssuedRedirectDelivery("session", extra)
		t.Fatal("overlapping delegation scopes exceeded the per-session entry budget")
	}
	s.finishIssuedRedirectDelivery("session", full)
	again, err := s.beginIssuedRedirectDelivery("session", target, scopes)
	if err != nil {
		t.Fatalf("finished multi-scope delivery kept pending capacity: %v", err)
	}
	s.finishIssuedRedirectDelivery("session", again)
	// A single oversized delivery must also be refused before allocating its entries.
	scopes[s.digestFields("overflow")] = struct{}{}
	if extra, err := s.beginIssuedRedirectDelivery("other", target, scopes); err == nil {
		s.finishIssuedRedirectDelivery("other", extra)
		t.Fatal("oversized scope set admitted")
	}
}

func TestIssuedRedirectDisabledStoreFlush(t *testing.T) {
	for _, saturated := range []bool{false, true} {
		t.Run(strconv.FormatBool(saturated), func(t *testing.T) {
			e := newDelegationEnv(t, nil)
			ic := &InterceptContext{Proxy: e.p, Config: e.cfg, ClientIP: "10.0.0.1", Agent: "agent-one", ActorAuth: envelope.ActorAuthBound}
			store := newIssuerQueryStoreWithReader(&errorReader{err: io.ErrUnexpectedEOF})
			if !store.disabled {
				t.Fatal("failed random source did not disable issuer store")
			}
			e.p.issuerCookieRuntime.Load().query = store
			store.deliveries = make(map[string]*issuedRedirectDeliverySet)
			if saturated {
				for i := 0; i < issuerCookieMaxSessions; i++ {
					store.deliveries[strconv.Itoa(i)] = &issuedRedirectDeliverySet{}
				}
			}
			target := delegationFilesURL(delegationFilesPath, delegationTicketQuery())
			source := httptest.NewRequestWithContext(t.Context(), http.MethodGet, delegationSourceURL(), nil)
			response := &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {target}}, Request: source}
			w := &issuedRedirectFlushWriter{ResponseRecorder: httptest.NewRecorder()}
			w.Header().Set("Location", target)
			w.afterWriteHeader = func() {
				store.mu.Lock()
				defer store.mu.Unlock()
				for _, bucket := range store.deliveries {
					if bucket.entries != 0 {
						t.Error("disabled store reserved pending capacity")
					}
				}
			}
			if err := ic.flushIssuedRedirectHeaders(w, response); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusFound || w.calls != 0 {
				t.Fatalf("disabled store response/flushes = %d/%d, want 302/0", w.Code, w.calls)
			}
			if got := e.do("agent-one", http.MethodGet, target); got != http.StatusForbidden {
				t.Fatalf("disabled store follow-up = %d, want 403", got)
			}
		})
	}
}
