// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

	status    atomic.Int64
	locations atomic.Pointer[[]string]
	fileHits  atomic.Int32
	sourceHit atomic.Int32
}

func newDelegationEnv(t *testing.T, mutate func(*config.Config)) *delegationEnv {
	t.Helper()
	e := &delegationEnv{t: t}
	e.status.Store(http.StatusFound)
	e.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.Split(r.Host, ":")[0] {
		case delegationSourceHost:
			e.sourceHit.Add(1)
			if locs := e.locations.Load(); locs != nil {
				for _, l := range *locs {
					w.Header().Add("Location", l)
				}
			}
			w.WriteHeader(int(e.status.Load()))
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
			e.do("agent-one", tc.method, tc.url)
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
