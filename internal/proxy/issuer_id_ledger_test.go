// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ledgerTestID is a server-shaped ID that no test request sends first.
func ledgerTestID() string {
	return strings.Join([]string{"Srv1Qx7M", "pL2nZ8wK", "c4Vb6TyR", "h9Jd3"}, "")
}

// newInitiallyDisabledIssuerProxy starts a process whose first runtime has
// issuer evidence off; the returned config re-enables it.
func newInitiallyDisabledIssuerProxy(t *testing.T) (*Proxy, *config.Config) {
	t.Helper()
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	off := cfg.Clone()
	off.RequestBodyScanning.IssuerBoundSessionCookies = false
	sc := scanner.MustNew(off)
	t.Cleanup(sc.Close)
	p, err := New(off, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p, cfg
}

func reloadIssuerFlag(t *testing.T, p *Proxy, base *config.Config, enabled bool) *config.Config {
	t.Helper()
	next := base.Clone()
	next.RequestBodyScanning.IssuerBoundSessionCookies = enabled
	if !p.Reload(next, scanner.MustNew(next)) {
		t.Fatalf("reload to issuer evidence %v failed", enabled)
	}
	return next
}

// destinationFrozen reports whether the caller's bucket for target exists and
// refuses learning.
func destinationFrozen(s *issuerQueryStore, session string, target *url.URL) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket := s.idDestinationLocked(session, target)
	return bucket != nil && bucket.block != issuerHistoryComplete
}

// A reload that disables and re-enables issuer evidence must not forget what
// the caller sent, whichever store a sender captured and whenever a stream
// froze the destination. Each case ends with a reflected value that must not
// become an ID.
func TestIssuerIDLedgerSurvivesPrerequisiteReload(t *testing.T) {
	const agent, clientIP = "reader", "192.0.2.1"
	auth := envelope.ActorAuthBound
	for _, mode := range []string{
		"stream-before-disable",
		"stream-while-disabled",
		"captured-record-after-reenable",
		"captured-record-while-disabled",
		"initially-disabled",
		"repeated-disable",
	} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			var p *Proxy
			var cfg *config.Config
			if mode == "initially-disabled" {
				p, cfg = newInitiallyDisabledIssuerProxy(t)
			} else {
				p, cfg = newSentIssuerProxy(t)
			}
			key := sessionKeyFor(cfg, agent, clientIP, auth)
			origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
			if mode == "initially-disabled" {
				p.issuerStoreForUnmediatedSend().recordSent(key, origin, nil, []byte(agentBlob), true, time.Now())
			}
			old := p.issuerStoreForUnmediatedSend()
			if mode == "stream-before-disable" {
				p.taintIssuerSessionForStream(cfg, agent, clientIP, auth, origin)
			}
			off := reloadIssuerFlag(t, p, cfg, false)
			if mode == "stream-while-disabled" {
				p.taintIssuerSessionForStream(off, agent, clientIP, auth, origin)
			}
			if mode == "captured-record-while-disabled" {
				old.recordSent(key, origin, nil, []byte(agentBlob), true, time.Now())
			}
			if mode == "repeated-disable" {
				p.issuerStoreForUnmediatedSend().recordSent(key, origin, nil, []byte(agentBlob), true, time.Now())
				off = reloadIssuerFlag(t, p, off, false)
			}
			reloadIssuerFlag(t, p, off, true)
			if mode == "captured-record-after-reenable" {
				old.recordSent(key, origin, nil, []byte(agentBlob), true, time.Now())
			}
			live := p.issuerStoreForUnmediatedSend()
			if live == old {
				t.Fatal("disabling reload kept the positive generation")
			}
			live.recordSent(key, origin, nil, nil, true, time.Now())
			live.mintServerID(key, origin, agentBlob, time.Now())
			if live.serverIDIssued(key, origin, agentBlob) {
				t.Fatal("reload forgot history and admitted a reflected value")
			}
			if live.issuerIDLedger != old.issuerIDLedger {
				t.Fatal("generations do not share one ledger")
			}
		})
	}
}

// Disabling still revokes every positive allowance. A replaced generation
// cannot grant, mint, or stamp server-first provenance into the shared ledger,
// while provenance recorded before the reload remains valid.
func TestIssuerIDLedgerRevokesPositiveGenerations(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	p, cfg := newSentIssuerProxy(t)
	key := sessionKeyFor(cfg, "reader", "192.0.2.1", envelope.ActorAuthBound)
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	id := ledgerTestID()
	itemPath := mustIssuerQueryURL(t, "https://api.vendor.example/items/"+id)

	old := p.issuerStoreForUnmediatedSend()
	old.recordSent(key, origin, nil, nil, true, time.Now())
	old.mintServerID(key, origin, id, time.Now())
	if !old.serverIDIssued(key, itemPath, id) {
		t.Fatal("setup: unsent server value was not minted")
	}
	off := reloadIssuerFlag(t, p, cfg, false)
	reloadIssuerFlag(t, p, off, true)
	live := p.issuerStoreForUnmediatedSend()
	if live.serverIDIssued(key, itemPath, id) {
		t.Fatal("re-enable revived a revoked allowance")
	}
	if old.serverIDIssued(key, itemPath, id) {
		t.Fatal("retired generation still grants its allowance")
	}
	other := ledgerTestID() + "Z"
	before := retiredIDCount(old, key)
	old.mintServerID(key, origin, other, time.Now())
	if retiredIDCount(old, key) != before || live.serverIDIssued(key, itemPath, other) {
		t.Fatal("retired generation minted an allowance")
	}
	// The stale sender uses the revoked ID. Its words enter the shared ledger
	// as agent-first, so the live generation cannot mint that ID from a
	// later reflection.
	old.recordSent(key, itemPath, nil, nil, true, time.Now())
	live.mintServerID(key, origin, id, time.Now())
	if live.serverIDIssued(key, itemPath, id) {
		t.Fatal("retired generation stamped server-first provenance")
	}
}

// Server-first provenance recorded while an allowance was live keeps working
// after a toggle: the origin listing the same ID again re-mints it.
func TestIssuerIDLedgerKeepsServerFirstProvenance(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	p, cfg := newSentIssuerProxy(t)
	key := sessionKeyFor(cfg, "reader", "192.0.2.1", envelope.ActorAuthBound)
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	id := ledgerTestID()
	itemPath := mustIssuerQueryURL(t, "https://api.vendor.example/items/"+id)
	store := p.issuerStoreForUnmediatedSend()
	store.recordSent(key, origin, nil, nil, true, time.Now())
	store.mintServerID(key, origin, id, time.Now())
	store.recordSent(key, itemPath, nil, nil, true, time.Now())

	off := reloadIssuerFlag(t, p, cfg, false)
	reloadIssuerFlag(t, p, off, true)
	live := p.issuerStoreForUnmediatedSend()
	live.mintServerID(key, origin, id, time.Now())
	if !live.serverIDIssued(key, itemPath, id) {
		t.Fatal("server-first provenance was lost across the toggle")
	}
}

// Freezes and the admission latch are permanent across toggles, while an
// unaffected destination and another caller still learn independently.
func TestIssuerIDLedgerKeepsFreezesAndLatches(t *testing.T) {
	t.Run("destination freeze", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", t.TempDir())
		p, cfg := newSentIssuerProxy(t)
		key := sessionKeyFor(cfg, "reader", "192.0.2.1", envelope.ActorAuthBound)
		otherKey := sessionKeyFor(cfg, "writer", "192.0.2.2", envelope.ActorAuthBound)
		frozen := mustIssuerQueryURL(t, "https://api.vendor.example/items")
		open := mustIssuerQueryURL(t, "https://files.vendor.example/items")
		p.issuerStoreForUnmediatedSend().recordSent(key, frozen, nil, nil, false, time.Now())

		off := reloadIssuerFlag(t, p, cfg, false)
		reloadIssuerFlag(t, p, off, true)
		live := p.issuerStoreForUnmediatedSend()
		if !destinationFrozen(live, key, frozen) {
			t.Fatal("toggle cleared a destination freeze")
		}
		id := ledgerTestID()
		live.mintServerID(key, frozen, id, time.Now())
		if live.serverIDIssued(key, frozen, id) {
			t.Fatal("frozen destination learned after toggle")
		}
		for _, c := range []struct {
			name    string
			session string
			target  *url.URL
		}{{"other host", key, open}, {"other caller", otherKey, frozen}} {
			live.recordSent(c.session, c.target, nil, nil, true, time.Now())
			live.mintServerID(c.session, c.target, id, time.Now())
			if !live.serverIDIssued(c.session, c.target, id) {
				t.Fatalf("%s did not learn independently", c.name)
			}
		}
	})
	t.Run("caller freeze and admission latch", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", t.TempDir())
		p, cfg := newSentIssuerProxy(t)
		key := sessionKeyFor(cfg, "reader", "192.0.2.1", envelope.ActorAuthBound)
		store := p.issuerStoreForUnmediatedSend()
		store.recordSent(key, nil, nil, nil, true, time.Now())
		store.mu.Lock()
		store.closeIDAdmissionLocked()
		store.mu.Unlock()

		off := reloadIssuerFlag(t, p, cfg, false)
		reloadIssuerFlag(t, p, off, true)
		live := p.issuerStoreForUnmediatedSend()
		live.mu.Lock()
		defer live.mu.Unlock()
		if caller := live.history[key]; caller == nil || caller.block != issuerHistoryUnknownDestination {
			t.Fatal("toggle cleared the caller-wide freeze")
		}
		if !live.idAdmissionClosed || live.admitIDCallerLocked("fresh-caller") != nil {
			t.Fatal("toggle reopened closed admission")
		}
	})
}

func retiredIDCount(s *issuerQueryStore, session string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.idCount(session)
}

// idCount reads the caller's retained proof count; callers serialize access.
func (s *issuerQueryStore) idCount(session string) int {
	if c := s.ids[session]; c != nil {
		return len(c.entries)
	}
	return 0
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no randomness") }

// A ledger without a key stays disabled in every later generation.
func TestIssuerIDLedgerDisabledKeyPersists(t *testing.T) {
	first := newIssuerQueryStoreWithReader(failingReader{})
	next := first.nextGeneration()
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	next.recordSent("caller", origin, nil, nil, true, time.Now())
	next.mintServerID("caller", origin, ledgerTestID(), time.Now())
	if !next.disabled || next.serverIDIssued("caller", origin, ledgerTestID()) {
		t.Fatal("new generation of a disabled ledger granted evidence")
	}
}

// reverseIssuerHarness serves a trusted bound default caller.
func reverseIssuerHarness(t *testing.T, mutate func(*config.Config), handler http.HandlerFunc) (*ReverseProxyHandler, *Proxy, *config.Config, *url.URL) {
	t.Helper()
	cfg := reverseParityBaseConfig(t)
	cfg.TLSInterception.Enabled = true
	cfg.DefaultAgentIdentity = "reader"
	cfg.BindDefaultAgentIdentity = true
	if mutate != nil {
		mutate(cfg)
	}
	rp, p, origin := newReverseParityHarness(t, cfg, handler)
	target := *origin
	target.Scheme = "https"
	return rp, p, cfg, &target
}

// Every request the reverse proxy forwards enters the shared ledger under the
// caller's resolved identity, with the rewritten URL, headers and exact body,
// signed or not, before any byte reaches the upstream.
func TestReverseIssuerSendRecordsHistory(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(*config.Config)
		sign   bool
		method string
		path   string
		body   []byte
		header http.Header
		frozen bool
	}{
		{name: "unsigned body", method: http.MethodPost, path: "/messages", body: []byte(agentBlob)},
		{name: "signed body", sign: true, method: http.MethodPost, path: "/messages", body: []byte(agentBlob)},
		{name: "query", method: http.MethodGet, path: "/messages?q=" + agentBlob},
		{name: "header", method: http.MethodGet, path: "/messages", header: http.Header{"X-Note": {agentBlob}}},
		{name: "unbuffered body", mutate: func(cfg *config.Config) { cfg.RequestBodyScanning.Enabled = false }, method: http.MethodPost, path: "/messages", body: []byte(agentBlob), frozen: true},
		{name: "upgrade", method: http.MethodGet, path: "/socket", header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}}, frozen: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var p *Proxy
			var key string
			var target *url.URL
			recordedBeforeSend, gotSignature := false, false
			rp, owner, cfg, origin := reverseIssuerHarness(t, c.mutate, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				gotSignature = r.Header.Get("Signature") != ""
				store := p.issuerStoreForUnmediatedSend()
				if c.frozen {
					recordedBeforeSend = destinationFrozen(store, key, target)
				} else {
					store.mu.Lock()
					recordedBeforeSend = store.idDestinationLocked(key, target) != nil
					store.mu.Unlock()
				}
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("ok"))
			})
			p, target = owner, origin
			key = sessionKeyFor(cfg, "reader", "192.0.2.1", envelope.ActorAuthConfigDefault)
			if c.sign {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				signer, err := envelope.NewSigner(envelope.SignerConfig{
					PrivKey: priv, KeyID: config.DefaultEnvelopeSignKeyID,
					SignedComponents: config.DefaultEnvelopeSignedComponents(), MaxBodyBytes: config.DefaultEnvelopeSignMaxBodyBytes,
				})
				if err != nil {
					t.Fatal(err)
				}
				var emPtr atomic.Pointer[envelope.Emitter]
				emPtr.Store(envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: cfg.CanonicalPolicyHash(), Signer: signer}))
				rp.SetEnvelopeEmitter(&emPtr)
			}
			req := httptest.NewRequestWithContext(t.Context(), c.method, "http://proxy.vendor.example"+c.path, http.NoBody)
			if c.body != nil {
				req = httptest.NewRequestWithContext(t.Context(), c.method, "http://proxy.vendor.example"+c.path, strings.NewReader(string(c.body)))
			}
			for name, values := range c.header {
				req.Header[name] = values
			}
			req.RemoteAddr = "192.0.2.1:1234"
			rec := httptest.NewRecorder()
			rp.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("request not delivered: %d %s", rec.Code, rec.Body.String())
			}
			if gotSignature != c.sign {
				t.Fatalf("upstream signature present = %v, want %v", gotSignature, c.sign)
			}
			if !recordedBeforeSend {
				t.Fatal("history was not recorded before the upstream received the request")
			}
			store := p.issuerStoreForUnmediatedSend()
			if c.frozen {
				return
			}
			store.mintServerID(key, target, agentBlob, time.Now())
			if store.serverIDIssued(key, target, agentBlob) {
				t.Fatal("reverse send missing from same-caller reflection history")
			}
		})
	}
}

// Reverse recording mutates only trusted state, and a blocked request
// neither reaches the upstream nor enters history.
func TestReverseIssuerSendRefusals(t *testing.T) {
	t.Run("untrusted caller", func(t *testing.T) {
		cfg := reverseParityBaseConfig(t)
		cfg.TLSInterception.Enabled = true
		rp, p, _ := newReverseParityHarness(t, cfg, nil)
		rec := reverseParityRequest(t, rp, http.MethodPost, "http://proxy.vendor.example/messages", "192.0.2.1:1234", []byte(agentBlob))
		if rec.Code != http.StatusOK {
			t.Fatalf("request not delivered: %d", rec.Code)
		}
		store := p.issuerStoreForUnmediatedSend()
		store.mu.Lock()
		defer store.mu.Unlock()
		if len(store.history) != 0 {
			t.Fatal("untrusted reverse caller mutated issuer history")
		}
	})
	t.Run("blocked request", func(t *testing.T) {
		delivered := false
		rp, p, _, _ := reverseIssuerHarness(t, nil, func(w http.ResponseWriter, _ *http.Request) {
			delivered = true
			w.WriteHeader(http.StatusOK)
		})
		secret := "ghp_" + strings.Repeat("aB3x", 9)
		rec := reverseParityRequest(t, rp, http.MethodPost, "http://proxy.vendor.example/messages", "192.0.2.1:1234", []byte("token="+secret))
		if rec.Code == http.StatusOK || delivered {
			t.Fatalf("setup: secret body was not blocked: %d", rec.Code)
		}
		store := p.issuerStoreForUnmediatedSend()
		store.mu.Lock()
		defer store.mu.Unlock()
		if len(store.history) != 0 {
			t.Fatal("blocked reverse request entered issuer history")
		}
	})
}

// Senders holding whichever generation they loaded race prerequisite toggles.
// Every send lands in the one ledger under its shared lock.
func TestIssuerIDLedgerConcurrentReloadRecording(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	p, cfg := newSentIssuerProxy(t)
	key := sessionKeyFor(cfg, "reader", "192.0.2.1", envelope.ActorAuthBound)
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 8; i++ {
			store := p.issuerStoreForUnmediatedSend()
			store.recordSent(key, origin, nil, []byte(agentBlob), true, time.Now())
			store.mintServerID(key, origin, ledgerTestID(), time.Now())
			_ = store.serverIDIssued(key, origin, ledgerTestID())
		}
	}()
	current := cfg
	for i := 0; i < 8; i++ {
		current = reloadIssuerFlag(t, p, current, i%2 == 1)
	}
	<-done
	reloadIssuerFlag(t, p, current, true)
	live := p.issuerStoreForUnmediatedSend()
	live.recordSent(key, origin, nil, nil, true, time.Now())
	live.mintServerID(key, origin, agentBlob, time.Now())
	if live.serverIDIssued(key, origin, agentBlob) {
		t.Fatal("a send racing reloads was lost from the ledger")
	}
}
