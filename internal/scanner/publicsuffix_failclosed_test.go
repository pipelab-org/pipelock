// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/net/publicsuffix"
)

// publicSuffixErrorClass is one return from golang.org/x/net/publicsuffix
// EffectiveTLDPlusOne (list.go). The three fmt.Errorf texts are the whole set.
const (
	publicSuffixClassNone    = "none"
	publicSuffixClassDerive  = "cannot-derive"
	publicSuffixClassEmpty   = "empty-label"
	publicSuffixClassInvalid = "invalid-suffix"
	publicSuffixClassOther   = "other"
)

func publicSuffixErrorClass(host string) string {
	_, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err == nil {
		return publicSuffixClassNone
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "empty label"):
		return publicSuffixClassEmpty
	case strings.Contains(msg, "cannot derive eTLD+1"):
		return publicSuffixClassDerive
	case strings.Contains(msg, "invalid public suffix"):
		return publicSuffixClassInvalid
	default:
		return publicSuffixClassOther
	}
}

// checkSubdomainEntropy trims one trailing root dot before the lookup.
// Classify the same spelling the lookup sees.
func suffixLookupHost(hostname string) string {
	return strings.TrimSuffix(hostname, ".")
}

func TestPublicSuffixLookupErrorClasses(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.DLP.Patterns = nil
	s := MustNew(cfg)
	t.Cleanup(s.Close)

	// Hosts are what checkSubdomainEntropy receives: lowercased, one trailing
	// dot still present when the caller kept an FQDN root.
	cases := []struct {
		name      string
		host      string
		class     string
		wantAllow bool
	}{
		{name: "public suffix", host: "com", class: publicSuffixClassDerive, wantAllow: true},
		{name: "multi-label public suffix", host: "co.uk", class: publicSuffixClassDerive, wantAllow: true},
		{name: "private suffix", host: "github.io", class: publicSuffixClassDerive, wantAllow: true},
		{name: "private suffix blogspot", host: "blogspot.com", class: publicSuffixClassDerive, wantAllow: true},
		{name: "wildcard suffix itself", host: "c.mm", class: publicSuffixClassDerive, wantAllow: true},
		{name: "single-label localhost", host: "localhost", class: publicSuffixClassDerive, wantAllow: true},
		{name: "single-label intranet", host: "intranet", class: publicSuffixClassDerive, wantAllow: true},
		{name: "ordinary host", host: "api.vendor.example", class: publicSuffixClassNone, wantAllow: true},
		{name: "ccTLD host", host: "a.b.c.example.co.uk", class: publicSuffixClassNone, wantAllow: true},
		{name: "punycode host", host: "xn--n3h.example", class: publicSuffixClassNone, wantAllow: true},
		{name: "trailing-dot FQDN", host: "api.vendor.example.", class: publicSuffixClassNone, wantAllow: true},
		{name: "registrable exception host", host: "www.ck", class: publicSuffixClassNone, wantAllow: true},
		{name: "ip literal skipped", host: "127.0.0.1", class: publicSuffixClassDerive, wantAllow: true},
		{name: "empty label pair", host: "abcd0123456789ef..evil.example", class: publicSuffixClassEmpty, wantAllow: false},
		{name: "leading dot", host: ".example", class: publicSuffixClassEmpty, wantAllow: false},
		{name: "second trailing dot", host: "example..", class: publicSuffixClassEmpty, wantAllow: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := publicSuffixErrorClass(suffixLookupHost(tc.host)); got != tc.class {
				t.Fatalf("EffectiveTLDPlusOne class = %s, want %s", got, tc.class)
			}
			got := s.checkSubdomainEntropy(tc.host)
			if got.Allowed != tc.wantAllow {
				t.Fatalf("allowed = %v, want %v (reason %q scanner %q)", got.Allowed, tc.wantAllow, got.Reason, got.Scanner)
			}
			if !tc.wantAllow {
				if got.Scanner != ScannerSubdomainEntropy {
					t.Fatalf("scanner = %q, want %s", got.Scanner, ScannerSubdomainEntropy)
				}
				if got.Reason != publicSuffixLookupFailedReason {
					t.Fatalf("reason = %q, want %q", got.Reason, publicSuffixLookupFailedReason)
				}
				if strings.Contains(got.Reason, "evil") || strings.Contains(got.Reason, "example") || got.IsEntropyOnly() {
					t.Fatalf("lookup failure must not echo the host or look like heuristic entropy: %+v", got)
				}
			}
		})
	}
}

// The invalid-suffix error is a real EffectiveTLDPlusOne return. x/net v0.62.0
// does not produce it for a host the empty-label check accepts, so the class
// is applied to a normal host with that error. A cannot-derive host stays benign.
func TestPublicSuffixInvalidSuffixClassFailsClosed(t *testing.T) {
	t.Parallel()
	const host = "api.vendor.example"
	if publicSuffixErrorClass(host) != publicSuffixClassNone {
		t.Fatalf("control host class = %s, want none", publicSuffixErrorClass(host))
	}
	invalid := errors.New(`publicsuffix: invalid public suffix "example" for domain "api.vendor.example"`)
	if !unexpectedPublicSuffixLookup(host, invalid) {
		t.Fatal("invalid public suffix error was treated as benign")
	}
	derive := errors.New(`publicsuffix: cannot derive eTLD+1 for domain "localhost"`)
	if unexpectedPublicSuffixLookup("localhost", derive) {
		t.Fatal("cannot-derive error was treated as unexpected")
	}
	empty := errors.New(`publicsuffix: empty label in domain "foo..example"`)
	if !unexpectedPublicSuffixLookup("foo..example", empty) {
		t.Fatal("empty-label error was treated as benign")
	}

	// No host in this set produces the invalid-suffix class. If one ever does,
	// the lookup must block it.
	for _, candidate := range []string{
		"www.ck", "foo.www.ck", "www.www.ck", "test.ck", "b.test.ck",
		"c.mm", "b.c.mm", "com", "github.io", "api.vendor.example",
		".com", "com.", "com..au", "foo..bar",
	} {
		class := publicSuffixErrorClass(candidate)
		if class != publicSuffixClassInvalid {
			continue
		}
		cfg := testConfig()
		cfg.DLP.Patterns = nil
		s := MustNew(cfg)
		t.Cleanup(s.Close)
		got := s.checkSubdomainEntropy(candidate)
		if got.Allowed || got.Reason != publicSuffixLookupFailedReason {
			t.Fatalf("%s invalid-suffix lookup allowed: %+v", candidate, got)
		}
	}
}

// Text inspection calls checkSubdomainEntropy on hosts parsed out of the text.
// It does not go through destination.New, so an empty label reaches the lookup.
func TestTextDLPEmptyLabelHostFailsClosed(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.DLP.Patterns = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)

	text := "see https://foo..bar.example/docs"
	got := s.ScanTextForDLP(context.Background(), text)
	if got.Clean || !ContainsHostnameExfilMatch(got.Matches) {
		t.Fatalf("empty-label host in text was not refused: %+v", got)
	}
	plain := s.ScanTextForDLP(context.Background(), "see https://api.vendor.example/docs")
	if !plain.Clean || ContainsHostnameExfilMatch(plain.Matches) {
		t.Fatalf("ordinary host in text was refused: %+v", plain)
	}
}

// Scan rejects an empty DNS label as an invalid destination before subdomain
// entropy runs. The lookup fail-open is not what Scan returns for that URL.
func TestScanEmptyLabelRejectedBeforeSuffixLookup(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.DLP.Patterns = nil
	s := MustNew(cfg)
	t.Cleanup(s.Close)

	blocked := []string{
		"https://abcd0123456789ef..evil.example/a",
		"https://.example/a",
		"https://example../a",
	}
	for _, raw := range blocked {
		got := s.Scan(context.Background(), raw)
		if got.Allowed {
			t.Fatalf("%s allowed: %+v", raw, got)
		}
		if got.Scanner == ScannerSubdomainEntropy {
			t.Fatalf("%s reached subdomain entropy: %+v", raw, got)
		}
	}

	allowed := []string{
		"https://api.vendor.example/v1",
		"https://a.b.c.example.co.uk/v1",
		"https://xn--n3h.example/v1",
		"https://api.vendor.example./v1",
		"https://localhost/v1",
		"https://intranet/v1",
		"https://com/v1",
		"https://github.io/v1",
		"https://www.ck/v1",
	}
	for _, raw := range allowed {
		got := s.Scan(context.Background(), raw)
		if !got.Allowed {
			t.Fatalf("%s blocked by %s: %s", raw, got.Scanner, got.Reason)
		}
	}
}
