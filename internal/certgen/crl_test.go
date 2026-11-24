// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package certgen

import (
	"bytes"
	"crypto/x509"
	"math/big"
	"sync"
	"testing"
	"time"
)

const testCRLURL = "http://127.0.0.1:8888/.well-known/pipelock/ca.crl"

func TestCRLLeafAndCache(t *testing.T) {
	ca, key, _, err := GenerateCA("Test", 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cache := mustNewCertCache(t, ca, key, time.Hour, 10)
	if !cache.Matches(ca, time.Hour, 10) || cache.Matches(ca, time.Minute, 10) || cache.Matches(ca, time.Hour, 9) {
		t.Fatal("cache match")
	}
	for _, urls := range [][]string{{testCRLURL}, nil, {testCRLURL + "?new"}} {
		cache.SetCRLDistributionPoints(urls)
		leaf, err := cache.Get("api.vendor.example")
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(leaf.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(cert.CRLDistributionPoints) != len(urls) {
			t.Fatalf("CDPs = %v, want %v", cert.CRLDistributionPoints, urls)
		}
		if len(urls) > 0 && cert.CRLDistributionPoints[0] != urls[0] {
			t.Fatal(cert.CRLDistributionPoints)
		}
		cache.SetCRLDistributionPoints(urls)
		same, err := cache.Get("api.vendor.example")
		if err != nil || leaf != same {
			t.Fatal("unchanged URLs must preserve leaf cache")
		}
	}
	ca.KeyUsage &^= x509.KeyUsageCRLSign
	cache.SetCRLDistributionPoints([]string{testCRLURL})
	leaf, err := cache.Get("no-crl.vendor.example")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.CRLDistributionPoints) != 0 {
		t.Fatal("CA without CRLSign advertised a CDP")
	}
	if _, err := cache.CRL(); err == nil {
		t.Fatal("unsigned CRL must fail")
	}
}

func TestCRLSignatureRefresh(t *testing.T) {
	ca, key, _, err := GenerateCA("Test", 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c := mustNewCertCache(t, ca, key, time.Hour, 10)
	first, err := c.CRL()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.CheckSignatureFrom(ca); err != nil {
		t.Fatal(err)
	}
	if len(parsed.RevokedCertificateEntries) != 0 || parsed.Number.Sign() <= 0 {
		t.Fatal("unexpected CRL contents")
	}
	again, err := c.CRL()
	if err != nil || !bytes.Equal(first, again) {
		t.Fatal("CRL not cached")
	}
	again[0] ^= 1
	if bytes.Equal(again, c.crlDER) {
		t.Fatal("caller can mutate cached DER")
	}
	// No sleeping: drive the refresh boundary using the cache's time input.
	c.mu.Lock()
	refreshed, err := c.crlLocked(parsed.NextUpdate.Add(-time.Hour))
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	next, err := x509.ParseRevocationList(refreshed)
	if err != nil {
		t.Fatal(err)
	}
	if next.Number.Cmp(parsed.Number) <= 0 || !next.NextUpdate.After(parsed.NextUpdate) {
		t.Fatal("CRL did not refresh before expiry")
	}
	if err := next.CheckSignatureFrom(ca); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	// A backwards clock must never reuse an earlier CRL number.
	c.crlNextUpdate = time.Time{}
	backwards, err := c.crlLocked(parsed.ThisUpdate)
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	back, err := x509.ParseRevocationList(backwards)
	if err != nil || back.Number.Cmp(next.Number) <= 0 {
		t.Fatal("CRL number went backwards")
	}
}

func TestGenerateCRLErrors(t *testing.T) {
	ca, key, _, err := GenerateCA("Test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		ca     *x509.Certificate
		key    any
		number *big.Int
	}{
		{"nil CA", nil, key, big.NewInt(1)},
		{"nil key", ca, nil, big.NewInt(1)},
		{"nil number", ca, key, nil},
		{"negative number", ca, key, big.NewInt(-1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := GenerateCRL(tc.ca, tc.key, tc.number, time.Now()); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	ca.KeyUsage &^= x509.KeyUsageCRLSign
	if _, err := GenerateCRL(ca, key, big.NewInt(1), time.Now()); err == nil {
		t.Fatal("missing CRLSign accepted")
	}
}

func TestCRLConcurrentUpdates(t *testing.T) {
	ca, key, _, err := GenerateCA("Test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c := mustNewCertCache(t, ca, key, time.Hour, 10)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				c.SetCRLDistributionPoints([]string{testCRLURL})
				if _, err := c.Get("api.vendor.example"); err != nil {
					t.Error(err)
				}
				if _, err := c.CRL(); err != nil {
					t.Error(err)
				}
				c.SetCRLDistributionPoints(nil)
			}
		})
	}
	wg.Wait()
	c.SetCRLDistributionPoints(nil)
	leaf, err := c.Get("api.vendor.example")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil || len(cert.CRLDistributionPoints) != 0 {
		t.Fatal("stale leaf survived CDP change")
	}
}

func BenchmarkCertCacheCRLLeafHit(b *testing.B) {
	ca, key, _, err := GenerateCA("Test", time.Hour)
	if err != nil {
		b.Fatal(err)
	}
	for _, withCDP := range []bool{false, true} {
		name := "noCDP"
		if withCDP {
			name = "withCDP"
		}
		b.Run(name, func(b *testing.B) {
			c, err := NewCertCache(ca, key, time.Hour, 10)
			if err != nil {
				b.Fatal(err)
			}
			if withCDP {
				c.SetCRLDistributionPoints([]string{testCRLURL})
			}
			if _, err := c.Get("api.vendor.example"); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := c.Get("api.vendor.example"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
