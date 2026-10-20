// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"math"
	"strings"
	"testing"
	"time"
)

const sizeLimitTestHost = "downloads.vendor.example"

func responseSizeLimitTestConfig(now time.Time) *Config {
	c := Defaults()
	c.ResponseScanning.SizeExemptDomains = []string{sizeLimitTestHost, "other.vendor.example"}
	c.ResponseScanning.SizeExemptScanLimits = []ResponseSizeScanLimit{{
		Host: sizeLimitTestHost, MaxBytes: 128 << 20, Owner: "operator", Reason: "bounded scanned download",
		Added: now.Add(-time.Hour).Format(time.RFC3339Nano), Expires: now.Add(14 * 24 * time.Hour).Format(time.RFC3339Nano),
	}}
	return c
}

func TestResponseSizeScanLimitSelection(t *testing.T) {
	now := time.Now().UTC()
	c := responseSizeLimitTestConfig(now)
	r := c.ResponseScanning
	for _, host := range []string{sizeLimitTestHost, "DOWNLOADS.VENDOR.EXAMPLE."} {
		if got := r.SizeExemptScanLimitForHost(host, now); got != 128<<20 {
			t.Fatalf("host %s cap %d", host, got)
		}
	}
	for _, host := range []string{"", "other.vendor.example", "sub." + sizeLimitTestHost, sizeLimitTestHost + ".attacker.example", "vendor.example"} {
		if got := r.SizeExemptScanLimitForHost(host, now); got != r.SizeExemptScanMaxBytes {
			t.Fatalf("grant escaped exact host to %q: %d", host, got)
		}
	}
	added, _ := time.Parse(time.RFC3339, r.SizeExemptScanLimits[0].Added)
	expires, _ := time.Parse(time.RFC3339, r.SizeExemptScanLimits[0].Expires)
	for _, at := range []time.Time{added.Add(-time.Nanosecond), expires, expires.Add(time.Hour)} {
		if got := r.SizeExemptScanLimitForHost(sizeLimitTestHost, at); got != r.SizeExemptScanMaxBytes {
			t.Fatalf("inactive grant cap %d at %v", got, at)
		}
	}
	if got := r.SizeExemptScanLimitForHost(sizeLimitTestHost, added); got != 128<<20 {
		t.Fatalf("grant not active at added: %d", got)
	}
	for _, mode := range []string{"unlisted", "zero", "budget", "added", "expiry", "order", "default", "owner"} {
		t.Run(mode, func(t *testing.T) {
			value := responseSizeLimitTestConfig(now).ResponseScanning
			switch mode {
			case "unlisted":
				value.SizeExemptDomains = nil
			case "zero":
				value.SizeExemptScanLimits[0].MaxBytes = 0
			case "budget":
				value.SizeExemptScanMaxInflightBytes = 1
			case "added":
				value.SizeExemptScanLimits[0].Added = "invalid"
			case "expiry":
				value.SizeExemptScanLimits[0].Expires = "invalid"
			case "order":
				value.SizeExemptScanLimits[0].Added = value.SizeExemptScanLimits[0].Expires
			case "default":
				value.SizeExemptScanMaxBytes = 0
				value.SizeExemptScanLimits = nil
			case "owner":
				value.SizeExemptScanLimits[0].Owner = ""
			}
			if got := value.SizeExemptScanLimitForHost(sizeLimitTestHost, now); got != DefaultSizeExemptScanMaxBytes {
				t.Fatalf("unsafe fallback cap %d", got)
			}
		})
	}
}

func TestResponseSizeScanLimitValidation(t *testing.T) {
	now := time.Now().UTC()
	for _, mode := range []string{"empty", "wildcard", "port", "url", "unlisted", "duplicate", "zero", "lower", "budget", "owner", "reason", "control", "long", "added", "expiry", "order", "probe"} {
		t.Run(mode, func(t *testing.T) {
			c := responseSizeLimitTestConfig(now)
			r := &c.ResponseScanning
			e := &r.SizeExemptScanLimits[0]
			switch mode {
			case "empty":
				e.Host = ""
			case "wildcard":
				e.Host = "*.vendor.example"
			case "port":
				e.Host += ":443"
			case "url":
				e.Host = "https://" + e.Host
			case "unlisted":
				e.Host = "unlisted.example"
			case "duplicate":
				r.SizeExemptScanLimits = append(r.SizeExemptScanLimits, *e)
			case "zero":
				e.MaxBytes = 0
			case "lower":
				e.MaxBytes = r.SizeExemptScanMaxBytes - 1
			case "budget":
				e.MaxBytes = r.SizeExemptScanMaxInflightBytes + 1
			case "probe":
				e.MaxBytes = math.MaxInt
				r.SizeExemptScanMaxInflightBytes = math.MaxInt
				if int64(e.MaxBytes) < math.MaxInt64 {
					e.MaxBytes = 0
				}
			case "owner":
				e.Owner = " "
			case "reason":
				e.Reason = " "
			case "control":
				e.Owner = "operator\nnext"
			case "long":
				e.Reason = strings.Repeat("a", 201)
			case "added":
				e.Added = "invalid"
			case "expiry":
				e.Expires = now.Format("2006-01-02")
			case "order":
				e.Expires = e.Added
			}
			r.Enabled = false // malformed dormant grants must also fail
			if err := c.Validate(); err == nil {
				t.Fatal("invalid grant accepted")
			}
		})
	}
	c := responseSizeLimitTestConfig(now)
	c.ResponseScanning.SizeExemptScanLimits[0].Added = now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
	c.ResponseScanning.SizeExemptScanLimits[0].Expires = now.Add(-time.Hour).Format(time.RFC3339Nano)
	warnings, err := c.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("expired grant refused startup: %v", err)
	}
	found := false
	for _, warning := range warnings {
		if strings.Contains(warning.Field, "size_exempt_scan_limits") && strings.Contains(warning.Message, sizeLimitTestHost) {
			found = true
		}
	}
	if !found {
		t.Fatal("missing expiry warning")
	}
	if got := c.ResponseScanning.SizeExemptScanLimitWarnings(now); len(got) != 1 || !strings.Contains(got[0].Message, sizeLimitTestHost) {
		t.Fatalf("expiry diagnostics lost the grant: %+v", got)
	}
	live := responseSizeLimitTestConfig(now)
	if got := live.ResponseScanning.SizeExemptScanLimitWarnings(now); len(got) != 0 {
		t.Fatalf("live grant warned: %+v", got)
	}
	live.ResponseScanning.SizeExemptScanLimits[0].Expires = "invalid"
	if got := live.ResponseScanning.SizeExemptScanLimitWarnings(now); len(got) != 0 {
		t.Fatalf("malformed grant claimed to be expired: %+v", got)
	}
	// An expired grant must not hold the whole config hostage after its host
	// is removed or its former memory budget is reduced.
	c.ResponseScanning.SizeExemptDomains = nil
	c.ResponseScanning.SizeExemptScanMaxInflightBytes = c.ResponseScanning.SizeExemptScanMaxBytes
	if err := c.Validate(); err != nil {
		t.Fatalf("stale grant blocked otherwise valid config: %v", err)
	}
}

func TestResponseSizeScanLimitCloneAndHash(t *testing.T) {
	now := time.Now().UTC()
	c := responseSizeLimitTestConfig(now)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	clone := c.Clone()
	if clone.CanonicalPolicyHash() != c.CanonicalPolicyHash() {
		t.Fatal("clone changed policy")
	}
	clone.ResponseScanning.SizeExemptScanLimits[0].Host = "other.vendor.example"
	if c.ResponseScanning.SizeExemptScanLimits[0].Host != sizeLimitTestHost {
		t.Fatal("clone aliases source")
	}
	// Fresh clones avoid testing mutation of an intentionally cached policy hash.
	changed := c.Clone()
	changed.ResponseScanning.SizeExemptScanLimits[0].MaxBytes++
	if changed.CanonicalPolicyHash() == c.CanonicalPolicyHash() {
		t.Fatal("cap missing from policy hash")
	}
	other := c.ResponseScanning.SizeExemptScanLimits[0]
	other.Host = "other.vendor.example"
	c.ResponseScanning.SizeExemptScanLimits = append(c.ResponseScanning.SizeExemptScanLimits, other)
	a := c.Clone()
	b := c.Clone()
	b.ResponseScanning.SizeExemptScanLimits[0], b.ResponseScanning.SizeExemptScanLimits[1] = b.ResponseScanning.SizeExemptScanLimits[1], b.ResponseScanning.SizeExemptScanLimits[0]
	b.ResponseScanning.SizeExemptScanLimits[0].Host = "OTHER.VENDOR.EXAMPLE."
	if a.CanonicalPolicyHash() != b.CanonicalPolicyHash() {
		t.Fatal("entry order or host spelling changed policy")
	}
}
