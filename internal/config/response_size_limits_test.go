// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const sizeLimitTestHost = "downloads.vendor.example"

func TestResponseSizeScanLimitHorizon(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name           string
		added, expires time.Time
		valid          bool
	}{
		{"approved", now, now.Add(14 * 24 * time.Hour), true},
		{"century", now, now.AddDate(100, 0, 0), false},
		{"boundary", now, now.Add(MaxResponseSizeScanLimitHorizon), true},
		{"over", now, now.Add(MaxResponseSizeScanLimitHorizon + time.Second), false},
		{"ancient-start", now.Add(-MaxResponseSizeScanLimitHorizon), now.Add(time.Hour), false},
		{"future-start", now.Add(MaxResponseSizeScanLimitHorizon), now.Add(2 * MaxResponseSizeScanLimitHorizon), false},
		{"lapsed", now.Add(-2 * MaxResponseSizeScanLimitHorizon), now.Add(-time.Hour), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := responseSizeLimitTestConfig(now)
			entry := &c.ResponseScanning.SizeExemptScanLimits[0]
			entry.Added, entry.Expires = tc.added.Format(time.RFC3339Nano), tc.expires.Format(time.RFC3339Nano)
			if err := validateResponseSizeScanLimitExpiryHorizons(c.ResponseScanning.SizeExemptScanLimits, now); (err == nil) != tc.valid {
				t.Fatalf("horizon: %v", err)
			}
			if err := c.Validate(); (err == nil) != tc.valid {
				t.Fatalf("startup: %v", err)
			}
			if err := c.ValidateExpiryAuthorizations(); (err == nil) != tc.valid {
				t.Fatalf("reload: %v", err)
			}
			if !tc.valid && c.ResponseScanning.SizeExemptScanLimitForHost(sizeLimitTestHost, now) != c.ResponseScanning.SizeExemptScanMaxBytes {
				t.Fatal("invalid runtime grant selected")
			}
		})
	}
}

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
	for _, mode := range []string{"empty", "wildcard", "wildcard-listed", "zero-expired", "port", "url", "unlisted", "duplicate", "zero", "lower", "budget", "owner", "reason", "control", "long", "added", "expiry", "order", "probe"} {
		t.Run(mode, func(t *testing.T) {
			c := responseSizeLimitTestConfig(now)
			r := &c.ResponseScanning
			e := &r.SizeExemptScanLimits[0]
			switch mode {
			case "empty":
				e.Host = ""
			case "wildcard":
				e.Host = "*.vendor.example"
			case "wildcard-listed":
				// The wildcard is itself an admitted size-exempt pattern, so
				// only the exact-host rule can refuse the entry.
				r.SizeExemptDomains = append(r.SizeExemptDomains, "*.vendor.example")
				e.Host = "*.vendor.example"
			case "zero-expired":
				// A lapsed entry stays loadable, but a malformed one does not.
				e.MaxBytes = 0
				e.Added = now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
				e.Expires = now.Add(-time.Hour).Format(time.RFC3339Nano)
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

func TestResponseSizeScanMaxBytesLeavesProbeByte(t *testing.T) {
	if strconv.IntSize != 64 {
		t.Skip("probe overflow needs a 64-bit int")
	}
	c := Defaults()
	c.ResponseScanning.SizeExemptScanMaxBytes = math.MaxInt
	c.ResponseScanning.SizeExemptScanMaxInflightBytes = math.MaxInt
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "probe byte") {
		t.Fatalf("shared ceiling without probe room accepted: %v", err)
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

func TestResponseSizeScanLimitYAMLLoad(t *testing.T) {
	now := time.Now().UTC()
	added, expires := now.Add(-time.Hour).Format(time.RFC3339), now.Add(24*time.Hour).Format(time.RFC3339)
	for _, quote := range []string{"", `"`} {
		doc := "response_scanning:\n  size_exempt_domains: [downloads.vendor.example, other.vendor.example]\n  size_exempt_scan_limits:\n" +
			"    - host: Downloads.Vendor.Example.\n      max_bytes: 134217728\n      owner: operator\n      reason: bounded scanned download\n" +
			"      added: " + quote + added + quote + "\n      expires: " + quote + expires + quote + "\n"
		c, err := LoadBytes([]byte(doc))
		if err != nil {
			t.Fatalf("quote=%q: %v", quote, err)
		}
		if got := c.ResponseScanning.SizeExemptScanLimitForHost(sizeLimitTestHost, now); got != 128<<20 {
			t.Fatalf("quote=%q: loaded grant cap %d", quote, got)
		}
		if got := c.ResponseScanning.SizeExemptScanLimitForHost("other.vendor.example", now); got != DefaultSizeExemptScanMaxBytes {
			t.Fatalf("quote=%q: neighbor cap %d", quote, got)
		}
	}
	// A date without a time or zone names no instant and must be refused.
	day, later := now.Format(time.DateOnly), now.Add(24*time.Hour).Format(time.DateOnly)
	dateOnly := "response_scanning:\n  size_exempt_domains: [downloads.vendor.example]\n  size_exempt_scan_limits:\n    - {host: downloads.vendor.example, max_bytes: 134217728, owner: o, reason: r, added: " + day + ", expires: " + later + "}\n"
	if _, err := LoadBytes([]byte(dateOnly)); err == nil {
		t.Fatal("date-only grant loaded")
	}
}

func TestResponseSizeScanLimitDocumentedHorizon(t *testing.T) {
	if MaxResponseSizeScanLimitHorizon != MaxUnscannablePassthroughHorizon {
		t.Fatal("scanned grants no longer match the documented temporary download tier")
	}
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "configuration.md"))
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "| `size_exempt_scan_limits` |"
	for _, line := range strings.Split(string(doc), "\n") {
		if strings.HasPrefix(line, prefix) {
			want := "for at most " + strconv.Itoa(int(MaxResponseSizeScanLimitHorizon/(24*time.Hour))) + " days."
			if !strings.Contains(line, want) {
				t.Fatalf("scanned grant documentation must state %q", want)
			}
			return
		}
	}
	t.Fatal("scanned grant documentation row is missing")
}
