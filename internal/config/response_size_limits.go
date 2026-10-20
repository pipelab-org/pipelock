// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"
)

// ResponseSizeScanLimit changes only a size-exempt host's bounded scan ceiling.
// It grants neither size-exempt membership nor permission to skip any scanner.
// Timestamps use RFC 3339 so expiry names an instant, not a local calendar day.
type ResponseSizeScanLimit struct {
	Host     string `yaml:"host"`
	MaxBytes int    `yaml:"max_bytes"`
	Owner    string `yaml:"owner"`
	Reason   string `yaml:"reason"`
	Added    string `yaml:"added"`
	Expires  string `yaml:"expires"`
}

// SizeExemptScanLimitForHost resolves the effective cap at response admission.
// Expired entries lapse to the ordinary cap without requiring a config reload.
// Validation rejects malformed entries; the checks also protect direct users
// of unvalidated Config values. The aggregate reservation remains mandatory.
func (r ResponseScanning) SizeExemptScanLimitForHost(host string, now time.Time) int {
	limit := r.SizeExemptScanMaxBytes
	if limit <= 0 {
		limit = DefaultSizeExemptScanMaxBytes
	}
	host = canonicalCoreObserveHost(host)
	if host == "" || !hostMatchesResponseSizeExemptDomain(host, r.SizeExemptDomains) {
		return limit
	}
	var selected *ResponseSizeScanLimit
	for i := range r.SizeExemptScanLimits {
		entry := &r.SizeExemptScanLimits[i]
		if canonicalCoreObserveHost(entry.Host) != host {
			continue
		}
		// Validation rejects duplicate hosts even when an entry has expired.
		// Direct callers must use the shared cap for the same ambiguity.
		if selected != nil {
			return limit
		}
		selected = entry
	}
	if selected != nil {
		entry := selected
		added, addedErr := time.Parse(time.RFC3339, entry.Added)
		expires, expiryErr := time.Parse(time.RFC3339, entry.Expires)
		if addedErr != nil || expiryErr != nil || !added.Before(expires) || expires.Sub(added) > MaxResponseSizeScanLimitHorizon || now.Before(added) || !now.Before(expires) ||
			entry.MaxBytes < limit || entry.MaxBytes > r.SizeExemptScanMaxInflightBytes || int64(entry.MaxBytes) == math.MaxInt64 ||
			!validResponseSizeGrantText(entry.Owner) || !validResponseSizeGrantText(entry.Reason) {
			return limit
		}
		return entry.MaxBytes
	}
	return limit
}

func (r *ResponseScanning) validateSizeExemptScanLimits(warnings *[]Warning, now time.Time) error {
	if err := validateResponseSizeScanLimitExpiryHorizons(r.SizeExemptScanLimits, now); err != nil {
		return err
	}
	seen := make(map[string]int, len(r.SizeExemptScanLimits))
	for i := range r.SizeExemptScanLimits {
		entry := &r.SizeExemptScanLimits[i]
		field := fmt.Sprintf("response_scanning.size_exempt_scan_limits[%d]", i)
		host := []string{entry.Host}
		if strings.TrimSpace(entry.Host) == "" {
			return fmt.Errorf("%s.host is required", field)
		}
		if err := ValidateTrustedDomains(host, field+".host"); err != nil {
			return err
		}
		if strings.ContainsAny(host[0], "*?[]") {
			return fmt.Errorf("%s.host must be one exact host without wildcards", field)
		}
		entry.Host = canonicalCoreObserveHost(host[0])
		if prior, ok := seen[entry.Host]; ok {
			return fmt.Errorf("%s duplicates response_scanning.size_exempt_scan_limits[%d]", field, prior)
		}
		seen[entry.Host] = i
		if entry.MaxBytes <= 0 {
			return fmt.Errorf("%s.max_bytes must be positive", field)
		}
		for _, text := range []struct {
			name  string
			value *string
		}{{"owner", &entry.Owner}, {"reason", &entry.Reason}} {
			*text.value = strings.TrimSpace(*text.value)
			// Match the existing core-observe exception metadata contract.
			if !validResponseSizeGrantText(*text.value) {
				return fmt.Errorf("%s.%s must contain 1 to 200 bytes without control characters", field, text.name)
			}
		}
		added, err := time.Parse(time.RFC3339, strings.TrimSpace(entry.Added))
		if err != nil {
			return fmt.Errorf("%s.added must be an RFC3339 timestamp: %w", field, err)
		}
		expires, err := time.Parse(time.RFC3339, strings.TrimSpace(entry.Expires))
		if err != nil {
			return fmt.Errorf("%s.expires must be an RFC3339 timestamp: %w", field, err)
		}
		if !added.Before(expires) {
			return fmt.Errorf("%s.expires must be after added", field)
		}
		entry.Added, entry.Expires = added.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano)
		if !now.Before(expires) {
			*warnings = append(*warnings, responseSizeScanLimitExpiryWarning(*entry, i))
			continue
		}
		if !hostMatchesResponseSizeExemptDomain(entry.Host, r.SizeExemptDomains) {
			return fmt.Errorf("%s.host must match response_scanning.size_exempt_domains", field)
		}
		if entry.MaxBytes < r.SizeExemptScanMaxBytes || entry.MaxBytes > r.SizeExemptScanMaxInflightBytes || int64(entry.MaxBytes) == math.MaxInt64 {
			return fmt.Errorf("%s.max_bytes must be >= response_scanning.size_exempt_scan_max_bytes, <= response_scanning.size_exempt_scan_max_inflight_bytes, and leave room for one probe byte", field)
		}
	}
	return nil
}

func validateResponseSizeScanLimitExpiryHorizons(entries []ResponseSizeScanLimit, now time.Time) error {
	for i, entry := range entries {
		field := fmt.Sprintf("response_scanning.size_exempt_scan_limits[%d]", i)
		added, err := time.Parse(time.RFC3339, strings.TrimSpace(entry.Added))
		if err != nil {
			return fmt.Errorf("%s.added must be an RFC3339 timestamp: %w", field, err)
		}
		expires, err := time.Parse(time.RFC3339, strings.TrimSpace(entry.Expires))
		if err != nil {
			return fmt.Errorf("%s.expires must be an RFC3339 timestamp: %w", field, err)
		}
		if !added.Before(expires) {
			return fmt.Errorf("%s.expires must be after added", field)
		}
		// Expired entries are inactive and retain the lapse-with-warning
		// contract. Active grants cannot renew their horizon merely by reload.
		if now.Before(expires) && (expires.Sub(added) > MaxResponseSizeScanLimitHorizon || expires.After(now.Add(MaxResponseSizeScanLimitHorizon))) {
			return fmt.Errorf("%s.expires exceeds the maximum temporary horizon of %d days; shorten the grant", field, int(MaxResponseSizeScanLimitHorizon.Hours()/24))
		}
	}
	return nil
}

func validResponseSizeGrantText(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= 200 && strings.IndexFunc(value, unicode.IsControl) < 0
}

// SizeExemptScanLimitWarnings reports lapsed grants without mutating a loaded
// configuration or its cached policy identity. Startup validation and doctor
// share the same warning text and field path.
func (r ResponseScanning) SizeExemptScanLimitWarnings(now time.Time) []Warning {
	var warnings []Warning
	for i, entry := range r.SizeExemptScanLimits {
		expires, err := time.Parse(time.RFC3339, entry.Expires)
		if err == nil && !now.Before(expires) {
			warnings = append(warnings, responseSizeScanLimitExpiryWarning(entry, i))
		}
	}
	return warnings
}

func responseSizeScanLimitExpiryWarning(entry ResponseSizeScanLimit, index int) Warning {
	return Warning{
		Field:   fmt.Sprintf("response_scanning.size_exempt_scan_limits[%d].expires", index),
		Message: fmt.Sprintf("scan-cap grant for %s expired at %s; using response_scanning.size_exempt_scan_max_bytes; remove or renew the entry", entry.Host, entry.Expires),
	}
}

func canonicalResponseSizeScanLimits(entries []ResponseSizeScanLimit) []ResponseSizeScanLimit {
	if len(entries) == 0 {
		return nil
	}
	out := append([]ResponseSizeScanLimit(nil), entries...)
	for i := range out {
		out[i].Host = canonicalCoreObserveHost(out[i].Host)
		for _, timestamp := range []*string{&out[i].Added, &out[i].Expires} {
			if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*timestamp)); err == nil {
				*timestamp = parsed.UTC().Format(time.RFC3339Nano)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}
