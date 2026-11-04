// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// IssuedRedirectDelegation is an operator's explicit trust assertion about one
// download route: a delivered redirect from the named source route may carry
// entropy relief for exactly the URL in its Location header, provided that URL
// is on one of the listed HTTPS origins.
//
// It trusts the source to issue only URLs the agent is meant to follow. A
// source that reflects request data into a Location, or one an attacker
// controls, can use the delegation to carry that data to a listed origin past
// the entropy heuristic. Nothing else is relieved: DLP, the immutable core
// floor, SSRF, destination restrictions, request policy, URL length, rate
// limits, data budgets, header and body scanning, and query-key entropy still
// run on the followed request.
//
// The source reuses the request_policy route grammar (exact hosts, methods,
// literal path prefixes, RE2 path patterns). Unlike a request_policy rule it
// must name an exact host, at least one method, and an explicit path
// constraint, and it never carries content types. The delegation is inert
// unless every field validates; nothing is inferred from other policy.
type IssuedRedirectDelegation struct {
	Name          string             `yaml:"name"`
	Source        RequestPolicyRoute `yaml:"source"`
	TargetOrigins []string           `yaml:"target_origins"` // https://host or https://host:port, exact
	Reason        string             `yaml:"reason"`
	Owner         string             `yaml:"owner"`
	Expires       string             `yaml:"expires"` // YYYY-MM-DD, the whole UTC day inclusive
}

const issuedRedirectDelegationsField = "fetch_proxy.monitoring.issued_redirect_delegations"

var issuedRedirectDelegationName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// IssuedRedirectDelegationActive reports whether the delegation's expiry has
// not passed. An empty or malformed date is not active: validation requires one
// and a configuration that bypassed it must not delegate indefinitely.
func IssuedRedirectDelegationActive(d IssuedRedirectDelegation, now time.Time) bool {
	return d.Expires != "" && ScannerExceptionActive(d.Expires, now)
}

// NormalizeIssuedRedirectDelegations validates the operator's declarations and
// returns a private normalized copy. The scanner-side consumer calls it too, so
// an unvalidated Config cannot install a partial delegation.
func NormalizeIssuedRedirectDelegations(entries []IssuedRedirectDelegation) ([]IssuedRedirectDelegation, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	out := make([]IssuedRedirectDelegation, len(entries))
	seen := make(map[string]int, len(entries))
	for i, entry := range entries {
		field := fmt.Sprintf("%s[%d]", issuedRedirectDelegationsField, i)
		entry.Name = strings.TrimSpace(entry.Name)
		if !issuedRedirectDelegationName.MatchString(entry.Name) {
			return nil, fmt.Errorf("%s.name %q must be 1-64 characters from [A-Za-z0-9._-], starting with a letter or digit", field, entry.Name)
		}
		if j, dup := seen[entry.Name]; dup {
			return nil, fmt.Errorf("%s.name %q duplicates %s[%d]", field, entry.Name, issuedRedirectDelegationsField, j)
		}
		seen[entry.Name] = i

		source, err := normalizeIssuedRedirectSource(entry.Source, field+".source")
		if err != nil {
			return nil, err
		}
		entry.Source = source

		if len(entry.TargetOrigins) == 0 {
			return nil, fmt.Errorf("%s.target_origins must name at least one exact https origin", field)
		}
		targets := make([]string, len(entry.TargetOrigins))
		for j, raw := range entry.TargetOrigins {
			origin, err := normalizeIssuedRedirectTargetOrigin(raw)
			if err != nil {
				return nil, fmt.Errorf("%s.target_origins[%d] %q: %w", field, j, raw, err)
			}
			targets[j] = origin
		}
		slices.Sort(targets)
		entry.TargetOrigins = slices.Compact(targets)

		entry.Reason = strings.TrimSpace(entry.Reason)
		entry.Owner = strings.TrimSpace(entry.Owner)
		if entry.Reason == "" || entry.Owner == "" {
			return nil, fmt.Errorf("%s requires reason and owner", field)
		}
		if err := validateScannerExceptionMetadata(field, entry.Reason, entry.Owner); err != nil {
			return nil, err
		}

		entry.Expires = strings.TrimSpace(entry.Expires)
		if entry.Expires == "" {
			return nil, fmt.Errorf("%s.expires is required (YYYY-MM-DD)", field)
		}
		// A valid past date lapses at load rather than invalidating the file,
		// like every other scanner exception. There is no horizon: the entry is
		// a reviewed trust assertion about a route, not an incident exemption.
		if _, err := time.Parse(time.DateOnly, entry.Expires); err != nil {
			return nil, fmt.Errorf("%s.expires %q must be YYYY-MM-DD: %w", field, entry.Expires, err)
		}
		out[i] = entry
	}
	return out, nil
}

func normalizeIssuedRedirectSource(route RequestPolicyRoute, label string) (RequestPolicyRoute, error) {
	route = RequestPolicyRoute{
		Hosts:        slices.Clone(route.Hosts),
		Methods:      slices.Clone(route.Methods),
		PathPrefixes: slices.Clone(route.PathPrefixes),
		PathPatterns: slices.Clone(route.PathPatterns),
		ContentTypes: slices.Clone(route.ContentTypes),
	}
	if len(route.ContentTypes) > 0 {
		return route, fmt.Errorf("%s.content_types is not part of a delegation; remove it", label)
	}
	if len(route.Hosts) == 0 {
		return route, fmt.Errorf("%s.hosts must name at least one exact host", label)
	}
	if len(route.Methods) == 0 {
		return route, fmt.Errorf("%s.methods must name at least one method", label)
	}
	if len(route.PathPrefixes) == 0 && len(route.PathPatterns) == 0 {
		return route, fmt.Errorf("%s needs explicit path_prefixes or path_patterns", label)
	}
	if err := validateRequestPolicyRoute(&route, label); err != nil {
		return route, err
	}
	for i, host := range route.Hosts {
		if strings.Contains(host, "*") {
			return route, fmt.Errorf("%s.hosts[%d] %q must be exact; a wildcard source would trust every matching service", label, i, host)
		}
	}
	for i, prefix := range route.PathPrefixes {
		prefix = strings.TrimSpace(prefix)
		// A bare / prefix constrains nothing: the same host-wide spelling that
		// path_entropy_exclusions already refuses.
		if !strings.HasPrefix(prefix, "/") || prefix == "/" {
			return route, fmt.Errorf("%s.path_prefixes[%d] %q must start with / and be longer than /", label, i, prefix)
		}
		route.PathPrefixes[i] = prefix
	}
	route.Hosts = sortedCompact(route.Hosts)
	route.Methods = sortedCompact(route.Methods)
	route.PathPrefixes = sortedCompact(route.PathPrefixes)
	route.PathPatterns = sortedCompact(route.PathPatterns)
	return route, nil
}

// normalizeIssuedRedirectTargetOrigin accepts an RFC 6454 section 6.2 origin
// string, restricted to https: scheme, one exact host, optional port, and
// nothing else. The default port is dropped so spellings compare equal.
func normalizeIssuedRedirectTargetOrigin(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed != raw || raw == "" {
		return "", fmt.Errorf("must not be empty or carry surrounding whitespace")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("must be an https origin")
	}
	if parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.ForceQuery ||
		(parsed.Path != "" && parsed.Path != "/") || strings.HasSuffix(raw, "/") {
		return "", fmt.Errorf("must be scheme://host[:port] with no path, query, fragment or userinfo")
	}
	host, err := NormalizeAndCheckHostPattern(parsed.Hostname())
	if err != nil {
		return "", err
	}
	if strings.Contains(host, "*") {
		return "", fmt.Errorf("must be an exact host, not a wildcard")
	}
	port := parsed.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("port %q is not 1-65535", port)
		}
		port = strconv.Itoa(n)
	}
	if port == "443" {
		port = ""
	}
	authority := host
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port != "" {
		authority = net.JoinHostPort(host, port)
	}
	return "https://" + authority, nil
}

func sortedCompact(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

// IssuedRedirectDelegationScope is a stable, non-secret fingerprint of what a
// delegation authorizes: its source route and target origins. Name, reason,
// owner and expiry are excluded. Evidence minted under one scope is never
// honored under another, so a changed scope revokes what an earlier snapshot
// learned, while renewing an expiry does not discard still-valid evidence
// (the expiry itself is rechecked on every request).
func IssuedRedirectDelegationScope(d IssuedRedirectDelegation) [32]byte {
	h := sha256.New()
	write := func(tag string, values []string) {
		values = sortedCompact(values)
		_, _ = fmt.Fprintf(h, "%s:%d\n", tag, len(values))
		for _, v := range values {
			_, _ = fmt.Fprintf(h, "%d:%s\n", len(v), v)
		}
	}
	write("hosts", d.Source.Hosts)
	write("methods", d.Source.Methods)
	write("prefixes", d.Source.PathPrefixes)
	write("patterns", d.Source.PathPatterns)
	write("targets", d.TargetOrigins)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func validateIssuedRedirectDelegations(c *Config) error {
	entries, err := NormalizeIssuedRedirectDelegations(c.FetchProxy.Monitoring.IssuedRedirectDelegations)
	if err != nil {
		return err
	}
	c.FetchProxy.Monitoring.IssuedRedirectDelegations = entries
	return nil
}

func cloneIssuedRedirectDelegations(entries []IssuedRedirectDelegation) []IssuedRedirectDelegation {
	if entries == nil {
		return nil
	}
	out := make([]IssuedRedirectDelegation, len(entries))
	for i, e := range entries {
		e.Source = RequestPolicyRoute{
			Hosts:        slices.Clone(e.Source.Hosts),
			Methods:      slices.Clone(e.Source.Methods),
			PathPrefixes: slices.Clone(e.Source.PathPrefixes),
			PathPatterns: slices.Clone(e.Source.PathPatterns),
			ContentTypes: slices.Clone(e.Source.ContentTypes),
		}
		e.TargetOrigins = slices.Clone(e.TargetOrigins)
		out[i] = e
	}
	return out
}

// canonicalIssuedRedirectDelegations is the policy-hash view: normalized,
// sorted, and without the name, reason and owner text. Entries that do not validate
// keep their spelling so the hash still distinguishes them.
func canonicalIssuedRedirectDelegations(entries []IssuedRedirectDelegation) []IssuedRedirectDelegation {
	if len(entries) == 0 {
		return nil
	}
	out := cloneIssuedRedirectDelegations(entries)
	if normalized, err := NormalizeIssuedRedirectDelegations(entries); err == nil {
		out = normalized
	}
	for i := range out {
		out[i].Name, out[i].Reason, out[i].Owner = "", "", ""
	}
	sort.Slice(out, func(i, j int) bool {
		// Every field is JSON-marshalable. Compare the complete enforcement
		// view so renamed entries and invalid spellings have stable ordering.
		left, _ := json.Marshal(out[i])
		right, _ := json.Marshal(out[j])
		return string(left) < string(right)
	})
	return out
}

// issuedRedirectDelegationTuples expands each delegation into the individual
// authorizations it grants: one per source host, method, path constraint and
// target origin. Reload comparison works on these so widening any dimension
// is visible, and a rename or reordering is not.
func issuedRedirectDelegationTuples(entries []IssuedRedirectDelegation) map[string]string {
	tuples := make(map[string]string)
	normalized, err := NormalizeIssuedRedirectDelegations(entries)
	if err != nil {
		normalized = entries
	}
	for _, e := range normalized {
		constraints := make([]string, 0, len(e.Source.PathPrefixes)+len(e.Source.PathPatterns))
		for _, p := range e.Source.PathPrefixes {
			constraints = append(constraints, "prefix "+p)
		}
		for _, p := range e.Source.PathPatterns {
			constraints = append(constraints, "pattern "+p)
		}
		for _, host := range e.Source.Hosts {
			for _, method := range e.Source.Methods {
				for _, constraint := range constraints {
					for _, target := range e.TargetOrigins {
						key := fmt.Sprintf("%s %s %s -> %s", method, host, constraint, target)
						if previous, ok := tuples[key]; !ok || e.Expires > previous {
							tuples[key] = e.Expires
						}
					}
				}
			}
		}
	}
	return tuples
}

func appendIssuedRedirectDelegationReloadWarnings(warnings *[]ReloadWarning, old, updated *Config) {
	before := issuedRedirectDelegationTuples(old.FetchProxy.Monitoring.IssuedRedirectDelegations)
	after := issuedRedirectDelegationTuples(updated.FetchProxy.Monitoring.IssuedRedirectDelegations)
	var added, removed []string
	for key, expires := range after {
		if previous, ok := before[key]; !ok || scannerExceptionExpiryWidened(previous, expires) {
			added = append(added, key)
		}
	}
	for key := range before {
		if _, ok := after[key]; !ok {
			removed = append(removed, key)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	if len(added) > 0 {
		*warnings = append(*warnings, ReloadWarning{
			Field:   issuedRedirectDelegationsField,
			Message: "issued redirect delegations added, widened or extended: " + strings.Join(added, "; ") + " — a redirect from these sources can carry entropy relief for its exact Location; a source that reflects request data can use it to reach these origins",
		})
	}
	if len(removed) > 0 {
		*warnings = append(*warnings, ReloadWarning{
			Field:       issuedRedirectDelegationsField,
			Message:     "issued redirect delegations removed or narrowed: " + strings.Join(removed, "; ") + " — evidence learned under them stops applying",
			Disposition: ReloadWarningDispositionAdvisory,
		})
	}
}
