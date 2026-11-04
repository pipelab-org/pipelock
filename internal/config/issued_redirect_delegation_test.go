// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

const (
	delegationSourceHost = "api.vendor.example"
	delegationTarget     = "https://files.vendor.example"
)

func delegationDate(offset time.Duration) string {
	return time.Now().UTC().Add(offset).Format(time.DateOnly)
}

func testDelegation() IssuedRedirectDelegation {
	return IssuedRedirectDelegation{
		Name: "download-route",
		Source: RequestPolicyRoute{
			Hosts:        []string{delegationSourceHost},
			Methods:      []string{"get"},
			PathPrefixes: []string{"/v1/items/"},
		},
		TargetOrigins: []string{delegationTarget},
		Reason:        "operator-reviewed download route",
		Owner:         "platform",
		Expires:       delegationDate(30 * 24 * time.Hour),
	}
}

func delegationConfig(entries ...IssuedRedirectDelegation) *Config {
	cfg := Defaults()
	cfg.FetchProxy.Monitoring.IssuedRedirectDelegations = entries
	return cfg
}

func TestIssuedRedirectDelegationValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mutate func(*IssuedRedirectDelegation)
		want   string // empty: valid
	}{
		{"valid", func(*IssuedRedirectDelegation) {}, ""},
		{"valid pattern only", func(d *IssuedRedirectDelegation) {
			d.Source.PathPrefixes, d.Source.PathPatterns = nil, []string{`^/v1/items/[^/]+/content$`}
		}, ""},
		{"valid explicit port", func(d *IssuedRedirectDelegation) { d.TargetOrigins = []string{"https://files.vendor.example:8443"} }, ""},
		{"name empty", func(d *IssuedRedirectDelegation) { d.Name = " " }, "name"},
		{"name bad char", func(d *IssuedRedirectDelegation) { d.Name = "bad name" }, "name"},
		{"name too long", func(d *IssuedRedirectDelegation) { d.Name = strings.Repeat("a", 65) }, "name"},
		{"no hosts", func(d *IssuedRedirectDelegation) { d.Source.Hosts = nil }, "hosts"},
		{"wildcard host", func(d *IssuedRedirectDelegation) { d.Source.Hosts = []string{"*.vendor.example"} }, "exact"},
		{"url host", func(d *IssuedRedirectDelegation) { d.Source.Hosts = []string{"https://api.vendor.example"} }, "hosts"},
		{"no methods", func(d *IssuedRedirectDelegation) { d.Source.Methods = nil }, "methods"},
		{"bad method", func(d *IssuedRedirectDelegation) { d.Source.Methods = []string{"FETCH"} }, "method"},
		{"no path constraint", func(d *IssuedRedirectDelegation) { d.Source.PathPrefixes = nil }, "path_prefixes or path_patterns"},
		{"root prefix", func(d *IssuedRedirectDelegation) { d.Source.PathPrefixes = []string{"/"} }, "longer than /"},
		{"relative prefix", func(d *IssuedRedirectDelegation) { d.Source.PathPrefixes = []string{"v1/items"} }, "start with /"},
		{"bad pattern", func(d *IssuedRedirectDelegation) { d.Source.PathPatterns = []string{"("} }, "path_pattern"},
		{"empty pattern", func(d *IssuedRedirectDelegation) { d.Source.PathPatterns = []string{" "} }, "path_pattern"},
		{"content types", func(d *IssuedRedirectDelegation) { d.Source.ContentTypes = []string{"application/json"} }, "content_types"},
		{"no targets", func(d *IssuedRedirectDelegation) { d.TargetOrigins = nil }, "target_origins"},
		{"http target", func(d *IssuedRedirectDelegation) { d.TargetOrigins = []string{"http://files.vendor.example"} }, "https"},
		{"target path", func(d *IssuedRedirectDelegation) { d.TargetOrigins = []string{"https://files.vendor.example/dl"} }, "no path"},
		{"target trailing slash", func(d *IssuedRedirectDelegation) { d.TargetOrigins = []string{"https://files.vendor.example/"} }, "no path"},
		{"target query", func(d *IssuedRedirectDelegation) { d.TargetOrigins = []string{"https://files.vendor.example?a=b"} }, "no path"},
		{"target userinfo", func(d *IssuedRedirectDelegation) { d.TargetOrigins = []string{"https://u@files.vendor.example"} }, "no path"},
		{"target wildcard", func(d *IssuedRedirectDelegation) { d.TargetOrigins = []string{"https://*.vendor.example"} }, "target_origins"},
		{"target bare host", func(d *IssuedRedirectDelegation) { d.TargetOrigins = []string{"files.vendor.example"} }, "https"},
		{"target bad port", func(d *IssuedRedirectDelegation) { d.TargetOrigins = []string{"https://files.vendor.example:0"} }, "port"},
		{"target port range", func(d *IssuedRedirectDelegation) { d.TargetOrigins = []string{"https://files.vendor.example:70000"} }, "port"},
		{"target whitespace", func(d *IssuedRedirectDelegation) { d.TargetOrigins = []string{" https://files.vendor.example"} }, "whitespace"},
		{"target unparseable", func(d *IssuedRedirectDelegation) { d.TargetOrigins = []string{"https://[::1"} }, "target_origins"},
		{"target empty", func(d *IssuedRedirectDelegation) { d.TargetOrigins = []string{""} }, "target_origins"},
		{"no reason", func(d *IssuedRedirectDelegation) { d.Reason = " " }, "reason and owner"},
		{"no owner", func(d *IssuedRedirectDelegation) { d.Owner = "" }, "reason and owner"},
		{"control reason", func(d *IssuedRedirectDelegation) { d.Reason = "line\nbreak" }, "control"},
		{"long owner", func(d *IssuedRedirectDelegation) { d.Owner = strings.Repeat("o", 101) }, "100"},
		{"no expiry", func(d *IssuedRedirectDelegation) { d.Expires = "" }, "expires is required"},
		// clock-literal-ok: malformed date syntax is rejected before expiry evaluation.
		{"bad expiry", func(d *IssuedRedirectDelegation) { d.Expires = "2099-13-45" }, "YYYY-MM-DD"},
		// clock-literal-ok: malformed date syntax is rejected before expiry evaluation.
		{"rfc3339 expiry", func(d *IssuedRedirectDelegation) { d.Expires = "2099-01-01T00:00:00Z" }, "YYYY-MM-DD"},
		// clock-literal-ok: deliberately expired negative case, independent of future clock changes.
		{"past expiry lapses instead of failing", func(d *IssuedRedirectDelegation) { d.Expires = "2000-01-01" }, ""},
		{"far future expiry has no horizon", func(d *IssuedRedirectDelegation) {
			d.Expires = time.Now().UTC().AddDate(1000, 0, 0).Format(time.DateOnly)
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := testDelegation()
			tc.mutate(&d)
			err := delegationConfig(d).Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("valid delegation rejected: %v", err)
			case tc.want != "" && err == nil:
				t.Fatalf("invalid delegation accepted, want error containing %q", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
	t.Run("duplicate name", func(t *testing.T) {
		t.Parallel()
		if err := delegationConfig(testDelegation(), testDelegation()).Validate(); err == nil || !strings.Contains(err.Error(), "duplicates") {
			t.Fatalf("duplicate name accepted: %v", err)
		}
	})
	t.Run("omitted is off", func(t *testing.T) {
		t.Parallel()
		cfg := Defaults()
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		if got, err := NormalizeIssuedRedirectDelegations(nil); got != nil || err != nil {
			t.Fatalf("NormalizeIssuedRedirectDelegations(nil) = %v, %v", got, err)
		}
	})
}

func TestIssuedRedirectDelegationNormalizesSpellings(t *testing.T) {
	t.Parallel()
	d := testDelegation()
	d.Source.Hosts = []string{"API.Vendor.Example.", delegationSourceHost}
	d.Source.Methods = []string{"get", "GET"}
	d.TargetOrigins = []string{"HTTPS://Files.Vendor.Example:443", "https://files.vendor.example", "https://files.vendor.example:0443", "https://[2001:db8::1]:8443", "https://[2001:DB8::2]"}
	got, err := NormalizeIssuedRedirectDelegations([]IssuedRedirectDelegation{d})
	if err != nil {
		t.Fatal(err)
	}
	e := got[0]
	if len(e.Source.Hosts) != 1 || e.Source.Hosts[0] != delegationSourceHost {
		t.Fatalf("hosts = %v", e.Source.Hosts)
	}
	if len(e.Source.Methods) != 1 || e.Source.Methods[0] != "GET" {
		t.Fatalf("methods = %v", e.Source.Methods)
	}
	want := []string{"https://[2001:db8::1]:8443", "https://[2001:db8::2]", delegationTarget}
	if strings.Join(e.TargetOrigins, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v", e.TargetOrigins, want)
	}
	if d.Source.Hosts[0] != "API.Vendor.Example." {
		t.Fatal("normalization mutated the caller's entry")
	}
}

func TestIssuedRedirectDelegationActive(t *testing.T) {
	t.Parallel()
	now := time.Date(2030, 6, 15, 23, 59, 0, 0, time.UTC)
	for _, tc := range []struct {
		expires string
		want    bool
	}{
		{"2030-06-15", true}, // the whole UTC day is inclusive
		{"2030-06-16", true},
		{"2030-06-14", false},
		{"", false},
		{"not-a-date", false},
	} {
		d := testDelegation()
		d.Expires = tc.expires
		if got := IssuedRedirectDelegationActive(d, now); got != tc.want {
			t.Errorf("expires %q: active = %t, want %t", tc.expires, got, tc.want)
		}
	}
}

func TestIssuedRedirectDelegationScope(t *testing.T) {
	t.Parallel()
	base := testDelegation()
	scope := IssuedRedirectDelegationScope(base)

	same := base
	// clock-literal-ok: expiry metadata is excluded from the scope digest; no clock reads it.
	same.Name, same.Reason, same.Owner, same.Expires = "renamed", "other", "other", "2999-01-01"
	same.Source.Hosts = []string{delegationSourceHost, delegationSourceHost}
	if IssuedRedirectDelegationScope(same) != scope {
		t.Fatal("name, reason, owner, expiry and duplicate entries must not change the scope")
	}
	for name, mutate := range map[string]func(*IssuedRedirectDelegation){
		"host":    func(d *IssuedRedirectDelegation) { d.Source.Hosts = []string{"other.vendor.example"} },
		"method":  func(d *IssuedRedirectDelegation) { d.Source.Methods = []string{"GET", "POST"} },
		"prefix":  func(d *IssuedRedirectDelegation) { d.Source.PathPrefixes = []string{"/v1/items"} },
		"pattern": func(d *IssuedRedirectDelegation) { d.Source.PathPatterns = []string{"^/v1/"} },
		"target":  func(d *IssuedRedirectDelegation) { d.TargetOrigins = []string{"https://other.vendor.example"} },
		// The split between two lists must not collapse into one.
		"prefix moved to pattern": func(d *IssuedRedirectDelegation) {
			d.Source.PathPrefixes, d.Source.PathPatterns = nil, []string{"/v1/items/"}
		},
	} {
		changed := testDelegation()
		mutate(&changed)
		if IssuedRedirectDelegationScope(changed) == scope {
			t.Errorf("changing %s did not change the scope", name)
		}
	}
}

func TestIssuedRedirectDelegationCloneIsSeparate(t *testing.T) {
	t.Parallel()
	cfg := delegationConfig(testDelegation())
	clone := cfg.Clone()
	e := &clone.FetchProxy.Monitoring.IssuedRedirectDelegations[0]
	e.Source.Hosts[0] = "changed.vendor.example"
	e.Source.Methods[0] = "POST"
	e.Source.PathPrefixes[0] = "/changed/"
	e.TargetOrigins[0] = "https://changed.vendor.example"
	e.Name = "changed"
	orig := cfg.FetchProxy.Monitoring.IssuedRedirectDelegations[0]
	if orig.Source.Hosts[0] != delegationSourceHost || orig.Source.Methods[0] != "get" ||
		orig.Source.PathPrefixes[0] != "/v1/items/" || orig.TargetOrigins[0] != delegationTarget || orig.Name != "download-route" {
		t.Fatalf("clone aliases the original: %+v", orig)
	}
	if got := Defaults().Clone().FetchProxy.Monitoring.IssuedRedirectDelegations; got != nil {
		t.Fatalf("empty list cloned as %v", got)
	}
}

func TestIssuedRedirectDelegationPolicyHash(t *testing.T) {
	t.Parallel()
	none := Defaults().CanonicalPolicyHash()
	if got := delegationConfig().CanonicalPolicyHash(); got != none {
		t.Fatal("an empty list changed the policy hash")
	}
	base := delegationConfig(testDelegation()).CanonicalPolicyHash()
	if base == none {
		t.Fatal("a delegation did not change the policy hash")
	}
	other := testDelegation()
	other.Name = "second-route"
	other.Source.Hosts = []string{"second.vendor.example"}
	ab := delegationConfig(testDelegation(), other).CanonicalPolicyHash()
	if ba := delegationConfig(other, testDelegation()).CanonicalPolicyHash(); ab != ba {
		t.Fatal("entry order changed the policy hash")
	}
	noText := testDelegation()
	noText.Name = "renamed-route"
	noText.Reason, noText.Owner = "edited reason", "edited owner"
	if delegationConfig(noText).CanonicalPolicyHash() != base {
		t.Fatal("reason and owner text changed the policy hash")
	}
	other.Name = "aaa-renamed-second"
	if delegationConfig(other, noText).CanonicalPolicyHash() != ab {
		t.Fatal("renaming entries changed the policy hash or canonical order")
	}
	respelled := testDelegation()
	respelled.TargetOrigins = []string{"HTTPS://FILES.VENDOR.EXAMPLE:443"}
	if delegationConfig(respelled).CanonicalPolicyHash() != base {
		t.Fatal("an equivalent origin spelling changed the policy hash")
	}
	for name, mutate := range map[string]func(*IssuedRedirectDelegation){
		"expiry": func(d *IssuedRedirectDelegation) { d.Expires = delegationDate(60 * 24 * time.Hour) },
		"target": func(d *IssuedRedirectDelegation) { d.TargetOrigins = []string{"https://files.vendor.example:8443"} },
		"path":   func(d *IssuedRedirectDelegation) { d.Source.PathPrefixes = []string{"/v2/items/"} },
	} {
		d := testDelegation()
		mutate(&d)
		if delegationConfig(d).CanonicalPolicyHash() == base {
			t.Errorf("changing %s did not change the policy hash", name)
		}
	}
}

func TestIssuedRedirectDelegationLoadsFromYAML(t *testing.T) {
	t.Parallel()
	yaml := `
fetch_proxy:
  monitoring:
    issued_redirect_delegations:
      - name: download-route
        source:
          hosts: [api.vendor.example]
          methods: [GET]
          path_prefixes: [/v1/items/]
        target_origins: [https://files.vendor.example]
        reason: operator-reviewed download route
        owner: platform
        expires: ` + delegationDate(30*24*time.Hour) + "\n"
	cfg, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.FetchProxy.Monitoring.IssuedRedirectDelegations
	if len(got) != 1 || got[0].Source.Hosts[0] != delegationSourceHost || got[0].TargetOrigins[0] != delegationTarget {
		t.Fatalf("loaded = %+v", got)
	}
	bad := strings.Replace(yaml, "path_prefixes: [/v1/items/]", "path_prefixes: [/v1/items/]\n          unknown_field: x", 1)
	if _, err := LoadBytes([]byte(bad)); err == nil {
		t.Fatal("unknown source field accepted")
	}
}

func TestIssuedRedirectDelegationLapsesAtLoad(t *testing.T) {
	t.Parallel()
	expired, live := testDelegation(), testDelegation()
	// clock-literal-ok: deliberately expired negative case, independent of future clock changes.
	expired.Name, expired.Expires = "expired-route", "2000-01-01"
	cfg := delegationConfig(expired, live)
	warnings, err := cfg.LapseExpiredScannerExceptions(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.FetchProxy.Monitoring.IssuedRedirectDelegations
	if len(got) != 1 || got[0].Name != "download-route" {
		t.Fatalf("effective set = %+v", got)
	}
	found := false
	for _, w := range warnings {
		found = found || (strings.Contains(w.Field, "issued_redirect_delegations") && strings.Contains(w.Message, "expired-route"))
	}
	if !found {
		t.Fatalf("no lapse warning for the expired delegation: %+v", warnings)
	}
	bad := testDelegation()
	bad.Source.Hosts = nil
	if _, err := delegationConfig(live, bad).LapseExpiredScannerExceptions(time.Now().UTC()); err == nil {
		t.Fatal("a malformed delegation must fail the whole lapse atomically")
	}
}

func TestIssuedRedirectDelegationReloadWarnings(t *testing.T) {
	t.Parallel()
	with := func(mutate func(*IssuedRedirectDelegation)) *Config {
		d := testDelegation()
		mutate(&d)
		return delegationConfig(d)
	}
	same := func(*IssuedRedirectDelegation) {}
	type result struct{ trust, advisory bool }
	for _, tc := range []struct {
		name     string
		old, new *Config
		want     result
	}{
		{"added", Defaults(), with(same), result{trust: true}},
		{"removed", with(same), Defaults(), result{advisory: true}},
		{"unchanged", with(same), with(same), result{}},
		{"renamed and respelled", with(same), with(func(d *IssuedRedirectDelegation) {
			d.Name = "renamed"
			d.TargetOrigins = []string{"HTTPS://Files.Vendor.Example:443"}
			d.Source.Hosts = []string{"API.VENDOR.EXAMPLE."}
		}), result{}},
		{"widened host", with(same), with(func(d *IssuedRedirectDelegation) {
			d.Source.Hosts = []string{delegationSourceHost, "other.vendor.example"}
		}), result{trust: true}},
		{"widened method", with(same), with(func(d *IssuedRedirectDelegation) { d.Source.Methods = []string{"GET", "POST"} }), result{trust: true}},
		{"widened target", with(same), with(func(d *IssuedRedirectDelegation) {
			d.TargetOrigins = []string{delegationTarget, "https://more.vendor.example"}
		}), result{trust: true}},
		{"changed prefix", with(same), with(func(d *IssuedRedirectDelegation) { d.Source.PathPrefixes = []string{"/v2/"} }), result{trust: true, advisory: true}},
		{"extended expiry", with(same), with(func(d *IssuedRedirectDelegation) { d.Expires = delegationDate(90 * 24 * time.Hour) }), result{trust: true}},
		{"shortened expiry", with(same), with(func(d *IssuedRedirectDelegation) { d.Expires = delegationDate(24 * time.Hour) }), result{}},
		{"narrowed target", with(func(d *IssuedRedirectDelegation) {
			d.TargetOrigins = []string{delegationTarget, "https://more.vendor.example"}
		}), with(same), result{advisory: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got result
			for _, w := range ValidateReload(tc.old, tc.new) {
				if w.Field != issuedRedirectDelegationsField {
					continue
				}
				if w.Disposition == ReloadWarningDispositionAdvisory {
					got.advisory = true
				} else {
					got.trust = true
				}
			}
			if got != tc.want {
				t.Fatalf("warnings = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestIssuedRedirectDelegationReloadComparesInvalidEntries(t *testing.T) {
	t.Parallel()
	bad := testDelegation()
	bad.Reason = "" // fails validation, so comparison falls back to the raw entry
	wider := bad
	wider.TargetOrigins = []string{delegationTarget, "https://more.vendor.example"}
	var warned bool
	for _, w := range ValidateReload(delegationConfig(bad), delegationConfig(wider)) {
		warned = warned || (w.Field == issuedRedirectDelegationsField && w.Disposition != ReloadWarningDispositionAdvisory)
	}
	if !warned {
		t.Fatal("a widened entry that fails validation went unreported")
	}
}
