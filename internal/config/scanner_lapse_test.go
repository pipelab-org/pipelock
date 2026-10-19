// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func scannerExceptionConfig() *Config {
	cfg := validEntropyWarnRouteConfig()
	cfg.RequestBodyScanning.ContentEntropyWarnRoutes = nil
	return cfg
}

func TestLoadExpiredScannerExceptions(t *testing.T) {
	past := todayUTC().AddDate(0, 0, -1).Format(time.DateOnly)
	future := todayUTC().AddDate(0, 0, 1).Format(time.DateOnly)
	for _, family := range []string{"path", "query", "warn", "body host", "websocket host", "sigv4"} {
		t.Run(family, func(t *testing.T) {
			cfg := scannerExceptionConfig()
			for i, expires := range []string{past, future} {
				host := []string{"expired.vendor.example", "active.vendor.example"}[i]
				switch family {
				case "path":
					cfg.FetchProxy.Monitoring.PathEntropyExclusions = append(cfg.FetchProxy.Monitoring.PathEntropyExclusions, PathEntropyExclusion{Host: host, PathPrefix: "/files/", Expires: expires})
				case "query":
					cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = append(cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions, QueryEntropyParamExclusion{Host: host, Path: "/files", Param: "id", Expires: expires})
				case "warn":
					route := prefixRoute("/files/")
					route.Host, route.Expires = host, expires
					cfg.RequestBodyScanning.ContentEntropyWarnRoutes = append(cfg.RequestBodyScanning.ContentEntropyWarnRoutes, route)
				case "body host":
					cfg.RequestBodyScanning.ContentEntropyExclusions = append(cfg.RequestBodyScanning.ContentEntropyExclusions, EntropyHostExclusion{Host: host, Expires: expires})
				case "websocket host":
					cfg.WebSocketProxy.ContentEntropyExclusions = append(cfg.WebSocketProxy.ContentEntropyExclusions, EntropyHostExclusion{Host: host, Expires: expires})
				case "sigv4":
					cfg.RequestBodyScanning.SigV4CredentialRoutes = append(cfg.RequestBodyScanning.SigV4CredentialRoutes, RequestBodySigV4CredentialRoute{Host: host, Path: "/files", ContentTypes: []string{contentTypeJSON}, Methods: []string{"POST"}, Reason: "attachment migration", Owner: "platform", Expires: expires})
				}
			}
			data, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, err := Load(path)
			if err != nil {
				t.Fatalf("valid expired exception must lapse while its sibling loads: %v", err)
			}
			if got := loaded.LapsedScannerExceptionWarnings(); len(got) != 1 || !strings.Contains(got[0].Message, "expired.vendor.example") {
				t.Fatalf("lapse warnings = %+v", got)
			}
			warnings, err := loaded.ValidateWithWarnings()
			if err != nil || !strings.Contains(fmtWarnings(warnings), "normal scanning applies") {
				t.Fatalf("retained warnings = %+v, error %v", warnings, err)
			}
			active, err := yaml.Marshal(loaded)
			if err != nil || strings.Contains(string(active), "expired.vendor.example") || !strings.Contains(string(active), "active.vendor.example") {
				t.Fatalf("effective YAML lost sibling or retained expired entry: %s, %v", active, err)
			}
			clone := loaded.Clone()
			before := loaded.CanonicalPolicyHash()
			again, err := loaded.LapseExpiredScannerExceptions(time.Now())
			if err != nil || len(again) != 1 || loaded.CanonicalPolicyHash() != before {
				t.Fatalf("repeated lapse changed state: %+v, %v", again, err)
			}
			if !reflect.DeepEqual(clone.LapsedScannerExceptionWarnings(), again) {
				t.Fatal("clone lost private diagnostics")
			}
			clone.lapsedScannerExceptions = nil
			if clone.CanonicalPolicyHash() != before {
				t.Fatal("private diagnostics affect policy identity")
			}
		})
	}
}

func fmtWarnings(warnings []Warning) string {
	var messages []string
	for _, warning := range warnings {
		messages = append(messages, warning.Field+": "+warning.Message)
	}
	return strings.Join(messages, "\n")
}

func allScannerExceptions(expires string) *Config {
	cfg := scannerExceptionConfig()
	cfg.FetchProxy.Monitoring.PathEntropyExclusions = []PathEntropyExclusion{{Host: "api.vendor.example", PathPrefix: "/files/", Expires: expires}}
	cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []QueryEntropyParamExclusion{{Host: "api.vendor.example", Path: "/files", Param: "id", Expires: expires}}
	route := prefixRoute("/files/")
	route.Expires = expires
	cfg.RequestBodyScanning.ContentEntropyWarnRoutes = []RequestBodyEntropyWarnRoute{route}
	cfg.RequestBodyScanning.SigV4CredentialRoutes = []RequestBodySigV4CredentialRoute{{Host: "api.vendor.example", Path: "/files", ContentTypes: []string{contentTypeJSON}, Methods: []string{"post"}, Reason: "attachment migration", Owner: "platform", Expires: expires}}
	cfg.RequestBodyScanning.ContentEntropyExclusions = []EntropyHostExclusion{{Host: "api.vendor.example", Expires: expires}}
	cfg.WebSocketProxy.ContentEntropyExclusions = []EntropyHostExclusion{{Host: "api.vendor.example", Expires: expires}}
	return cfg
}

func TestExpiredScannerExceptionsValidateBeforeLapse(t *testing.T) {
	past := todayUTC().AddDate(0, 0, -1).Format(time.DateOnly)
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{"path malformed date", func(c *Config) { c.FetchProxy.Monitoring.PathEntropyExclusions[0].Expires = "2026-02-30" }},
		{"path invalid host", func(c *Config) { c.FetchProxy.Monitoring.PathEntropyExclusions[0].Host = "*.com" }},
		{"path invalid prefix", func(c *Config) { c.FetchProxy.Monitoring.PathEntropyExclusions[0].PathPrefix = "/" }},
		{"path invalid metadata", func(c *Config) { c.FetchProxy.Monitoring.PathEntropyExclusions[0].Owner = "bad\aowner" }},
		{"path duplicate", func(c *Config) {
			c.FetchProxy.Monitoring.PathEntropyExclusions = append(c.FetchProxy.Monitoring.PathEntropyExclusions, c.FetchProxy.Monitoring.PathEntropyExclusions[0])
		}},
		{"query invalid host", func(c *Config) { c.FetchProxy.Monitoring.QueryEntropyParamExclusions[0].Host = "*.vendor.example" }},
		{"query invalid path", func(c *Config) { c.FetchProxy.Monitoring.QueryEntropyParamExclusions[0].Path = "/../files" }},
		{"query invalid parameter", func(c *Config) { c.FetchProxy.Monitoring.QueryEntropyParamExclusions[0].Param = "*" }},
		{"query invalid metadata", func(c *Config) {
			c.FetchProxy.Monitoring.QueryEntropyParamExclusions[0].Reason = strings.Repeat("x", 201)
		}},
		{"query duplicate", func(c *Config) {
			c.FetchProxy.Monitoring.QueryEntropyParamExclusions = append(c.FetchProxy.Monitoring.QueryEntropyParamExclusions, c.FetchProxy.Monitoring.QueryEntropyParamExclusions[0])
		}},
		{"warn invalid parent", func(c *Config) { c.RequestBodyScanning.ContentEntropyAction = ActionWarn }},
		{"warn invalid host", func(c *Config) { c.RequestBodyScanning.ContentEntropyWarnRoutes[0].Host = "*.vendor.example" }},
		{"warn invalid path", func(c *Config) { c.RequestBodyScanning.ContentEntropyWarnRoutes[0].PathPrefix = "/" }},
		{"warn missing metadata", func(c *Config) { c.RequestBodyScanning.ContentEntropyWarnRoutes[0].Owner = "" }},
		{"warn overlapping routes", func(c *Config) {
			r := c.RequestBodyScanning.ContentEntropyWarnRoutes[0]
			r.PathPrefix += "nested/"
			c.RequestBodyScanning.ContentEntropyWarnRoutes = append(c.RequestBodyScanning.ContentEntropyWarnRoutes, r)
		}},
		{"body mapping invalid host", func(c *Config) { c.RequestBodyScanning.ContentEntropyExclusions[0].Host = "*.com" }},
		{"body mapping invalid metadata", func(c *Config) { c.RequestBodyScanning.ContentEntropyExclusions[0].Reason = "bad\areason" }},
		{"body mapping duplicate", func(c *Config) {
			c.RequestBodyScanning.ContentEntropyExclusions = append(c.RequestBodyScanning.ContentEntropyExclusions, c.RequestBodyScanning.ContentEntropyExclusions[0])
		}},
		{"websocket mapping invalid host", func(c *Config) { c.WebSocketProxy.ContentEntropyExclusions[0].Host = "*.com" }},
		{"websocket mapping invalid metadata", func(c *Config) { c.WebSocketProxy.ContentEntropyExclusions[0].Owner = "bad\aowner" }},
		{"websocket mapping missing expiry", func(c *Config) {
			c.WebSocketProxy.ContentEntropyExclusions[0].Expires = ""
			c.WebSocketProxy.ContentEntropyExclusions[0].mapped = true
		}},
		{"websocket mapping duplicate", func(c *Config) {
			c.WebSocketProxy.ContentEntropyExclusions = append(c.WebSocketProxy.ContentEntropyExclusions, c.WebSocketProxy.ContentEntropyExclusions[0])
		}},
		{"sigv4 invalid parent", func(c *Config) {
			c.RequestBodyScanning.Enabled = false
			c.RequestBodyScanning.ContentEntropyWarnRoutes = nil
		}},
		{"sigv4 invalid host", func(c *Config) { c.RequestBodyScanning.SigV4CredentialRoutes[0].Host = "*.vendor.example" }},
		{"sigv4 invalid path", func(c *Config) { c.RequestBodyScanning.SigV4CredentialRoutes[0].Path = "/" }},
		{"sigv4 invalid metadata", func(c *Config) { c.RequestBodyScanning.SigV4CredentialRoutes[0].Owner = "" }},
		{"sigv4 duplicate", func(c *Config) {
			c.RequestBodyScanning.SigV4CredentialRoutes = append(c.RequestBodyScanning.SigV4CredentialRoutes, c.RequestBodyScanning.SigV4CredentialRoutes[0])
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := allScannerExceptions(past)
			tc.edit(cfg)
			before, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.Clone().Validate(); err == nil {
				t.Fatal("full validation accepted malformed expired declaration")
			}
			if err := cfg.ValidateExpiryAuthorizations(); err == nil {
				t.Fatal("direct activation accepted malformed expired declaration")
			}
			if _, err := cfg.LapseExpiredScannerExceptions(time.Now()); err == nil {
				t.Fatal("lapse accepted malformed expired declaration")
			}
			after, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) || len(cfg.LapsedScannerExceptionWarnings()) != 0 {
				t.Fatal("failed lapse/activation changed candidate")
			}
		})
	}
}

func TestScannerLapseDefaultsCopiesAndHash(t *testing.T) {
	past := todayUTC().AddDate(0, 0, -1).Format(time.DateOnly)
	for _, tc := range []struct {
		name         string
		paths        []PathEntropyExclusion
		wantDefaults bool
	}{
		{"omitted", nil, true},
		{"opt out", []PathEntropyExclusion{}, false},
		{"last expired entry", []PathEntropyExclusion{{Host: "api.vendor.example", PathPrefix: "/files/", Expires: past}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.FetchProxy.Monitoring.PathEntropyExclusions = tc.paths
			cfg.ApplyDefaults()
			cfg = cfg.Clone()
			_ = cfg.CanonicalPolicyHash() // lapse must invalidate a previously warmed cache
			if _, err := cfg.LapseExpiredScannerExceptions(time.Now()); err != nil {
				t.Fatal(err)
			}
			cfg.ApplyDefaults()
			want := []PathEntropyExclusion{}
			if tc.wantDefaults {
				want = ShippedPathEntropyExclusions()
			}
			if cfg.FetchProxy.Monitoring.PathEntropyExclusions == nil || !reflect.DeepEqual(canonicalPathEntropyExclusions(cfg.FetchProxy.Monitoring.PathEntropyExclusions), canonicalPathEntropyExclusions(want)) {
				t.Fatalf("effective paths = %+v, want %+v", cfg.FetchProxy.Monitoring.PathEntropyExclusions, want)
			}
			clean := Defaults()
			clean.FetchProxy.Monitoring.PathEntropyExclusions = want
			clean.ApplyDefaults()
			if cfg.CanonicalPolicyHash() != clean.CanonicalPolicyHash() {
				t.Fatal("lapse retained stale policy hash or hashed diagnostics")
			}
		})
	}

	cfg := allScannerExceptions(todayUTC().AddDate(0, 0, 1).Format(time.DateOnly))
	clone := cfg.Clone()
	clone.FetchProxy.Monitoring.PathEntropyExclusions[0].Host = "other.vendor.example"
	clone.FetchProxy.Monitoring.QueryEntropyParamExclusions[0].Host = "other.vendor.example"
	clone.RequestBodyScanning.ContentEntropyExclusions[0].Host = "other.vendor.example"
	clone.WebSocketProxy.ContentEntropyExclusions[0].Host = "other.vendor.example"
	for _, host := range []string{cfg.FetchProxy.Monitoring.PathEntropyExclusions[0].Host, cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions[0].Host, cfg.RequestBodyScanning.ContentEntropyExclusions[0].Host, cfg.WebSocketProxy.ContentEntropyExclusions[0].Host} {
		if host != "api.vendor.example" {
			t.Fatal("clone aliases scanner declarations")
		}
	}
}

func TestScannerExceptionExpiryIdentity(t *testing.T) {
	for _, family := range []string{"path", "query"} {
		t.Run(family, func(t *testing.T) {
			cfg := allScannerExceptions(todayUTC().AddDate(0, 0, 1).Format(time.DateOnly))
			renewed := cfg.Clone()
			expires := todayUTC().AddDate(0, 0, 2).Format(time.DateOnly)
			if family == "path" {
				renewed.FetchProxy.Monitoring.PathEntropyExclusions[0].Expires = expires
			} else {
				renewed.FetchProxy.Monitoring.QueryEntropyParamExclusions[0].Expires = expires
			}
			if cfg.CanonicalPolicyHash() == renewed.CanonicalPolicyHash() {
				t.Fatal("expiry did not change policy identity")
			}
			warnings := ValidateReload(cfg, renewed)
			if !strings.Contains(fmtReloadWarnings(warnings), "expires="+expires) {
				t.Fatalf("renewal not reported: %+v", warnings)
			}
		})
	}
}

func fmtReloadWarnings(warnings []ReloadWarning) string {
	var messages []string
	for _, warning := range warnings {
		messages = append(messages, warning.Message)
	}
	return strings.Join(messages, "\n")
}

func TestScannerExceptionActivityUTCDay(t *testing.T) {
	for _, tc := range []struct {
		name, expires, stamp string
		active               bool
	}{
		{"permanent", "", "2026-10-20T00:00:00Z", true},
		{"future", "2026-10-21", "2026-10-20T00:00:00Z", true},
		{"last instant", "2026-10-19", "2026-10-19T23:59:59.999999999Z", true},
		{"first expired instant", "2026-10-19", "2026-10-20T00:00:00Z", false},
		{"local previous day", "2026-10-19", "2026-10-19T20:00:00-04:00", false},
		{"local next day", "2026-10-19", "2026-10-20T01:00:00+02:00", true},
		{"invalid date", "2026-02-30", "2026-10-19T00:00:00Z", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now, err := time.Parse(time.RFC3339Nano, tc.stamp)
			if err != nil {
				t.Fatal(err)
			}
			if got := ScannerExceptionActive(tc.expires, now); got != tc.active {
				t.Fatalf("activity = %v, want %v", got, tc.active)
			}
		})
	}
}

func TestReloaderScannerLapseDiagnostics(t *testing.T) {
	data, err := yaml.Marshal(allScannerExceptions(todayUTC().AddDate(0, 0, -1).Format(time.DateOnly)))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, trigger := range []ReloadTrigger{ReloadTriggerFile, ReloadTriggerSignal} {
		r := NewReloader(path)
		r.tryReload(trigger)
		select {
		case event := <-r.Reloads():
			if event.Err != nil || event.Trigger != trigger || event.Config == nil {
				t.Fatalf("reload event = %+v", event)
			}
			if len(event.Config.LapsedScannerExceptionWarnings()) != 6 {
				t.Fatal("reloader dropped lapse diagnostics")
			}
		default:
			t.Fatal("reloader did not deliver a validated lapsed config")
		}
	}
}

func TestExpiredScannerWarningsDescribeEffectivePolicy(t *testing.T) {
	cfg := allScannerExceptions(todayUTC().AddDate(0, 0, -1).Format(time.DateOnly))
	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatal(err)
	}
	for _, warning := range warnings {
		if warning.Field == "request_body_scanning.content_entropy_warn_routes" || warning.Field == "request_body_scanning.sigv4_credential_routes" {
			t.Fatalf("lapsed exception reported as active: %+v", warning)
		}
	}
}

func TestScannerExceptionDiagnosticCopies(t *testing.T) {
	src := allScannerExceptions(todayUTC().AddDate(0, 0, -1).Format(time.DateOnly))
	if _, err := src.LapseExpiredScannerExceptions(time.Now()); err != nil {
		t.Fatal(err)
	}
	dst := Defaults()
	dst.CopyScannerExceptionDiagnosticsFrom(src)
	if !reflect.DeepEqual(src.LapsedScannerExceptionWarnings(), dst.LapsedScannerExceptionWarnings()) {
		t.Fatal("diagnostic copy lost declarations")
	}
	warnings := dst.LapsedScannerExceptionWarnings()
	warnings[0].Message = "changed"
	dst.lapsedScannerExceptions[1].Message = "changed"
	if src.LapsedScannerExceptionWarnings()[0].Message == "changed" || src.LapsedScannerExceptionWarnings()[1].Message == "changed" || dst.LapsedScannerExceptionWarnings()[0].Message == "changed" {
		t.Fatal("diagnostics alias caller-owned storage")
	}
	dst.CopyScannerExceptionDiagnosticsFrom(nil)
	if len(dst.LapsedScannerExceptionWarnings()) != 0 {
		t.Fatal("nil source did not clear diagnostics")
	}
}

func TestScannerEntropyHostHorizon(t *testing.T) {
	for _, tc := range []struct {
		name    string
		offset  time.Duration
		wantErr bool
	}{
		{"on horizon", MaxContentEntropyHostExclusionHorizon, false},
		{"beyond horizon", MaxContentEntropyHostExclusionHorizon + 24*time.Hour, true},
		{"already expired", -24 * time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := EntropyHostExclusion{Host: "api.vendor.example", Expires: todayUTC().Add(tc.offset).Format(time.DateOnly)}
			if err := validateEntropyHostExclusions("content_entropy_exclusions", []EntropyHostExclusion{entry}); (err != nil) != tc.wantErr {
				t.Fatalf("validation = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

func TestScannerLapsePreservesOtherExpiryRefusals(t *testing.T) {
	past := todayUTC().AddDate(0, 0, -1).Format(time.DateOnly)
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{"core observe", func(c *Config) { c.ResponseScanning.CoreObserveExceptions = []CoreObserveException{{Expires: past}} }},
		{"unscannable passthrough", func(c *Config) {
			c.ResponseScanning.UnscannablePassthrough = []UnscannablePassthroughEntry{{Expires: past}}
		}},
		{"sandbox", func(c *Config) {
			c.Sandbox.BestEffort = true
			c.Sandbox.BestEffortReason = "temporary namespace failure"
			c.Sandbox.BestEffortExpiry = past + "T00:00:00Z"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := allScannerExceptions(past)
			tc.edit(cfg)
			if _, err := cfg.LapseExpiredScannerExceptions(time.Now()); err != nil {
				t.Fatal(err)
			}
			if err := cfg.ValidateExpiryAuthorizations(); err == nil || !strings.Contains(err.Error(), "expired") {
				t.Fatalf("unrelated expired authorization was accepted: %v", err)
			}
		})
	}
}
