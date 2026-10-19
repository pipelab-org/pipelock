// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestServerScannerExceptionRejectedReloadAudited(t *testing.T) {
	t.Parallel()
	logPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := audit.New("json", "file", logPath, false, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	s := &Server{logger: logger, opts: ServerOpts{ConfigFile: "policy.yaml"}}
	invalid := config.Defaults()
	invalid.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{{Host: "*.com", PathPrefix: "/files/"}}
	if err := s.Reload(invalid); err == nil {
		t.Fatal("invalid scanner exception accepted")
	}
	data, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{configReloadAuditMethod, "path_entropy_exclusions", "policy.yaml", "rejected: invalid config reload"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("audit log missing %q: %s", want, data)
		}
	}
}

func scannerLapseYAML() string {
	past := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	future := time.Now().UTC().AddDate(0, 0, 1).Format(time.DateOnly)
	var paths, query, warn, sigv4, hosts string
	for i, expires := range []string{past, future} {
		host := []string{"expired.vendor.example", "active.vendor.example"}[i]
		paths += fmt.Sprintf("    - {host: %s, path_prefix: /files/, expires: %s}\n", host, expires)
		query += fmt.Sprintf("    - {host: %s, path: /files, param: id, expires: %s}\n", host, expires)
		warn += fmt.Sprintf("    - {host: %s, path_prefix: /files/, content_types: [application/json], owner: platform, reason: opaque upload, expires: %s}\n", host, expires)
		sigv4 += fmt.Sprintf("    - {host: %s, path: /files, content_types: [application/json], methods: [POST], owner: platform, reason: attachment migration, expires: %s}\n", host, expires)
		hosts += fmt.Sprintf("    - {host: %s, expires: %s}\n", host, expires)
	}
	return "mode: balanced\nfetch_proxy:\n  monitoring:\n    path_entropy_exclusions:\n" + indentScannerPaths(paths) + "    query_entropy_param_exclusions:\n" + indentScannerPaths(query) +
		"request_body_scanning:\n  enabled: true\n  content_entropy_enabled: true\n  content_entropy_action: block\n  content_entropy_warn_routes:\n" + warn + "  sigv4_credential_routes:\n" + sigv4 + "  content_entropy_exclusions:\n" + hosts +
		"websocket_proxy:\n  content_entropy_exclusions:\n" + hosts
}

func indentScannerPaths(entries string) string {
	return "  " + strings.ReplaceAll(strings.TrimSuffix(entries, "\n"), "\n", "\n  ") + "\n"
}

func assertScannerLapse(t *testing.T, cfg *config.Config, stderr *syncBuffer) {
	t.Helper()
	if got := cfg.LapsedScannerExceptionWarnings(); len(got) != 6 {
		t.Fatalf("lapsed = %+v, want six families", got)
	}
	for _, warning := range cfg.LapsedScannerExceptionWarnings() {
		if !stderr.contains(warning.Field) || !stderr.contains("normal scanning applies") {
			t.Fatalf("missing warning %s: %s", warning.Field, stderr.String())
		}
	}
	for _, got := range []int{
		len(cfg.FetchProxy.Monitoring.PathEntropyExclusions), len(cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions),
		len(cfg.RequestBodyScanning.ContentEntropyWarnRoutes), len(cfg.RequestBodyScanning.SigV4CredentialRoutes),
		len(cfg.RequestBodyScanning.ContentEntropyExclusions), len(cfg.WebSocketProxy.ContentEntropyExclusions),
	} {
		if got != 1 {
			t.Fatalf("effective list has %d entries, want active sibling only", got)
		}
	}
}

func TestServerScannerExceptionLapseConsumers(t *testing.T) {
	t.Run("startup", func(t *testing.T) {
		s, stderr, err := newLapseTestServer(t, scannerLapseYAML())
		if err != nil {
			t.Fatal(err)
		}
		assertScannerLapse(t, s.proxy.CurrentConfig(), stderr)
	})
	for _, trigger := range []string{"direct", "file", "SIGHUP"} {
		t.Run(trigger, func(t *testing.T) {
			s, stderr, err := newLapseTestServer(t, "mode: balanced\n")
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := loadServerTestConfig(t, scannerLapseYAML())
			if err != nil {
				t.Fatal(err)
			}
			if trigger == "direct" {
				// Restore a raw expired declaration, bypassing Load's partition.
				candidate = candidate.Clone()
				candidate.CopyScannerExceptionDiagnosticsFrom(nil)
				expires := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
				candidate.FetchProxy.Monitoring.PathEntropyExclusions = append(candidate.FetchProxy.Monitoring.PathEntropyExclusions, config.PathEntropyExclusion{Host: "expired.vendor.example", PathPrefix: "/files/", Expires: expires})
				candidate.FetchProxy.Monitoring.QueryEntropyParamExclusions = append(candidate.FetchProxy.Monitoring.QueryEntropyParamExclusions, config.QueryEntropyParamExclusion{Host: "expired.vendor.example", Path: "/files", Param: "id", Expires: expires})
				warn := candidate.RequestBodyScanning.ContentEntropyWarnRoutes[0]
				warn.Host, warn.Expires = "expired.vendor.example", expires
				candidate.RequestBodyScanning.ContentEntropyWarnRoutes = append(candidate.RequestBodyScanning.ContentEntropyWarnRoutes, warn)
				sigv4 := candidate.RequestBodyScanning.SigV4CredentialRoutes[0]
				sigv4.Host, sigv4.Expires = "expired.vendor.example", expires
				candidate.RequestBodyScanning.SigV4CredentialRoutes = append(candidate.RequestBodyScanning.SigV4CredentialRoutes, sigv4)
				candidate.RequestBodyScanning.ContentEntropyExclusions = append(candidate.RequestBodyScanning.ContentEntropyExclusions, config.EntropyHostExclusion{Host: "expired.vendor.example", Expires: expires})
				candidate.WebSocketProxy.ContentEntropyExclusions = append(candidate.WebSocketProxy.ContentEntropyExclusions, config.EntropyHostExclusion{Host: "expired.vendor.example", Expires: expires})
				if err := s.Reload(candidate); err != nil {
					t.Fatal(err)
				}
				if len(candidate.FetchProxy.Monitoring.PathEntropyExclusions) != 2 || len(candidate.LapsedScannerExceptionWarnings()) != 0 {
					t.Fatal("Reload mutated caller-owned declarations")
				}
			} else {
				kind := config.ReloadTriggerFile
				if trigger == "SIGHUP" {
					kind = config.ReloadTriggerSignal
				}
				s.handleConfigReload(config.ReloadEvent{Config: candidate, Trigger: kind})
			}
			assertScannerLapse(t, s.proxy.CurrentConfig(), stderr)
		})
	}
}

func TestServerScannerExceptionRejectsBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*config.Config)
	}{
		{"path duplicate", func(c *config.Config) {
			c.FetchProxy.Monitoring.PathEntropyExclusions = append(c.FetchProxy.Monitoring.PathEntropyExclusions, c.FetchProxy.Monitoring.PathEntropyExclusions[0])
		}},
		{"query path", func(c *config.Config) { c.FetchProxy.Monitoring.QueryEntropyParamExclusions[0].Path = "/../files" }},
		{"warn parent", func(c *config.Config) { c.RequestBodyScanning.ContentEntropyAction = config.ActionWarn }},
		{"warn overlap", func(c *config.Config) {
			c.RequestBodyScanning.ContentEntropyWarnRoutes = append(c.RequestBodyScanning.ContentEntropyWarnRoutes, c.RequestBodyScanning.ContentEntropyWarnRoutes[0])
		}},
		{"body host", func(c *config.Config) { c.RequestBodyScanning.ContentEntropyExclusions[0].Host = "*.com" }},
		{"websocket metadata", func(c *config.Config) { c.WebSocketProxy.ContentEntropyExclusions[0].Owner = "bad\aowner" }},
		{"sigv4 path", func(c *config.Config) { c.RequestBodyScanning.SigV4CredentialRoutes[0].Path = "/" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, err := newLapseTestServer(t, scannerLapseYAML())
			if err != nil {
				t.Fatal(err)
			}
			live := s.proxy.CurrentConfig()
			before := live.CanonicalPolicyHash()
			candidate := live.Clone()
			past := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
			candidate.FetchProxy.Monitoring.PathEntropyExclusions[0].Expires = past
			candidate.FetchProxy.Monitoring.QueryEntropyParamExclusions[0].Expires = past
			candidate.RequestBodyScanning.ContentEntropyWarnRoutes[0].Expires = past
			candidate.RequestBodyScanning.SigV4CredentialRoutes[0].Expires = past
			candidate.RequestBodyScanning.ContentEntropyExclusions[0].Expires = past
			candidate.WebSocketProxy.ContentEntropyExclusions[0].Expires = past
			tc.edit(candidate)
			// This candidate would otherwise change restart-only state and mode.
			candidate.FetchProxy.Listen = ":9999"
			candidate.Mode = config.ModeAudit
			if err := s.Reload(candidate); err == nil {
				t.Fatal("malformed expired candidate accepted")
			}
			if s.proxy.CurrentConfig() != live || live.CanonicalPolicyHash() != before {
				t.Fatal("rejected reload mutated live policy")
			}
			if candidate.FetchProxy.Listen != ":9999" {
				t.Fatal("rejected reload mutated caller")
			}
		})
	}
}
