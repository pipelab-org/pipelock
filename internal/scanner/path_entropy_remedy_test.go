// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestPathEntropyRemedyGuidance(t *testing.T) {
	for _, fragment := range []string{
		"defaults to HTTPS",
		"`scheme: http`",
		"path visible on the network",
		"exclusion does not encrypt it",
		"separate entries if both schemes are needed",
	} {
		t.Run(fragment, func(t *testing.T) {
			hint := OperatorHintForResult(ScannerEntropy, "high entropy path segment")
			if !strings.Contains(hint, fragment) {
				t.Fatalf("path-entropy hint %q omits %q", hint, fragment)
			}
			if queryHint := OperatorHintForResult(ScannerEntropy, `high entropy query param "data"`); strings.Contains(queryHint, "`scheme: http`") {
				t.Fatalf("HTTP path guidance leaked into query guidance: %q", queryHint)
			}
		})
	}
}

func TestPathEntropyRemedyDocumentedConfig(t *testing.T) {
	doc, err := os.ReadFile("../../docs/false-positive-tuning.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(doc), "## Tuning Entropy Thresholds\n")
	if !ok {
		t.Fatal("entropy tuning section missing")
	}
	_, fenced, ok := strings.Cut(section, "```yaml\n")
	if !ok {
		t.Fatal("entropy tuning YAML missing")
	}
	example, _, ok := strings.Cut(fenced, "```")
	if !ok {
		t.Fatal("entropy tuning YAML fence is incomplete")
	}

	const host = "packages.vendor.example"
	const route = "/releases/"
	credential := "gh" + "p_" + strings.Repeat("a", 36)
	for _, mode := range []string{"both", "https only", "http only", "no exclusions"} {
		t.Run(mode, func(t *testing.T) {
			cfg, loadErr := config.LoadBytes([]byte(example))
			if loadErr != nil {
				t.Fatalf("load documented YAML: %v", loadErr)
			}
			entries := cfg.FetchProxy.Monitoring.PathEntropyExclusions
			if len(entries) != 2 || entries[0].Scheme != config.QueryEntropyParamDefaultScheme || entries[1].Scheme != "http" {
				t.Fatalf("want defaulted HTTPS and explicit HTTP entries, got %+v", entries)
			}
			switch mode {
			case "https only":
				cfg.FetchProxy.Monitoring.PathEntropyExclusions = entries[:1]
			case "http only":
				cfg.FetchProxy.Monitoring.PathEntropyExclusions = entries[1:]
			case "no exclusions":
				cfg.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{}
			}
			cfg.Internal = nil // no DNS; literal-IP SSRF protection remains enabled
			s := MustNew(cfg)
			defer s.Close()

			for _, scheme := range []string{"https", "http"} {
				t.Run(scheme, func(t *testing.T) {
					base := scheme + "://" + host
					raw := base + route + highEntropyID
					wantAllowed := mode == "both" || mode == scheme+" only"
					res := s.Scan(t.Context(), raw)
					if res.Allowed != wantAllowed || (!wantAllowed && res.Scanner != ScannerEntropy) {
						t.Fatalf("Scan(%q) = %+v, want allowed=%v and entropy denial otherwise", raw, res, wantAllowed)
					}
					if !wantAllowed {
						return
					}
					for _, tt := range []struct {
						name    string
						rawURL  string
						scanner string
					}{
						{"wrong host", scheme + "://other.vendor.example" + route + highEntropyID, ScannerEntropy},
						{"subdomain", scheme + "://sub." + host + route + highEntropyID, ScannerEntropy},
						{"wrong prefix", base + "/other/" + highEntropyID, ScannerEntropy},
						{"prefix lookalike", base + "/releasesX/" + highEntropyID, ScannerEntropy},
						{"encoded separator", base + "/releases%2F" + highEntropyID, ScannerEntropy},
						{"query entropy", raw + "?data=" + highEntropyID, ScannerEntropy},
						{"DLP", base + route + credential, ScannerCoreDLP},
					} {
						t.Run(tt.name, func(t *testing.T) {
							got := s.Scan(t.Context(), tt.rawURL)
							if got.Allowed || got.Scanner != tt.scanner {
								t.Fatalf("Scan(%q) = %+v, want %s denial", tt.rawURL, got, tt.scanner)
							}
						})
					}
				})
			}

			if mode != "both" {
				return
			}
			for _, tt := range []struct {
				name    string
				host    string
				scanner string
			}{
				{"subdomain entropy", "0123456789abcdef." + host, ScannerSubdomainEntropy},
				{"literal SSRF", "127.0.0.1", ScannerCoreSSRF},
			} {
				t.Run(tt.name, func(t *testing.T) {
					for i := range cfg.FetchProxy.Monitoring.PathEntropyExclusions {
						cfg.FetchProxy.Monitoring.PathEntropyExclusions[i].Host = tt.host
					}
					scoped := MustNew(cfg)
					defer scoped.Close()
					for _, scheme := range []string{"http", "https"} {
						raw := scheme + "://" + tt.host + route + highEntropyID
						parsed, parseErr := url.Parse(raw)
						if parseErr != nil {
							t.Fatal(parseErr)
						}
						if !scoped.isPathEntropyExcluded(parsed) {
							t.Fatalf("fixture does not match the path exclusion: %s", raw)
						}
						got := scoped.Scan(t.Context(), raw)
						if got.Allowed || got.Scanner != tt.scanner {
							t.Fatalf("Scan(%q) = %+v, want %s denial on the excluded route", raw, got, tt.scanner)
						}
					}
				})
			}
		})
	}
}
