// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// resourceSpelling rewrites a canonical "scheme://rest" URL into another
// spelling.
type resourceSpelling func(scheme, rest string) string

func canonicalResource(scheme, rest string) string { return scheme + "://" + rest }

// metadataHost is a link-local address the URL policy always refuses.
func metadataHost() net.IP { return net.IPv4(169, 254, 169, 254).To4() }

const resourceTestPath = "/probe"

func TestScanRequest_ResourcesReadHTTPSpellingsConsumeOneRateSlot(t *testing.T) {
	for _, uri := range []string{
		"https://example.com/docs/readme.md",
		"HTTPS://example.com/docs/readme.md",
		"hTtPs://example.com/docs/readme.md",
		"https:example.com/docs/readme.md",
		"http://example.com/a" + `\` + "b",
	} {
		t.Run(uri, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.FetchProxy.Monitoring.MaxReqPerMinute = 2
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			line := []byte(makeRequest(1, "resources/read", map[string]string{"uri": uri}))
			for i := range 2 {
				v := ScanRequest(t.Context(), line, sc, config.ActionBlock, config.ActionBlock)
				if !v.Clean {
					t.Fatalf("read %d used more than one request slot: %+v", i+1, v.URLFindings)
				}
			}
			v := ScanRequest(t.Context(), line, sc, config.ActionBlock, config.ActionBlock)
			if len(v.URLFindings) != 1 || v.URLFindings[0].Scanner != scanner.ScannerRateLimit ||
				inputVerdictEffectiveAction(v, config.ActionBlock) != config.ActionBlock {
				t.Fatalf("third read must be blocked by the rate limit: %+v", v)
			}
		})
	}
}

// resources/read URIs reach the URL policy when they are HTTP(S). A URL
// reader that follows the WHATWG URL standard reads other spellings as the
// same HTTP(S) address. Each spelling below must reach the URL policy the
// same way the canonical one does, unless the submitted spelling is already
// refused by the raw URL parser. Keep that earlier refusal explicit.
func TestScanRequest_ResourcesReadHTTPSpellingsUseURLPolicy(t *testing.T) {
	sc := testInputScanner(t)
	rest := metadataHost().String() + resourceTestPath
	ctl := func(b byte) string { return string([]byte{b}) }
	tests := []struct {
		name        string
		scheme      string
		spell       resourceSpelling
		wantScanner string
	}{
		{"canonical", "http", canonicalResource, scanner.ScannerCoreSSRF},
		{"scheme_case_variant", "HTTP", canonicalResource, scanner.ScannerCoreSSRF},
		{"scheme_case_variant_tls", "hTtPs", canonicalResource, scanner.ScannerCoreSSRF},
		{"surrounding_space", "http", func(s, r string) string { return "  " + canonicalResource(s, r) + "  " }, scanner.ScannerCoreSSRF},
		{"leading_c0_control", "http", func(s, r string) string { return ctl(0x01) + canonicalResource(s, r) }, scanner.ScannerCoreSSRF},
		{"leading_nul_control", "http", func(s, r string) string { return ctl(0x00) + canonicalResource(s, r) }, scanner.ScannerCoreSSRF},
		{"trailing_c0_control", "http", func(s, r string) string { return canonicalResource(s, r) + ctl(0x1f) }, scanner.ScannerParser},
		{"scheme_tab_inserted", "http", func(s, r string) string { return s[:2] + ctl('\t') + s[2:] + "://" + r }, scanner.ScannerCoreSSRF},
		{"scheme_newline_inserted", "http", func(s, r string) string { return s[:1] + ctl('\n') + s[1:] + "://" + r }, scanner.ScannerCoreSSRF},
		{"authority_cr_inserted", "http", func(s, r string) string {
			i := strings.IndexByte(r, '.')
			return s + "://" + r[:i+1] + ctl('\r') + r[i+1:]
		}, scanner.ScannerParser},
		{"scheme_slash_variant_one", "http", func(s, r string) string { return s + ":/" + r }, scanner.ScannerCoreSSRF},
		{"scheme_slash_variant_none", "http", func(s, r string) string { return s + ":" + r }, scanner.ScannerCoreSSRF},
		{"scheme_slash_variant_three", "http", func(s, r string) string { return s + ":///" + r }, scanner.ScannerParser},
		{"scheme_backslash_variant", "http", func(s, r string) string { return s + ":" + strings.Repeat(`\`, 2) + r }, scanner.ScannerCoreSSRF},
		{"scheme_mixed_separator_variant", "https", func(s, r string) string { return s + ":/" + `\` + r }, scanner.ScannerCoreSSRF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri := tt.spell(tt.scheme, rest)
			wantView := strings.ToLower(tt.scheme) + "://" + rest
			if view, ok, err := httpResourceURLView(uri); !ok || err != nil || view != wantView {
				t.Fatalf("%s: URL view = %q, %v; want %q", tt.name, view, ok, wantView)
			}
			line := makeRequest(1, "resources/read", map[string]string{"uri": uri})
			verdict := ScanRequest(context.Background(), []byte(line), sc, config.ActionWarn, config.ActionBlock)
			if verdict.Clean {
				t.Fatalf("%s: resources/read reached no URL policy", tt.name)
			}
			if len(verdict.URLFindings) != 1 || verdict.URLFindings[0].Scanner != tt.wantScanner {
				t.Fatalf("%s: expected %s finding, got %+v", tt.name, tt.wantScanner, verdict.URLFindings)
			}
			if got := inputVerdictEffectiveAction(verdict, config.ActionWarn); got != config.ActionBlock {
				t.Fatalf("%s: effective action = %q, want %q", tt.name, got, config.ActionBlock)
			}
			publicURI := tt.spell(tt.scheme, "example.com"+resourceTestPath)
			public := ScanRequest(t.Context(), []byte(makeRequest(1, "resources/read", map[string]string{"uri": publicURI})), sc, config.ActionBlock, config.ActionBlock)
			if tt.wantScanner == scanner.ScannerParser {
				if public.Clean || len(public.URLFindings) != 1 || public.URLFindings[0].Scanner != scanner.ScannerParser {
					t.Fatalf("%s: raw syntax refusal must also apply to public hosts: %+v", tt.name, public)
				}
			} else if !public.Clean {
				t.Fatalf("%s: public destination should stay clean: %+v", tt.name, public)
			}
		})
	}
}

// Host spellings must reach destination policy unless the raw parser refuses
// them first. Opaque spellings also exercise normalization without that refusal.
func TestScanRequest_ResourcesReadHostSpellingsUseURLPolicy(t *testing.T) {
	sc := testInputScanner(t)
	ip := metadataHost()
	n := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	octets := make([]string, 4)
	escaped := ""
	for i, b := range ip {
		octets[i] = fmt.Sprintf("0%o", b)
	}
	for _, c := range ip.String() {
		escaped += fmt.Sprintf("%%%02X", c)
	}
	tests := []struct {
		name string
		host string
	}{
		{"host_trailing_dot", ip.String() + "."},
		{"host_hex_integer", fmt.Sprintf("0x%x", n)},
		{"host_decimal_integer", fmt.Sprintf("%d", n)},
		{"host_octal_octets", strings.Join(octets, ".")},
		{"host_v4_mapped_v6", "[::ffff:" + ip.String() + "]"},
		{"host_with_userinfo", "user@" + ip.String()},
		{"host_percent_escaped", escaped},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, prefix := range []string{"http://", "http:"} {
				uri := prefix + tt.host + resourceTestPath
				wantScanner := scanner.ScannerCoreSSRF
				if tt.name == "host_percent_escaped" && prefix == "http://" {
					wantScanner = scanner.ScannerParser
				}
				line := makeRequest(1, "resources/read", map[string]string{"uri": uri})
				verdict := ScanRequest(t.Context(), []byte(line), sc, config.ActionWarn, config.ActionBlock)
				if verdict.Clean || len(verdict.URLFindings) != 1 || verdict.URLFindings[0].Scanner != wantScanner {
					t.Fatalf("%s: expected %s finding, got %+v", uri, wantScanner, verdict)
				}
				if got := inputVerdictEffectiveAction(verdict, config.ActionWarn); got != config.ActionBlock {
					t.Fatalf("%s: effective action = %q, want %q", uri, got, config.ActionBlock)
				}
			}
		})
	}
}

// Positive control: ordinary resource identifiers, including look-alikes of
// the spellings above that no URL reader treats as HTTP(S), stay clean.
func TestScanRequest_ResourcesReadNonHTTPSpellingsStayClean(t *testing.T) {
	sc := testInputScanner(t)
	host := metadataHost().String()
	tests := []struct {
		name string
		uri  string
	}{
		{"custom_scheme_template", "ui://trusted/template.html"},
		{"file_scheme", "file:///etc/hosts"},
		{"custom_scheme_with_http_segment", "repo://http/" + host},
		{"scheme_with_http_prefix", "httpx://" + host + "/"},
		{"custom_scheme_with_embedded_url", "memo:http://" + host + "/"},
		{"public_https", "https://example.com/docs/readme.md"},
		{"public_http_backslash_in_path", "http://example.com/a" + `\` + "b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := makeRequest(1, "resources/read", map[string]string{"uri": tt.uri})
			verdict := ScanRequest(context.Background(), []byte(line), sc, config.ActionBlock, config.ActionBlock)
			if !verdict.Clean {
				t.Fatalf("%s: resources/read should stay clean: %+v", tt.name, verdict)
			}
		})
	}
}

// A URL reader that follows the WHATWG host parser maps a host that is not
// plain ASCII (UTS 46) before it resolves the address, so an ideographic full
// stop or a full-width digit names the same address as the dotted form. The
// literal-address floor must see that address.
func TestScanRequest_ResourcesReadNonASCIIHostSpellingsUseURLPolicy(t *testing.T) {
	sc := testInputScanner(t)
	ip := metadataHost()
	fullwidth := func(s string, dot string) string {
		var b strings.Builder
		for _, c := range s {
			switch {
			case c == '.':
				b.WriteString(dot)
			case c >= '0' && c <= '9':
				b.WriteRune(c - '0' + '０')
			default:
				b.WriteRune(c)
			}
		}
		return b.String()
	}
	dots := func(dot string) string { return strings.ReplaceAll(ip.String(), ".", dot) }
	tests := []struct {
		name string
		host string
	}{
		{"ideographic_full_stop", dots("。")},
		{"halfwidth_ideographic_full_stop", dots("｡")},
		{"fullwidth_full_stop", dots("．")},
		{"fullwidth_digits", fullwidth(ip.String(), ".")},
		{"fullwidth_digits_and_stops", fullwidth(ip.String(), "。")},
		{"ideographic_full_stop_trailing", dots("。") + "。"},
		{"ideographic_full_stop_percent_escaped", dots("%E3%80%82")},
		{"userinfo_before_mapped_host", "user@" + dots("。")},
		{"mapped_host_with_port", dots("。") + ":80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, scheme := range []string{"http", "HTTPS"} {
				uri := scheme + "://" + tt.host + resourceTestPath
				line := makeRequest(1, "resources/read", map[string]string{"uri": uri})
				verdict := ScanRequest(context.Background(), []byte(line), sc, config.ActionWarn, config.ActionBlock)
				if verdict.Clean {
					t.Fatalf("%s: resources/read reached no URL policy", uri)
				}
				if len(verdict.URLFindings) != 1 || verdict.URLFindings[0].Scanner != scanner.ScannerCoreSSRF {
					t.Fatalf("%s: expected core SSRF finding, got %+v", uri, verdict.URLFindings)
				}
				if got := inputVerdictEffectiveAction(verdict, config.ActionWarn); got != config.ActionBlock {
					t.Fatalf("%s: effective action = %q, want %q", uri, got, config.ActionBlock)
				}
			}
		})
	}
}

// Positive control: a public internationalized host and an IPv6 literal still
// pass the URL policy, and each read consumes one rate slot.
func TestScanRequest_ResourcesReadNonASCIIPublicHostStaysClean(t *testing.T) {
	for _, uri := range []string{
		"https://bücher.example/docs",
		"HTTPS://BÜCHER.example/docs",
		"https://xn--bcher-kva.example/docs",
		"https://foo_。example/docs",
		"http:foo_。example/docs",
		"https://[2001:db8::1]/docs",
		"https://user@bücher.example:8443/docs?q=1#f",
	} {
		t.Run(uri, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.FetchProxy.Monitoring.MaxReqPerMinute = 2
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			line := []byte(makeRequest(1, "resources/read", map[string]string{"uri": uri}))
			for i := range 2 {
				if v := ScanRequest(t.Context(), line, sc, config.ActionBlock, config.ActionBlock); !v.Clean {
					t.Fatalf("read %d should stay clean: %+v", i+1, v.URLFindings)
				}
			}
			v := ScanRequest(t.Context(), line, sc, config.ActionBlock, config.ActionBlock)
			if len(v.URLFindings) != 1 || v.URLFindings[0].Scanner != scanner.ScannerRateLimit ||
				inputVerdictEffectiveAction(v, config.ActionBlock) != config.ActionBlock {
				t.Fatalf("third read must be blocked by the rate limit: %+v", v)
			}
		})
	}
}

func TestAsciiAuthorityHost(t *testing.T) {
	tests := []struct {
		name, in, want string
		wantErr        bool
	}{
		{"plain_ascii", "example.com/a", "example.com/a", false},
		{"ipv6_literal", "[::1]:80/a", "[::1]:80/a", false},
		{"mapped_stop", "169。254。169。254/a?q=。", "169.254.169.254/a?q=。", false},
		{"userinfo_and_port", "u:p@1０.0.0.1:8080/x", "u:p@10.0.0.1:8080/x", false},
		{"escaped_stop", "169%E3%80%82254%E3%80%82169%E3%80%82254", "169.254.169.254", false},
		{"mapping_rejected", "a\u200db\u0378.example/x", "", true},
		{"no_path", "bücher.example", "xn--bcher-kva.example", false},
		{"url_host_underscore", "foo_。example/x", "foo_.example/x", false},
		{"ignored_host", "\u00ad/x", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := asciiAuthorityHost(tt.in)
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Fatalf("host view = %q, %v; want %q, error %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestScanRequest_ResourcesReadURLHostMapping(t *testing.T) {
	for _, prefix := range []string{"http:", "http://", "https:"} {
		for _, host := range []string{"foo_。example", "foo_．example", "foo_｡example", "ＦＯＯ_。example", "foo_%E3%80%82example"} {
			t.Run(prefix+host, func(t *testing.T) {
				cfg := config.Defaults()
				cfg.Internal = nil
				cfg.FetchProxy.Monitoring.Blocklist = []string{"*.example"}
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				uri := prefix + host + "/"
				v := ScanRequest(t.Context(), []byte(makeRequest(1, "resources/read", map[string]string{"uri": uri})), sc, config.ActionWarn, config.ActionBlock)
				want := scanner.ScannerBlocklist
				if v.Clean || len(v.URLFindings) != 1 || v.URLFindings[0].Scanner != want || inputVerdictEffectiveAction(v, config.ActionWarn) != config.ActionBlock {
					t.Fatalf("mapped destination must be blocked by %s: %+v", want, v)
				}
			})
		}
	}
	for _, uri := range []string{"http:a\u200db\u0378.example/", "http:\u00ad/"} {
		sc := testInputScanner(t)
		v := ScanRequest(t.Context(), []byte(makeRequest(1, "resources/read", map[string]string{"uri": uri})), sc, config.ActionWarn, config.ActionWarn)
		if v.Clean || len(v.URLFindings) != 1 || v.URLFindings[0].Scanner != scanner.ScannerParser || inputVerdictEffectiveAction(v, config.ActionWarn) != config.ActionBlock {
			t.Fatalf("invalid host must fail closed: %+v", v)
		}
	}
}
