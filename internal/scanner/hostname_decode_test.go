// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func hostnameLabelCarrier(encoded string, width int) string {
	var labels []string
	for start := 0; start < len(encoded); start += width {
		labels = append(labels, encoded[start:min(start+width, len(encoded))])
	}
	return strings.Join(labels, ".")
}

func hostnameLabelEncodings(value string) map[string]string {
	data := []byte(value)
	standard := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	return map[string]string{
		"hex":       hex.EncodeToString(data),
		"base32":    standard,
		"lower32":   strings.ToLower(standard),
		"base32hex": strings.ToLower(base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(data)),
		"base64url": base64.RawURLEncoding.EncodeToString(data),
	}
}

func TestHostnameLabelDecoding(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for name, credential := range map[string]string{
		"github repeated": "ghp_" + strings.Repeat("aB3c", 9),
		"github diverse":  "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		"aws":             "AKIA" + "Q3ZT7XKP2M5RN8WB",
	} {
		for encoding, encoded := range hostnameLabelEncodings(credential) {
			// RFC 1035 section 2.3.4 permits labels up to 63 octets.
			for _, width := range []int{1, 4, 7, 12, 63} {
				t.Run(fmt.Sprintf("%s/%s/%d", name, encoding, width), func(t *testing.T) {
					host := hostnameLabelCarrier(encoded, width) + ".vendor.example"
					result := sc.Scan(t.Context(), "https://"+host+"/")
					if result.Allowed || result.Scanner != ScannerCoreDLP {
						t.Fatalf("want core DLP rejection, got %+v", result)
					}
				})
			}
		}
	}
}

func TestHostnameLabelConfiguredDecoding(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.IncludeDefaults = ptrBool(false)
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Recovery Marker", Regex: `recovery_[A-Z0-9]{24}`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	marker := "recovery_" + "ABCDEFGHIJKLMNOPQRSTUVWX"
	for encoding, encoded := range hostnameLabelEncodings(marker) {
		for _, suffix := range []string{"vendor.example", "vendor.co.uk", "vendor.github.io"} {
			t.Run(encoding+"/"+suffix, func(t *testing.T) {
				parsed, err := url.Parse("https://" + hostnameLabelCarrier(encoded, 4) + "." + suffix + ".:8443/")
				if err != nil {
					t.Fatal(err)
				}
				result, _ := sc.checkDLP(parsed)
				if result.Allowed || result.Scanner != ScannerDLP || !strings.Contains(result.Reason, "Recovery Marker") {
					t.Fatalf("want configured DLP rejection, got %+v", result)
				}
			})
		}
	}
}

func TestHostnameLabelHarmless(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, host := range []string{
		"d111111abcdef8.cloudfront.net",
		"assets-9f86d081884c7d659a2feaa0c55ad015.cdn.vendor.example",
		"images.bucket.vendor.example",
		"project-build-artifacts.s3.us-east-1.amazonaws.com",
		"storage.googleapis.com",
		"project-build-artifacts.storage.googleapis.com",
		"account123.blob.core.windows.net",
		"my-service.eastus.azurecontainerapps.io",
		"ec2-203-0-113-10.compute-1.amazonaws.com",
		"xn--bcher-kva.example",
		"api.xn--bcher-kva.example",
		"xn--r8jz45g.xn--zckzah",
		"6768.6a6b.6c6d.6e6f.7071.7273.7475.7677.vendor.example",
		"ordinary.status.vendor.co.uk.",
	} {
		t.Run(host, func(t *testing.T) {
			if result := sc.Scan(t.Context(), "https://"+host+"/"); !result.Allowed {
				t.Fatalf("harmless hostname blocked: %+v", result)
			}
		})
	}
}

func TestHostnameLabelRandomRetainsEntropyPolicy(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, label := range []string{"a9k3m7p2v8x4q6r1t5w0y2z8", strings.Repeat("a9k3m7p2v8x4q6r1t5w0y2z8", 3)[:63]} {
		t.Run(label, func(t *testing.T) {
			// These non-credential labels already meet the subdomain entropy policy.
			// Hostname decoding must not replace that decision with a DLP finding.
			result := sc.Scan(t.Context(), "https://"+label+".vendor.example/")
			if result.Allowed || result.Scanner != ScannerSubdomainEntropy {
				t.Fatalf("want existing subdomain entropy refusal, got %+v", result)
			}
		})
	}
}

func TestHostnameLabelUnicodeSuffix(t *testing.T) {
	credential := "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for encoding, encoded := range hostnameLabelEncodings(credential) {
		t.Run(encoding, func(t *testing.T) {
			memo := &decodingMemo{}
			host := hostnameLabelCarrier(encoded, 4) + ".KKK.example"
			found := false
			for _, target := range appendHostnameDLPTargets(nil, host, memo) {
				if target.text == credential {
					found = true
				}
			}
			if !found {
				t.Fatal("case folding the suffix changed the payload boundary")
			}
		})
	}
}

func TestHostnameLabelViews(t *testing.T) {
	credential := "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for encoding, encoded := range hostnameLabelEncodings(credential) {
		t.Run(encoding, func(t *testing.T) {
			memo := &decodingMemo{}
			host := hostnameLabelCarrier(encoded, 4) + ".VENDOR.CO.UK."
			targets := appendHostnameDLPTargets(nil, host, memo)
			found := false
			for _, target := range targets {
				if target.text == credential {
					found = true
				}
			}
			if !found {
				t.Fatal("decoded payload-only view is absent")
			}
			if _, ok := memo.views[decodingMemoKey{text: encoded, includeURL: true}]; !ok {
				t.Fatal("payload did not use the shared bounded decoder")
			}
		})
	}
	for _, host := range []string{"", "localhost", "vendor.example", "127.0.0.1", "bad..example", "::1"} {
		t.Run(host, func(t *testing.T) {
			memo := &decodingMemo{}
			appendHostnameDLPTargets(nil, host, memo)
			for key := range memo.views {
				if key.text != host {
					t.Fatalf("unexpected payload view: %q", key.text)
				}
			}
		})
	}
}

func TestHostnameLabelDecodeBudget(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	payload := hex.EncodeToString([]byte("ordinary status data"))
	parsed, err := url.Parse("https://" + hostnameLabelCarrier(payload, 4) + ".vendor.example/")
	if err != nil {
		t.Fatal(err)
	}
	// Both consumers must preserve refusal when reusing an incomplete graph.
	memo := &decodingMemo{views: map[decodingMemoKey]memoDecode{
		{text: payload, includeURL: true}: {complete: false},
	}}
	if result := sc.checkCoreDLPWithDecodes(parsed, memo); result.Allowed || !memo.inspectionIncomplete() {
		t.Fatalf("core floor lost incomplete hostname inspection: %+v", result)
	}
	memo.incomplete = false
	if result, _ := sc.checkDLPWithDecodes(parsed, memo); result.Allowed || !memo.inspectionIncomplete() {
		t.Fatalf("configured DLP lost incomplete hostname inspection: %+v", result)
	}
}
