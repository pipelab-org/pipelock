// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const multipartRegionsContentType = "multipart/form-data; boundary=region-boundary"

func multipartRegionsBody(preamble, part, epilogue, newline string) []byte {
	return []byte(preamble + "--region-boundary" + newline +
		"Content-Disposition: form-data; name=field" + newline + newline + part + newline +
		"--region-boundary--" + newline + epilogue)
}

func TestMultipartRegionsDLPTransports(t *testing.T) {
	secret := "AKIA" + "Q9W8E7R6T5Y4U3I2"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	var percent strings.Builder
	for _, c := range []byte(secret) {
		_, _ = fmt.Fprintf(&percent, "%%%02X", c)
	}
	cases := []struct {
		name, preamble, part, epilogue, newline string
		block                                   bool
	}{
		{"preamble", secret + "\r\n", "ordinary text", "", "\r\n", true},
		{"epilogue", "", "ordinary text", secret, "\r\n", true},
		{"both", secret + "\r\n", "ordinary text", secret, "\r\n", true},
		{"split", "AKIA" + "\r\n", "Q9W8E7R6T5Y4U3I2", "", "\r\n", true},
		{"LF", secret + "\n", "ordinary text", secret, "\n", true},
		{"boundary-like", "--region-boundary-extra\r\n" + secret + "\r\n", "ordinary text", "", "\r\n", true},
		{"base64 preamble", encoded + "\r\n", "ordinary text", "", "\r\n", true},
		{"base64 epilogue", "", "ordinary text", encoded, "\r\n", true},
		{"percent preamble", percent.String() + "\r\n", "ordinary text", "", "\r\n", true},
		{"percent epilogue", "", "ordinary text", percent.String(), "\r\n", true},
		{"clean", "ordinary introduction\r\n", "ordinary text", "ordinary ending", "\r\n", false},
	}
	for _, surface := range []string{"forward", "intercept", "reverse"} {
		h := newUploadHarness(t, surface, uploadPolicy{config.ActionBlock, false})
		for _, tc := range cases {
			t.Run(surface+"/"+tc.name, func(t *testing.T) {
				body := multipartRegionsBody(tc.preamble, tc.part, tc.epilogue, tc.newline)
				status, hits, intact, message, headers := h.exercise(t, http.Header{"Content-Type": {multipartRegionsContentType}}, body)
				t.Logf("status=%d upstream_hits=%d block_reason=%q", status, hits, headers.Get("X-Pipelock-Block-Reason"))
				if tc.block {
					if status != http.StatusForbidden || hits != 0 || headers.Get("X-Pipelock-Block-Reason") != "dlp_match" {
						t.Fatalf("status=%d hits=%d headers=%v body=%s", status, hits, headers, message)
					}
				} else if status != http.StatusCreated || hits != 1 || !intact {
					t.Fatalf("status=%d hits=%d intact=%t body=%s", status, hits, intact, message)
				}
			})
		}
	}
}

func TestMultipartRegionsDLPEmptyForm(t *testing.T) {
	sc := newBodyDLPScanner(t)
	for _, region := range []string{"preamble", "epilogue"} {
		t.Run(region, func(t *testing.T) {
			secret := "AKIA" + "Q9W8E7R6T5Y4U3I2"
			body := "--region-boundary--\r\n" + secret
			if region == "preamble" {
				body = secret + "\r\n--region-boundary--\r\n"
			}
			_, result := scanRequestBody(t.Context(), BodyScanRequest{Body: strings.NewReader(body), ContentType: multipartRegionsContentType, MaxBytes: 4096, Scanner: sc, Action: config.ActionBlock})
			if result.Clean || len(result.DLPMatches) == 0 {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestMultipartRegionsDLPLimits(t *testing.T) {
	const limit = 1 << 20
	secret := "AKIA" + "Q9W8E7R6T5Y4U3I2"
	skeleton := multipartRegionsBody("\r\n", "ordinary text", "", "\r\n")
	// Short preamble lines remain within mime/multipart's line buffer.
	padding := func(n int) []byte { return []byte(strings.Repeat("x\n", n/2) + strings.Repeat("x", n%2)) }
	atLimit := append(padding(limit-len(skeleton)), skeleton...)
	seededSkeleton := multipartRegionsBody("\r\n"+secret+"\r\n", "ordinary text", "", "\r\n")
	seededLimit := append(padding(limit-len(seededSkeleton)), seededSkeleton...)
	for _, surface := range []string{"forward", "intercept", "reverse"} {
		h := newUploadHarness(t, surface, uploadPolicy{config.ActionWarn, true})
		for _, tc := range []struct {
			name           string
			body           []byte
			reason, detail string
			status         int
		}{
			{"at limit", atLimit, "", "", http.StatusCreated},
			{"credential at limit", seededLimit, "dlp_match", "", http.StatusForbidden},
			{"over limit", append([]byte("x"), atLimit...), "dlp_match", "max_body_bytes", http.StatusForbidden},
			{"missing close", []byte(secret + "\r\n--region-boundary\r\nContent-Disposition: form-data; name=field\r\n\r\nordinary text"), "dlp_match", "unexpected EOF", http.StatusForbidden},
		} {
			t.Run(surface+"/"+tc.name, func(t *testing.T) {
				wantReason, wantStatus := tc.reason, tc.status
				// Reverse rejects a known oversized Content-Length before body scanning.
				if surface == "reverse" && tc.name == "over limit" {
					wantReason, wantStatus = "data_budget", http.StatusRequestEntityTooLarge
				}
				status, hits, intact, message, headers := h.exercise(t, http.Header{"Content-Type": {multipartRegionsContentType}}, tc.body)
				if status != wantStatus || headers.Get("X-Pipelock-Block-Reason") != wantReason || !strings.Contains(message, tc.detail) {
					t.Fatalf("status=%d reason=%q body=%s", status, headers.Get("X-Pipelock-Block-Reason"), message)
				}
				if wantReason != "" {
					if hits != 0 {
						t.Fatalf("blocked request reached upstream %d times", hits)
					}
				} else if hits != 1 || !intact {
					t.Fatalf("hits=%d intact=%t", hits, intact)
				}
			})
		}
	}
}

func TestMultipartRegionsDLPActions(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	addBodyDLPTestPattern(cfg)
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	for _, region := range []string{"preamble", "epilogue"} {
		for _, action := range []string{config.ActionBlock, config.ActionWarn} {
			t.Run(region+"/"+action, func(t *testing.T) {
				preamble, epilogue := fakeBodyDLPSecret()+"\r\n", ""
				if region == "epilogue" {
					preamble, epilogue = "", fakeBodyDLPSecret()
				}
				body := multipartRegionsBody(preamble, "ordinary text", epilogue, "\r\n")
				scan := func(body []byte) ([]byte, BodyScanResult) {
					return scanRequestBody(t.Context(), BodyScanRequest{Body: bytes.NewReader(body), ContentType: multipartRegionsContentType, MaxBytes: 4096, Scanner: sc, Action: action})
				}
				_, control := scan(multipartRegionsBody("", fakeBodyDLPSecret(), "", "\r\n"))
				got, result := scan(body)
				if result.Clean || len(result.DLPMatches) == 0 || result.Action != control.Action || !bytes.Equal(got, body) {
					t.Fatalf("clean=%t matches=%d action=%q want=%q intact=%t", result.Clean, len(result.DLPMatches), result.Action, control.Action, bytes.Equal(got, body))
				}
			})
		}
	}
}

func TestMultipartRegionsDLPForwardingPolicy(t *testing.T) {
	secret := "key-" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
	for _, surface := range []string{"forward", "intercept", "reverse"} {
		for _, auditMode := range []bool{false, true} {
			for _, region := range []string{"preamble", "epilogue"} {
				t.Run(fmt.Sprintf("%s/audit=%t/%s", surface, auditMode, region), func(t *testing.T) {
					preamble, epilogue := secret+"\r\n", ""
					if region == "epilogue" {
						preamble, epilogue = "", secret
					}
					body := multipartRegionsBody(preamble, "ordinary text", epilogue, "\r\n")
					var log bytes.Buffer
					logger, err := audit.NewWithStream("json", "stdout", "", true, true, &log)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(logger.Close)
					status, hits, _ := exerciseObservedUpload(t, surface, uploadPolicy{config.ActionWarn, auditMode}, body, logger, multipartRegionsContentType)
					if status != http.StatusCreated || hits != 1 {
						t.Fatalf("status=%d hits=%d", status, hits)
					}
					if !strings.Contains(log.String(), "Mailgun API Key") {
						t.Fatalf("forwarded request must log a finding: %s", log.String())
					}
				})
			}
		}
	}
}

func TestMultipartRegionsDLPRedactionAndTrust(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.RequestBodyScanning.TrustedHosts = []string{"api.vendor.example"}
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	for _, region := range []string{"preamble", "epilogue"} {
		t.Run(region, func(t *testing.T) {
			secret := "AKIA" + "Q9W8E7R6T5Y4U3I2"
			preamble, epilogue := secret+"\r\n", ""
			if region == "epilogue" {
				preamble, epilogue = "", secret
			}
			data := multipartRegionsBody(preamble, "ordinary text", epilogue, "\r\n")
			for _, auditMode := range []bool{false, true} {
				body, result := scanRequestBody(t.Context(), BodyScanRequest{Body: bytes.NewReader(data), ContentType: multipartRegionsContentType, MaxBytes: 4096, Scanner: sc, Action: config.ActionWarn, AuditMode: auditMode, Host: "api.vendor.example", RedactMatcher: redact.NewDefaultMatcher(), RedactAllowlistUnparseable: []string{"api.vendor.example"}, DisablePatterns: []string{"AWS Access ID"}, PatternActions: map[string]string{"AWS Access ID": config.ActionWarn}})
				if result.Clean || len(result.DLPMatches) == 0 || !bytes.Equal(body, data) || !shouldHardBlockBodyCriticalDLP(result, "api.vendor.example", cfg) {
					t.Fatalf("core floor must survive trust, unparseable redaction allowance, audit and pattern overrides: clean=%t matches=%d", result.Clean, len(result.DLPMatches))
				}
				if result.RedactionReport == nil || result.RedactionReport.Applied {
					t.Fatal("multipart must retain existing unparseable redaction behavior")
				}
			}
		})
	}
}
