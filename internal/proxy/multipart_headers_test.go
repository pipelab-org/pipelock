// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const multipartHeaderType = "multipart/form-data; boundary=B"

func multipartHeaderForm(headers, content string) []byte {
	return []byte("--B\r\nContent-Disposition: form-data; name=f\r\n" + headers + "\r\n" + content + "\r\n--B--\r\n")
}

func multipartHeaderCases(secret string) []struct {
	name   string
	body   []byte
	reason string
} {
	return []struct {
		name   string
		body   []byte
		reason string
	}{
		{"field name", multipartHeaderForm(secret+": x\r\n", "clean"), "dlp_match"},
		{"parameter name", []byte("--B\r\nContent-Disposition: form-data; name=f; " + secret + "=1\r\n\r\nclean\r\n--B--\r\n"), "dlp_match"},
		{"second transfer encoding", multipartHeaderForm("Content-Transfer-Encoding: 7bit\r\nContent-Transfer-Encoding: "+secret+"\r\n", "clean"), "dlp_match"},
		{"body control", multipartHeaderForm("", secret), "dlp_match"},
	}
}

func TestMultipartHeaderDLP(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	secret := "ghp_" + strings.Repeat("aB3dE5", 6)
	for _, tc := range multipartHeaderCases(secret) {
		t.Run(tc.name, func(t *testing.T) {
			_, result := scanRequestBody(context.Background(), BodyScanRequest{Body: bytes.NewReader(tc.body), ContentType: multipartHeaderType, MaxBytes: 1 << 20, Scanner: sc, Action: config.ActionBlock})
			t.Logf("clean=%v matches=%d reason=%q", result.Clean, len(result.DLPMatches), result.Reason)
			if result.Clean {
				t.Fatal("header content was not inspected")
			}
			if tc.name != "second transfer encoding" && len(result.DLPMatches) == 0 {
				t.Fatal("missing credential finding")
			}
			if tc.name == "second transfer encoding" && !strings.Contains(result.Reason, "multiple Content-Transfer-Encoding") {
				t.Fatalf("expected duplicate encoding refusal: %+v", result)
			}
		})
	}
}

func TestMultipartHeaderTransports(t *testing.T) {
	secret := "ghp_" + strings.Repeat("aB3dE5", 6)
	for _, surface := range []string{"forward", "intercept", "reverse"} {
		t.Run(surface, func(t *testing.T) {
			h := newUploadHarness(t, surface, uploadPolicy{config.ActionBlock, false})
			for _, tc := range multipartHeaderCases(secret) {
				t.Run(tc.name, func(t *testing.T) {
					status, hits, _, message, hdr := h.exercise(t, http.Header{"Content-Type": {multipartHeaderType}}, tc.body)
					t.Logf("status=%d upstream_hits=%d reason=%q", status, hits, hdr.Get("X-Pipelock-Block-Reason"))
					if status != http.StatusForbidden || hits != 0 || hdr.Get("X-Pipelock-Block-Reason") != tc.reason {
						t.Fatalf("status=%d hits=%d reason=%q response=%s", status, hits, hdr.Get("X-Pipelock-Block-Reason"), message)
					}
				})
			}
		})
	}
}

func TestMultipartHeaderWireViews(t *testing.T) {
	secret := fakeGitHubToken()
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"split name and value", multipartHeaderForm(secret[:12]+": "+secret[12:]+"\r\n", "clean")},
		{"folded split name and value", multipartHeaderForm(secret[:12]+": "+secret[12:24]+"\r\n\t"+secret[24:]+"\r\n", "clean")},
		{"folded value", multipartHeaderForm("X-Note: "+secret[:12]+"\r\n\t"+secret[12:]+"\r\n", "clean")},
		{"second part", []byte("--B\r\nContent-Disposition: form-data; name=a\r\n\r\nprefix --B is body text\r\n--B\r\n" + secret + ": clean\r\n\r\nhello\r\n--B--\r\n")},
		{"after encoded part", []byte("--B\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--B\r\n" + secret + ": x\r\n\r\nhello\r\n--B--\r\n")},
		{"after buffered headers", multipartHeaderForm("X-Long: "+strings.Repeat("a", 8192)+"\r\n"+secret+": x\r\n", "clean")},
		{"LF and padding", bytes.ReplaceAll(multipartHeaderForm(secret+": x\r\n", "clean"), []byte("\r\n"), []byte("\n"))},
		{"transport padding", bytes.ReplaceAll(multipartHeaderForm(secret+": x\r\n", "clean"), []byte("--B\r\n"), []byte("--B \t\r\n"))},
		{"preamble", append([]byte("ignored preamble\r\n"), multipartHeaderForm(secret+": x\r\n", "clean")...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testScannerConfig()
			sc := scanner.MustNew(cfg)
			defer sc.Close()
			_, result := scanRequestBody(t.Context(), BodyScanRequest{Body: bytes.NewReader(tc.body), ContentType: multipartHeaderType, MaxBytes: 1 << 20, Scanner: sc})
			if result.Clean || len(result.DLPMatches) == 0 {
				t.Fatalf("missing credential finding: %+v", result)
			}
			for _, surface := range []string{"forward", "intercept", "reverse"} {
				t.Run(surface, func(t *testing.T) {
					status, hits, _, message, hdr := exerciseUpload(t, surface, uploadPolicy{config.ActionBlock, false}, multipartHeaderType, tc.body)
					if status != http.StatusForbidden || hits != 0 || hdr.Get("X-Pipelock-Block-Reason") != "dlp_match" {
						t.Fatalf("status=%d hits=%d response=%s", status, hits, message)
					}
				})
			}
		})
	}
}

func TestMultipartHeaderWarnPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, secret string
		audit        bool
		status       int
	}{
		{"non-core audit warning", fakeNonCoreAPIKey(), true, http.StatusCreated},
		{"core warn floor", fakeGitHubToken(), true, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, form := range multipartHeaderCases(tc.secret) {
				t.Run(form.name, func(t *testing.T) {
					cfg := testScannerConfig()
					sc := scanner.MustNew(cfg)
					defer sc.Close()
					_, result := scanRequestBody(t.Context(), BodyScanRequest{Body: bytes.NewReader(form.body), ContentType: multipartHeaderType, MaxBytes: 1 << 20, Scanner: sc, Action: config.ActionWarn})
					want := tc.status
					if form.name == "second transfer encoding" {
						want = http.StatusForbidden
					} else if result.Clean || len(result.DLPMatches) == 0 {
						t.Fatalf("missing warning finding: %+v", result)
					}
					for _, surface := range []string{"forward", "intercept", "reverse"} {
						t.Run(surface, func(t *testing.T) {
							status, hits, intact, message, _ := exerciseUpload(t, surface, uploadPolicy{config.ActionWarn, tc.audit}, multipartHeaderType, form.body)
							if status != want || (want == http.StatusCreated && (hits != 1 || !intact)) || (want == http.StatusForbidden && hits != 0) {
								t.Fatalf("status=%d hits=%d intact=%t response=%s", status, hits, intact, message)
							}
						})
					}
				})
			}
		})
	}
}

func TestMultipartHeaderOrdinaryForms(t *testing.T) {
	// curl -F note=hello and Python requests files/data emit these bodies;
	// only their generated boundary has been replaced with B.
	curlForm := []byte("--B\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--B--\r\n")
	requestsForm := []byte("--B\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"hello.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B--\r\n")
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"curl", curlForm},
		{"requests", requestsForm},
		{"browser", []byte("--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"hello.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B--\r\n")},
		{"base64", multipartHeaderForm("Content-Transfer-Encoding: base64\r\n", "aGVsbG8=")},
		{"quoted printable", multipartHeaderForm("Content-Transfer-Encoding: quoted-printable\r\n", "hello=20world")},
		{"boundary in header", multipartHeaderForm("X-Note: --B\r\n", "hello")},
		{"empty headers", []byte("--B\r\n\r\nhello\r\n--B--\r\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testScannerConfig()
			sc := scanner.MustNew(cfg)
			defer sc.Close()
			_, result := scanRequestBody(t.Context(), BodyScanRequest{Body: bytes.NewReader(tc.body), ContentType: multipartHeaderType, MaxBytes: 1 << 20, Scanner: sc})
			if !result.Clean {
				t.Fatalf("ordinary form refused: %+v", result)
			}
			for _, surface := range []string{"forward", "intercept", "reverse"} {
				t.Run(surface, func(t *testing.T) {
					status, hits, intact, message, _ := exerciseUpload(t, surface, uploadPolicy{config.ActionBlock, false}, multipartHeaderType, tc.body)
					if status != http.StatusCreated || hits != 1 || !intact {
						t.Fatalf("status=%d hits=%d intact=%t response=%s", status, hits, intact, message)
					}
				})
			}
		})
	}
}

func TestMultipartHeaderLimits(t *testing.T) {
	for _, n := range []int{99, 100, 101} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			body := []byte(strings.Repeat("--B\r\nContent-Disposition: form-data; name=f\r\n\r\nx\r\n", n) + "--B--\r\n")
			_, err := extractMultipart(body, "B", 1<<20)
			if (err != "") != (n > 100) {
				t.Fatalf("parts=%d error=%q", n, err)
			}
		})
	}
	body := multipartHeaderForm("X-Long: "+strings.Repeat("a", 1<<20)+"\r\n", "hello")
	cfg := testScannerConfig()
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	_, result := scanRequestBody(t.Context(), BodyScanRequest{Body: bytes.NewReader(body), ContentType: multipartHeaderType, MaxBytes: 1 << 20, Scanner: sc})
	if result.Clean || !strings.Contains(result.Reason, "max_body_bytes") {
		t.Fatalf("body size limit not enforced: %+v", result)
	}
	if _, err := extractMultipart(body, "B", 1024); !strings.Contains(err, "headers exceed max_body_bytes") {
		t.Fatalf("header limit error=%q", err)
	}
	for _, surface := range []string{"forward", "intercept", "reverse"} {
		t.Run(surface, func(t *testing.T) {
			status, hits, _, message, _ := exerciseUpload(t, surface, uploadPolicy{config.ActionBlock, false}, multipartHeaderType, body)
			want := http.StatusForbidden
			if surface == "reverse" {
				want = http.StatusRequestEntityTooLarge
			}
			if status != want || hits != 0 {
				t.Fatalf("status=%d hits=%d response=%s", status, hits, message)
			}
		})
	}
}

func TestRawMultipartHeaders(t *testing.T) {
	for _, tc := range []struct {
		name, body, want, rest string
		ok                     bool
	}{
		{"wire spelling", "preamble\r\n--B \t\r\nGhp_AbC: x\r\nX-Note: folded\r\n\tvalue\r\n\r\nhello", "Ghp_AbC: x\r\nX-Note: folded\r\n\tvalue\r\n", "hello", true},
		{"LF", "--B\nX-Note: x\n\nhello", "X-Note: x\n", "hello", true},
		{"empty", "--B\r\n\r\nhello", "", "hello", true},
		{"no delimiter", "nothing", "", "", false},
		{"no blank line", "--B\r\nX-Note: x\r\n", "", "", false},
		{"no newline", "--B\r\nX-Note: x", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, rest, ok := rawMultipartHeaders([]byte(tc.body), "B")
			if string(got) != tc.want || string(rest) != tc.rest || ok != tc.ok {
				t.Fatalf("headers=%q rest=%q ok=%t", got, rest, ok)
			}
		})
	}
}

func TestMultipartHeaderDuplicateEncoding(t *testing.T) {
	for _, headers := range []string{
		"Content-Transfer-Encoding: 7bit\r\nContent-Transfer-Encoding: 7bit\r\n",
		"content-transfer-encoding: base64\r\nCONTENT-TRANSFER-ENCODING: binary\r\n",
		"Content-Transfer-Encoding:\r\nContent-Transfer-Encoding:\r\n",
	} {
		t.Run(headers, func(t *testing.T) {
			body := multipartHeaderForm(headers, "hello")
			for _, surface := range []string{"forward", "intercept", "reverse"} {
				t.Run(surface, func(t *testing.T) {
					status, hits, _, message, hdr := exerciseUpload(t, surface, uploadPolicy{config.ActionWarn, true}, multipartHeaderType, body)
					if status != http.StatusForbidden || hits != 0 || hdr.Get("X-Pipelock-Block-Reason") != "dlp_match" || !strings.Contains(message, "multiple Content-Transfer-Encoding") {
						t.Fatalf("status=%d hits=%d reason=%q response=%s", status, hits, hdr.Get("X-Pipelock-Block-Reason"), message)
					}
				})
			}
		})
	}
}
