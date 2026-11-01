// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestMultipartHeaderJoinedRegionDLP(t *testing.T) {
	sc := scanner.MustNew(testScannerConfig())
	defer sc.Close()
	body := multipartRegionsBody("AKIA\r\n", "Q9W8E7R6T5Y4U3I2", "", "\r\n")
	_, got := scanRequestBody(t.Context(), BodyScanRequest{Body: bytes.NewReader(body), ContentType: multipartRegionsContentType, MaxBytes: 4096, Scanner: sc, Action: config.ActionBlock})
	if len(got.DLPMatches) == 0 {
		t.Fatalf("credential split between preamble and part missed: %+v", got)
	}
	for _, surface := range []string{"forward", "intercept", "reverse"} {
		h := newUploadHarness(t, surface, uploadPolicy{config.ActionWarn, true})
		for _, header := range []string{"", "Custom: ordinary\r\n"} {
			// Both the standard Content-Disposition section and Custom sort
			// between the A-prefixed credential fragment and the Q-prefixed one.
			variant := bytes.ReplaceAll(body, []byte("Content-Disposition:"), []byte(header+"Content-Disposition:"))
			status, hits, _, message, headers := h.exercise(t, http.Header{"Content-Type": {multipartRegionsContentType}}, variant)
			if status != http.StatusForbidden || hits != 0 || headers.Get("X-Pipelock-Block-Reason") != "dlp_match" {
				t.Fatalf("%s header=%q status=%d hits=%d body=%s", surface, header, status, hits, message)
			}
		}
	}
}

func TestMultipartHeaderAuthorizedURL(t *testing.T) {
	sc := scanner.MustNew(testScannerConfig())
	defer sc.Close()
	query := url.Values{}
	query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	query.Set("X-Amz-Credential", fakeAPIKey()+"/20260831/us-east-1/s3/aws4_request")
	query.Set("X-Amz-Date", "20260831T120000Z")
	query.Set("X-Amz-Expires", "3600")
	query.Set("X-Amz-Signature", strings.Repeat("a", 64))
	query.Set("X-Amz-SignedHeaders", "host")
	presigned := "https://uploads.s3.amazonaws.com/object?" + query.Encode()
	for _, redaction := range []bool{false, true} {
		for _, bareKey := range []bool{false, true} {
			body := bytes.ReplaceAll(multipartHeaderForm("", presigned), []byte("name=f"), []byte("name=z"))
			if bareKey {
				body = bytes.ReplaceAll(body, []byte("--B--\r\n"), []byte("--B\r\nContent-Disposition: form-data; name=other\r\n\r\n"+fakeAPIKey()+"\r\n--B--\r\n"))
			}
			req := BodyScanRequest{
				Body: bytes.NewReader(body), ContentType: multipartHeaderType, MaxBytes: 8192, Scanner: sc, Scheme: "https", Method: http.MethodPost, Host: trustedHostsTestDestination, Path: "/upload", EntropyRoutePath: "/upload", Action: config.ActionBlock,
				SigV4CredentialRoutes: []config.RequestBodySigV4CredentialRoute{{Host: trustedHostsTestDestination, Path: "/upload", Methods: []string{http.MethodPost}, ContentTypes: []string{"multipart/form-data"}, Expires: temporaryExpiryDate(config.MaxRequestBodySigV4CredentialRouteHorizon)}},
			}
			if redaction {
				req.RedactMatcher = redact.NewDefaultMatcher()
				req.RedactAllowlistUnparseable = []string{req.Host}
			}
			_, got := scanRequestBody(t.Context(), req)
			if got.Clean == bareKey || (bareKey && len(got.DLPMatches) == 0) {
				t.Fatalf("redaction=%t bare-key=%t result=%+v", redaction, bareKey, got)
			}
		}
	}
}
