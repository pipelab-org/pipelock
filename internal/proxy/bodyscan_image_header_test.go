// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestScanRequestBody_ImageDataURLHeaderCredentialBlocks is the request-body
// path for a credential in a verified image data URL parameter, as text and
// inside JSON.
func TestScanRequestBody_ImageDataURLHeaderCredentialBlocks(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	secret := rawViewAccessKeyID()
	dataURL := "data:image/png;filename=" + secret + ";base64," + base64.StdEncoding.EncodeToString(rawViewTinyPNG(t))

	for _, tc := range []struct{ contentType, body string }{
		{"text/plain", dataURL},
		{"application/json", `{"note":"` + dataURL + `"}`},
	} {
		req := BodyScanRequest{
			Body:        strings.NewReader(tc.body),
			ContentType: tc.contentType,
			MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
			Scanner:     sc,
			Action:      cfg.RequestBodyScanning.Action,
			Host:        "api.vendor.example",
		}
		applyContentEntropyConfig(&req, cfg)
		_, result := scanRequestBody(t.Context(), req)
		if !rawViewHasPattern(result.DLPMatches, "AWS Access ID") || blockingBodyFinding(result, "api.vendor.example", cfg) != bodyBlockCauseDLP {
			t.Fatalf("%s body forwarded the header credential: %+v", tc.contentType, result)
		}
	}
}

func rawViewTinyPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 1, G: 2, B: 3, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
