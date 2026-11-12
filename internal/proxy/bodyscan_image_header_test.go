// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
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
		if !rawViewHasAWSAccessID(result.DLPMatches) || blockingBodyFinding(result, "api.vendor.example", cfg) != bodyBlockCauseDLP {
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

// JSON producers may escape slashes or spell ASCII with Unicode escapes. Both
// spellings must retain the verified-image policy of the extracted field view.
func TestScanRequestBody_JSONEscapedVerifiedImageStaysClean(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	imageBytes := rawViewTinyPNG(t)
	alphabetRun, err := base64.StdEncoding.DecodeString("akia" + strings.Repeat("A", 16))
	if err != nil {
		t.Fatal(err)
	}
	// A valid ancillary chunk aligns the alphabet run on a base64 boundary.
	data := append([]byte{'x'}, alphabetRun...)
	const chunkDataBytes = 16 // One alignment byte plus 15 decoded base64 bytes.
	if len(data) != chunkDataBytes {
		t.Fatal("unexpected fixture chunk size")
	}
	chunk := binary.BigEndian.AppendUint32(nil, chunkDataBytes)
	chunk = append(chunk, "raNd"...)
	chunk = append(chunk, data...)
	chunk = binary.BigEndian.AppendUint32(chunk, crc32.ChecksumIEEE(chunk[4:]))
	imageBytes = append(append(append([]byte(nil), imageBytes[:33]...), chunk...), imageBytes[33:]...)
	if _, err := png.Decode(bytes.NewReader(imageBytes)); err != nil {
		t.Fatalf("fixture is not a readable PNG: %v", err)
	}
	imageURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(imageBytes)
	if !strings.Contains(imageURL, "akia"+strings.Repeat("A", 16)) {
		t.Fatal("fixture lacks the alphabet run")
	}
	if result := sc.ScanTextForDLP(t.Context(), imageURL); !result.Clean {
		t.Fatalf("field control: %+v", result.Matches)
	}
	for name, escaped := range map[string]string{
		"slashes": strings.ReplaceAll(imageURL, "/", `\/`),
		"scheme":  strings.Replace(imageURL, "data:", `\u0064ata:`, 1),
		"payload": strings.Replace(imageURL, "iVBOR", `\u0069VBOR`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			result := rawViewScanJSONBody(t, sc, `{"image":"`+escaped+`"}`)
			if !result.Clean {
				t.Fatalf("escaped verified image refused: %+v", result)
			}
			withHeader := strings.Replace(escaped, ";base64,", ";filename="+rawViewAccessKeyID()+";base64,", 1)
			blocked := rawViewScanJSONBody(t, sc, `{"image":"`+withHeader+`"}`)
			if blocked.Clean || !rawViewHasAWSAccessID(blocked.DLPMatches) {
				t.Fatalf("escaped header credential passed: %+v", blocked)
			}
			unverified := strings.Replace(escaped, ";base64,", ";base64,broken", 1)
			blocked = rawViewScanJSONBody(t, sc, `{"image":"`+unverified+`"}`)
			if blocked.Clean || !rawViewHasAWSAccessID(blocked.DLPMatches) {
				t.Fatalf("unverified carrier was exempted: %+v", blocked)
			}
		})
	}
}
