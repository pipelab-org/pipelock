// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package media

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testimage"
)

func TestImageDataURLView(t *testing.T) {
	data := base64.StdEncoding.EncodeToString(testimage.SmallPNG(t, ""))
	tests := []struct {
		name, raw string
		count     int
	}{
		{"ordinary text", "ordinary text", 0},
		{"root string", `"data"`, 0},
		{"malformed JSON", `{"data":!}`, 0},
		{"anthropic", `{"data":"` + data + `","media_type":"image/png"}`, 1},
		{"mcp", `{"mimeType":"image/png","data":"` + data + `"}`, 1},
		{"media type alias", `{"mediaType":"image/png","data":"` + data + `"}`, 1},
		{"resource", `{"mimeType":"image/png","blob":"` + data + `"}`, 1},
		{"raw", `{"mime_type":"image/png","raw":"` + data + `"}`, 1},
		{"openai", `{"data":[{"b64_json":"` + data + `"}]}`, 1},
		{"uppercase declaration", `{"media_type":"IMAGE/PNG","data":"` + data + `"}`, 1},
		{"escaped payload", `{"media_type":"image/png","data":"` + strings.ReplaceAll(data, "/", `\/`) + `"}`, 1},
		{"escaped key", `{"media_type":"image/png","d\u0061ta":"` + data + `"}`, 1},
		{"two", `[{"media_type":"image/png","data":"` + data + `"},{"data":"` + data + `","mimeType":"image/png"}]`, 2},
		{"mismatch", `{"media_type":"image/jpeg","data":"` + data + `"}`, 0},
		{"parent declaration", `{"media_type":"image/png","child":{"data":"` + data + `"}}`, 0},
		{"missing declaration", `{"data":"` + data + `"}`, 0},
		{"plaintext", `{"media_type":"image/png","data":"ordinary text"}`, 0},
		{"invalid alphabet", `{"media_type":"image/png","data":"!!!!!!!!!!!!!!!!!!!!!!!!"}`, 0},
		{"garbage suffix", `{"media_type":"image/png","data":"` + data + `!"}`, 0},
		{"overpadding", `{"media_type":"image/png","data":"` + data + `==="}`, 0},
		{"invalid final group", `{"media_type":"image/png","data":"` + data + `A"}`, 0},
		{"unrecognized magic", `{"media_type":"image/png","data":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}`, 0},
		{"short", `{"media_type":"image/png","data":"a"}`, 0},
		{"duplicate mime", `{"media_type":"image/jpeg","mimeType":"image/png","data":"` + data + `"}`, 0},
		{"nonstring mime", `{"media_type":null,"data":"` + data + `"}`, 0},
		{"nested mime", `{"media_type":{},"data":"` + data + `"}`, 0},
		{"nonstring duplicate mime", `{"media_type":"image/png","media_type":true,"data":"` + data + `"}`, 0},
		{"truncated JSON", `{"media_type":"image/png","data":"` + data + `"`, 0},
		{"trailing JSON", `{"media_type":"image/png","data":"` + data + `"} {}`, 0},
		{"array payload", `{"media_type":"image/png","data":["` + data + `"]}`, 0},
		{"other array values", `[null,3,false,{"media_type":"image/png","data":"` + data + `"}]`, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(ImageDataURLView([]byte(tt.raw)))
			if n := strings.Count(got, "data:image/png;base64,"); n != tt.count {
				t.Fatalf("headers=%d want %d", n, tt.count)
			}
			if tt.count == 0 && got != tt.raw {
				t.Fatal("ineligible input changed")
			}
			if again := string(ImageDataURLView([]byte(got))); again != got {
				t.Fatal("not idempotent")
			}
			for _, span := range BareImagePayloadSpans(tt.raw) {
				if !strings.HasPrefix(tt.raw[span.Start-1:], `"`) || tt.raw[span.End] != '"' {
					t.Fatal("span lost source coordinates")
				}
			}
		})
	}
}

func TestImageCarrierGIFMagic(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString(append([]byte("GIF89a"), make([]byte, 26)...))
	raw := []byte(`{"media_type":"image/gif","data":"` + payload + `"}`)
	if got := string(ImageDataURLView(raw)); !strings.Contains(got, "data:image/gif;base64,") {
		t.Fatal("GIF signature was not nominated for complete container validation")
	}
}
