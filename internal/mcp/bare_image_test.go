// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testimage"
)

func TestMCPBareBase64Images(t *testing.T) {
	sc := testScanner(t)
	key := "AKIA" + "ABCDEFGHIJKLMNOP"
	clean := testimage.SmallPNG(t, "")
	for _, shape := range []string{"anthropic", "openai", "mcp"} {
		tests := []struct {
			name, body string
			clean      bool
		}{
			{"clean", testimage.Carrier(t, shape, "png", clean), true},
			{"decoded secret", testimage.Carrier(t, shape, "png", testimage.SmallPNG(t, key)), false},
			{"sibling", `{"image":` + testimage.Carrier(t, shape, "png", clean) + `,"key":"` + key + `"}`, false},
			{"invalid magic", testimage.Carrier(t, shape, "png", []byte(key)), false},
		}
		if shape != "openai" {
			tests = append(tests, struct {
				name, body string
				clean      bool
			}{"mismatch", testimage.Carrier(t, shape, "jpeg", clean), false})
		}
		for _, tt := range tests {
			t.Run(shape+"/"+tt.name, func(t *testing.T) {
				request := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"inspect","arguments":` + tt.body + `}}`)
				t.Run("input", func(t *testing.T) {
					if r := ScanRequest(context.Background(), request, sc, config.ActionBlock, config.ActionBlock); r.Clean != tt.clean {
						t.Fatalf("input clean=%v want %v: %+v", r.Clean, tt.clean, r)
					}
				})
				response := []byte(`{"jsonrpc":"2.0","id":1,"result":` + tt.body + `}`)
				t.Run("output", func(t *testing.T) {
					if r := ScanResponse(response, sc); r.Clean != tt.clean {
						t.Fatalf("output clean=%v want %v: %+v", r.Clean, tt.clean, r)
					}
				})
			})
		}
	}
}

func TestA2ABareBase64Images(t *testing.T) {
	sc := testA2AScanner(t)
	key := "AKIA" + "ABCDEFGHIJKLMNOP"
	for _, dirty := range []bool{false, true} {
		literal := ""
		if dirty {
			literal = key
		}
		carrier := testimage.Carrier(t, "anthropic", "png", testimage.SmallPNG(t, literal))
		body := []byte(`{"artifacts":[{"parts":[{"data":` + carrier + `}]}]}`)
		r := ScanA2AResponseBody(context.Background(), body, sc, enabledA2ACfg())
		if r.Clean == dirty {
			t.Fatalf("dirty=%v: %+v", dirty, r)
		}
	}
}

func TestA2ABareBase64ImageSiblingPath(t *testing.T) {
	carrier := testimage.Carrier(t, "mcp", "png", testimage.SmallPNG(t, ""))
	key := "AKIA" + "ABCDEFGHIJKLMNOP"
	body := []byte(`{"a":` + carrier + `,"a.data":"` + key + `"}`)
	if r := ScanA2AResponseBody(context.Background(), body, testA2AScanner(t), enabledA2ACfg()); r.Clean {
		t.Fatal("sibling credential lost behind an image with the same display path")
	}
}
