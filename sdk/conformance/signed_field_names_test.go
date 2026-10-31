// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestSignedFieldNamesParity(t *testing.T) {
	raw, err := os.ReadFile("testdata/signed-field-names.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			File  string `json:"file"`
			Valid bool   `json:"valid"`
			Error string `json:"error"`
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := os.ReadFile("testdata/test-key.json")
	if err != nil {
		t.Fatal(err)
	}
	var key struct {
		Public string `json:"public_key_hex"`
	}
	if err := json.Unmarshal(keyBytes, &key); err != nil {
		t.Fatal(err)
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.File, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", tc.File))
			if err != nil {
				t.Fatal(err)
			}
			r, err := receipt.Unmarshal(data)
			if err == nil {
				err = receipt.VerifyWithKey(r, key.Public)
			}
			if (err == nil) != tc.Valid {
				t.Fatalf("valid=%v: %v", tc.Valid, err)
			}
			if !tc.Valid {
				if tc.Error == "" {
					t.Fatal("negative case names no expected error")
				}
				if !strings.Contains(err.Error(), tc.Error) {
					t.Fatalf("error %q lacks %q", err, tc.Error)
				}
			}
		})
	}
}
