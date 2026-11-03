// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"slices"
	"testing"
)

func TestSensitiveHeaderDefaultsAgree(t *testing.T) {
	loaded, err := LoadBytes([]byte("version: 1\nmode: balanced\n"))
	if err != nil {
		t.Fatal(err)
	}
	defaults := Defaults().RequestBodyScanning.SensitiveHeaders
	if !slices.Equal(defaults, loaded.RequestBodyScanning.SensitiveHeaders) {
		t.Fatalf("constructed defaults %v differ from YAML defaults %v", defaults, loaded.RequestBodyScanning.SensitiveHeaders)
	}
	if !slices.Contains(defaults, "Api-Key") {
		t.Fatal("documented Pinecone header is not scanned")
	}
}
