// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestRedactConfigKillSwitchTokenFile(t *testing.T) {
	const path = "/run/credentials/pipelock.service/admin-token"
	for _, tt := range []struct {
		file string
		want bool
	}{{file: path, want: true}, {file: "", want: false}} {
		cfg := config.Defaults()
		cfg.KillSwitch.APITokenFile = tt.file
		ks, ok := redactConfig(cfg)["kill_switch"].(map[string]any)
		if !ok || ks["api_token_file_configured"] != tt.want {
			t.Fatalf("api_token_file_configured = %v, want %v", ks["api_token_file_configured"], tt.want)
		}
		enc, err := json.Marshal(ks)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(enc), "admin-token") {
			t.Fatalf("support summary carries the token file path: %s", enc)
		}
	}
}
