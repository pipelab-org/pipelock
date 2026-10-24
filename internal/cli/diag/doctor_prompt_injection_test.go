// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDoctorPromptInjectionDetection(t *testing.T) {
	for _, mode := range []string{config.ActionBlock, config.ActionWarn, config.ActionAllow} {
		t.Run(mode, func(t *testing.T) {
			cfg := config.Defaults()
			enabled := mode != config.ActionAllow
			cfg.PromptInjectionDetection = &config.PromptInjectionDetection{Enabled: &enabled}
			if mode == config.ActionWarn {
				cfg.PromptInjectionDetection.Action = mode
			}
			check := checkDoctorPromptInjectionDetection(cfg)
			if (check.Status == doctorStatusWarn) != (mode != config.ActionBlock) {
				t.Fatalf("check: %+v", check)
			}
			if mode != config.ActionBlock && !strings.Contains(check.Detail, "DLP and destination controls") {
				t.Fatal(check.Detail)
			}
			if mode == config.ActionAllow && !strings.Contains(check.Detail, "no prompt-injection protection remains") {
				t.Fatal(check.Detail)
			}
		})
	}
}
