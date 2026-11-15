// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"fmt"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func checkDoctorPromptInjectionDetection(cfg *config.Config) doctorReportCheck {
	check := doctorReportCheck{
		Name: "prompt_injection_detection", Surface: doctorSurfaceConfig, Status: doctorStatusOK,
		Detail: "Regex prompt-injection wording detection uses the existing per-surface enforcement policy, including core wording rules.",
	}
	if notice := cfg.PromptInjectionNotice(); notice != "" {
		check.Status = doctorStatusWarn
		check.Configured = true
		check.Detail = notice
		check.Next = "restore prompt_injection_detection.enabled=true and action=block, and remove reduced prompt_injection_detection.surfaces entries, to restore the existing wording enforcement policy"
	}
	if policy := cfg.InjectionPolicy(); policy.Selected() {
		check.Configured = true
		bindings := make([]string, 0, 2)
		for _, sp := range policy.Surfaces() {
			bindings = append(bindings, fmt.Sprintf("%s=%s/%s (%s)", sp.Surface, sp.Checker, sp.Mode, sp.Source))
		}
		check.Detail += " Checker bindings: " + strings.Join(bindings, ", ") + "."
	}
	return check
}
