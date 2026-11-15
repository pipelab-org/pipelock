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
			bindings = append(bindings, sp.Surface+"="+sp.Binding())
		}
		check.Detail += " Checker bindings: " + strings.Join(bindings, ", ") + "."
		for _, name := range policy.CheckerNames() {
			cc, _ := policy.Checker(name)
			offHost := "stays on this machine"
			if cc.SendsOffHost() {
				offHost = "sends checked content off this machine (consented)"
			}
			check.Detail += fmt.Sprintf(" Checker %s: type %s, endpoint %s, %s.", name, cc.Type, cc.EndpointHost(), offHost)
		}
	}
	return check
}
