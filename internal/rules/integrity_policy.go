// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// StrictIntegrityError applies the startup policy shared by proxies and one-shot
// hooks. Strict mode refuses damaged installed bundles unless the operator
// explicitly permits degraded protection. Optional-store availability errors
// remain advisory. Reload consumers retain their existing rollback policy.
func StrictIntegrityError(cfg *config.Config, result *LoadResult) error {
	if result == nil || cfg.Mode != config.ModeStrict || cfg.Rules.AllowDegraded {
		return nil
	}
	integrityErrs := result.IntegrityErrors()
	if len(integrityErrs) == 0 {
		return nil
	}
	details := make([]string, 0, len(integrityErrs))
	for _, e := range integrityErrs {
		details = append(details, fmt.Sprintf("%s: %s", e.Name, e.Reason))
	}
	return fmt.Errorf("rule bundle integrity failure in strict mode: %s (verify or reinstall the bundle(s), or set rules.allow_degraded: true only as an emergency override)",
		strings.Join(details, "; "))
}
