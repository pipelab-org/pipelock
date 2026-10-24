// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/rules"
)

func reportBundleLoadResult(stderr io.Writer, cfg *config.Config, result *rules.LoadResult) error {
	for _, e := range result.Errors {
		_, _ = fmt.Fprintf(stderr, "pipelock: warning: bundle %s: %s\n", e.Name, e.Reason)
	}
	for _, w := range result.Warnings {
		_, _ = fmt.Fprintf(stderr, "pipelock: warning: %s\n", w)
	}
	return rules.StrictIntegrityError(cfg, result)
}
