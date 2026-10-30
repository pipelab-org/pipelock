// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package checker_test

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
)

func TestConformance(t *testing.T) {
	checkertest.Run(t, func(t *testing.T, endpoint string) checker.Checker {
		t.Helper()
		client, err := checker.NewClient(checker.Options{Endpoint: endpoint, AllowLoopbackHTTP: true})
		if err != nil {
			t.Fatal(err)
		}
		return client
	})
}
