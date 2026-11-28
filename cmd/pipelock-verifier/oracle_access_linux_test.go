// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestObservedV3Access(t *testing.T) {
	testreceipt.RunObservedAccessOracle(t, testreceipt.AccessOracle{
		Root:     newRootCmd(),
		MustOpen: []string{"chain"},
		Probes:   receiptCommandProbes(),
		Invoke: func(t *testing.T, args []string, out io.Writer, _ string, _ bool) int {
			t.Helper()
			return execute(args, out, out)
		},
	})
}
