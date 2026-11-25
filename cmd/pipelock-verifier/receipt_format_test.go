// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestLegacyVerifierCommandsRefuseV3(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, dir, path string) {
		cases := []struct {
			command, reader string
			err             error
		}{
			{"completeness", "the completeness verifier", runCompleteness(io.Discard, io.Discard, dir, completenessOptions{})},
			{"replay", "the replay verifier", runReplay(io.Discard, io.Discard, path, replayOptions{})},
			{"receipt", "the standalone receipt reader", runReceipt(io.Discard, io.Discard, path, receiptOptions{})},
			{"receipt --recheck-source", "the receipt recheck verifier", runReceipt(io.Discard, io.Discard, path, receiptOptions{recheckSource: "example"})},
			{"independent", "the independent anchor verifier", runIndependent(io.Discard, io.Discard, dir, independentOptions{})},
			{"audit-packet", "the audit packet verifier", runAuditPacket(io.Discard, io.Discard, path, auditPacketOptions{})},
		}
		for _, tc := range cases {
			testreceipt.RequiresV3Refusal(t, tc.err, tc.command, tc.reader)
			if cliutil.ExitCodeOf(tc.err) != cliutil.ExitConfig {
				t.Errorf("%s exit is %d", tc.command, cliutil.ExitCodeOf(tc.err))
			}
		}
	})
}
