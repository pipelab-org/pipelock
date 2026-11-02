// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/evidence/endproof"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
)

func assertFleetPartial(t testing.TB, err error) {
	t.Helper()
	if cliutil.ExitCodeOf(err) != endproof.ExitPrefix || err == nil || !strings.Contains(err.Error(), endproof.Prefix) {
		t.Fatalf("error = %v (code %d), want partial verdict exit %d", err, cliutil.ExitCodeOf(err), endproof.ExitPrefix)
	}
}

func TestVerifyReceiptCmd_FleetReportNeedsEndProof(t *testing.T) {
	cases := []struct {
		name    string
		version int
		dropped uint64
		reason  string
	}{
		{name: "v1 has no continuity field", version: fleetreceipt.SchemaVersionV1, reason: "Continuity:       unavailable"},
		{name: "v2 continuity unproven", version: fleetreceipt.SchemaVersionV2, reason: "cross_session_continuity_unproven"},
		{name: "reported drops", version: fleetreceipt.SchemaVersionV2, dropped: 1, reason: "Reported dropped actions: 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stmt := fleetReportStatementWithLimits(fleetreceipt.VerificationLevelL1, nil)
			if tc.version == fleetreceipt.SchemaVersionV2 {
				stmt.PredicateType = fleetreceipt.PredicateTypeV2
				stmt.Predicate.SchemaVersion = fleetreceipt.SchemaVersionV2
				stmt.Predicate.SourceBatches[0].Chain = &fleetreceipt.ChainIdentity{EntryVersion: 2, SessionID: "run-a"}
				stmt.Predicate.History = &fleetreceipt.History{
					Continuity: fleetreceipt.ContinuityUnproven,
					Sessions: []fleetreceipt.ObservedChain{{
						InstanceID:    "pl-1",
						Chain:         *stmt.Predicate.SourceBatches[0].Chain,
						FirstReceived: "2026-06-13T12:00:00Z",
						LastReceived:  "2026-06-13T12:00:00Z",
						SeqStart:      1,
						SeqEnd:        2,
					}},
					Gaps:      []fleetreceipt.SequenceGap{},
					Retention: fleetreceipt.RetentionCoverage{HistoryUnknown: true},
				}
			}
			if tc.dropped > 0 {
				stmt.Predicate.SourceBatches[0].DroppedCount = tc.dropped
				stmt.Predicate.Completeness.DroppedObservedActions = tc.dropped
			}
			pub, path := writeFleetReportStatement(t, stmt)

			cmd := VerifyReceiptCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetArgs([]string{path, "--fleet-report", "--key", hex.EncodeToString(pub)})
			err := cmd.Execute()
			if cliutil.ExitCodeOf(err) != endproof.ExitPrefix {
				t.Fatalf("Execute() error = %v (code %d), want exit %d; output:\n%s", err, cliutil.ExitCodeOf(err), endproof.ExitPrefix, out.String())
			}
			if !strings.Contains(out.String(), endproof.Prefix) {
				t.Fatalf("missing partial end-proof status in output: %s", out.String())
			}
			if strings.Contains(out.String(), "FLEET RECEIPT OK:") {
				t.Fatalf("partial report printed success banner: %s", out.String())
			}
			if !strings.Contains(out.String(), tc.reason) {
				t.Fatalf("partial report did not name reason %q: %s", tc.reason, out.String())
			}
		})
	}
}

func TestVerifyReceiptCmd_FleetReportAllowPrefix(t *testing.T) {
	pub, path := writeFleetReportStatement(t, fleetReportStatementWithLimits(fleetreceipt.VerificationLevelL1, nil))
	key := hex.EncodeToString(pub)

	run := func(args ...string) (string, error) {
		t.Helper()
		cmd := VerifyReceiptCmd()
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(legacyReceiptPrefixArgs(cmd, args))
		err := cmd.Execute()
		return out.String(), err
	}

	defaultOut, defaultErr := run(path, "--fleet-report", "--key", key)
	assertFleetPartial(t, defaultErr)
	if !strings.Contains(defaultOut, "FLEET RECEIPT "+endproof.Prefix+":") || strings.Contains(defaultOut, "FLEET RECEIPT OK:") {
		t.Fatalf("default fleet report output must retain the prefix verdict, got:\n%s", defaultOut)
	}

	allowedOut, allowedErr := run(path, "--fleet-report", "--key", key, "--allow-prefix")
	if allowedErr != nil {
		t.Fatalf("--allow-prefix error = %v (code %d), want success; output:\n%s", allowedErr, cliutil.ExitCodeOf(allowedErr), allowedOut)
	}
	if !strings.Contains(allowedOut, "FLEET RECEIPT "+endproof.Prefix+":") || strings.Contains(allowedOut, "FLEET RECEIPT OK:") {
		t.Fatalf("--allow-prefix must keep the partial verdict, got:\n%s", allowedOut)
	}

	_, pinErr := run(path, "--fleet-report", "--key", key, "--expect-seq", "1")
	if pinErr == nil || cliutil.ExitCodeOf(pinErr) != cliutil.ExitConfig {
		t.Fatalf("fleet --expect-seq error = %v (code %d), want usage refusal", pinErr, cliutil.ExitCodeOf(pinErr))
	}

	_, unpinnedErr := run(path, "--fleet-report", "--allow-prefix")
	if unpinnedErr == nil || cliutil.ExitCodeOf(unpinnedErr) != 1 {
		t.Fatalf("fleet --allow-prefix without --key error = %v (code %d), want unpinned refusal", unpinnedErr, cliutil.ExitCodeOf(unpinnedErr))
	}

	_, wrongKeyErr := run(path, "--fleet-report", "--key", strings.Repeat("0", len(key)), "--allow-prefix")
	if wrongKeyErr == nil || cliutil.ExitCodeOf(wrongKeyErr) != 1 {
		t.Fatalf("fleet --allow-prefix with wrong key error = %v (code %d), want invalid-signature refusal", wrongKeyErr, cliutil.ExitCodeOf(wrongKeyErr))
	}
}
