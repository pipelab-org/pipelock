// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	auditpacket "github.com/luckyPipewrench/pipelock/sdk/audit-packet"
)

func TestAuditPacketTrustAndFailureLabels(t *testing.T) {
	run := newCompletenessFixture(t)
	fix := &fixture{keyHex: run.keyHex, receipts: []receipt.Receipt{run.open("run-labels", "open-labels"), run.close("run-labels", "open-labels")}}
	for _, tc := range []struct {
		name    string
		flags   []string
		mutate  func(*auditpacket.Packet)
		status  string
		code    int
		trusted bool
	}{
		{name: "pinned positive", flags: []string{"--key", fix.keyHex}, status: "CHAIN VALID", trusted: true},
		{name: "structural only", flags: []string{"--no-trust-required"}, status: "CHAIN VALID"},
		{name: "offline", flags: []string{"--offline"}, status: "TRUST UNVERIFIED", code: 1},
		{name: "external anchor absent", status: "TRUST UNVERIFIED", code: 1},
		{name: "schema", flags: []string{"--key", fix.keyHex}, mutate: func(p *auditpacket.Packet) { p.SchemaVersion = "invalid" }, status: "PACKET INVALID", code: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fix.writePacketDir(t, dir, tc.mutate)
			report, code := auditPacketJSON(t, append(tc.flags, dir)...)
			if code != tc.code || report.Status != tc.status || report.Trusted != tc.trusted || report.Valid != (tc.code == 0) {
				t.Fatalf("exit=%d status=%q trusted=%v valid=%v; want exit=%d status=%q trusted=%v", code, report.Status, report.Trusted, report.Valid, tc.code, tc.status, tc.trusted)
			}
		})
	}
}
