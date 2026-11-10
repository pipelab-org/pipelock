// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"context"
	"net"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestShellHookMetadataOrLinkLocal(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{ip: "169.254.169.254", want: true},
		{ip: "100.100.100.200", want: true},
		{ip: "fd00:ec2::254", want: true},
		{ip: "168.63.129.16", want: true},
		{ip: "169.254.10.10", want: true},
		{ip: "169.254.1.10", want: true},
		{ip: "fe80::1", want: true},
		{ip: "224.0.0.1", want: true},
		{ip: "ff02::1", want: true},
		{ip: "127.0.0.1", want: false},
		{ip: "::1", want: false},
		{ip: "10.0.0.5", want: false},
		{ip: "172.16.0.1", want: false},
		{ip: "192.168.1.10", want: false},
		{ip: "100.64.0.10", want: false},
		{ip: "fd00::1", want: false},
		{ip: "0.0.0.0", want: false},
		{ip: "::", want: false},
		{ip: "203.0.113.10", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("parse %s", tc.ip)
			}
			if got := shellHookMetadataOrLinkLocal(ip); got != tc.want {
				t.Fatalf("shellHookMetadataOrLinkLocal(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
	if shellHookMetadataOrLinkLocal(nil) {
		t.Fatal("nil IP is not metadata or link-local")
	}
}

func TestDecide_ShellLiteralFloorDeniesInAuditMode(t *testing.T) {
	cfg, sc := shellDestinationScanner(t, nil)
	enforce := false
	cfg.Enforce = &enforce
	cases := []struct {
		name    string
		command string
		want    Outcome
		scanner string
	}{
		{name: "metadata literal", command: "curl http://169.254.169.254/latest/meta-data/", want: Deny, scanner: scanner.ScannerSSRFMetadata},
		{name: "link local literal", command: "curl http://169.254.10.10/", want: Deny, scanner: scanner.ScannerSSRF},
		{name: "localhost name", command: "curl http://localhost:3000/", want: Allow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision := Decide(context.Background(), cfg, sc, nil, Action{
				Source: "claude-code",
				Kind:   EventShellExecution,
				Shell:  &ShellPayload{Command: tc.command, CWD: "/tmp"},
			})
			if decision.Outcome != tc.want {
				t.Fatalf("outcome = %s, want %s; evidence = %+v", decision.Outcome, tc.want, decision.Evidence)
			}
			if tc.scanner != "" && !evidenceHasScanner(decision.Evidence, tc.scanner) {
				t.Fatalf("evidence = %+v, want %s", decision.Evidence, tc.scanner)
			}
		})
	}
}
