// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"net"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// failingDNSResolver fails every lookup, so infrastructure-error tests do not
// depend on how the host resolver treats reserved names.
type failingDNSResolver struct{}

func (failingDNSResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func newFailingDNSScanner(t *testing.T, cfg *config.Config) *scanner.Scanner {
	t.Helper()
	sc, err := scanner.NewWithOptions(cfg, scanner.Options{UpstreamResolver: failingDNSResolver{}})
	if err != nil {
		t.Fatalf("scanner: %v", err)
	}
	return sc
}
