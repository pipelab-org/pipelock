// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type denyDestinationResolver struct{ calls int }

func (r *denyDestinationResolver) LookupHost(context.Context, string) ([]string, error) {
	r.calls++
	return nil, errors.New("unplanned DNS fallback")
}

func TestDestinationAliasesDoNotUseDNSFallback(t *testing.T) {
	d := newDestinationPlan(50, []string{"10001", "10002", "10003", "10004", "10005", "10006", "10007", "10008"})
	cfg := config.Defaults()
	cfg.DNS.HostOverrides = d.overrides()
	cfg.SSRF.IPAllowlist = []string{"127.0.0.1/32"}
	fallback := &denyDestinationResolver{}
	scan, err := scanner.NewWithOptions(cfg, scanner.Options{UpstreamResolver: fallback})
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range d.Aliases {
		result := scan.Scan(context.Background(), "http://"+net.JoinHostPort(alias, d.Ports[0])+"/ok")
		if !result.Allowed {
			t.Fatalf("SSRF path rejected pinned alias: %+v", result)
		}
		ips, err := scan.HostResolver().LookupHost(context.Background(), alias)
		if err != nil || len(ips) != 1 || ips[0] != "127.0.0.1" {
			t.Fatalf("dial resolver: %v %v", ips, err)
		}
	}
	if fallback.calls != 0 {
		t.Fatalf("known aliases used fallback %d times", fallback.calls)
	}
	if _, err := scan.HostResolver().LookupHost(context.Background(), "unknown.load.example"); err == nil || fallback.calls != 1 {
		t.Fatal("negative control did not call failing fallback")
	}
}

func TestDestinationPoolCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s, err := startSink(ctx, newWorkload(1, 0, 4), destinationsPerRequest); err == nil {
		s.close()
		t.Fatal("canceled pool started")
	}
}
