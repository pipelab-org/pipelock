// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestWatchMetadataDialReload(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{"metadata.vendor.example": {"169.254.169.254"}}
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	for _, addr := range []string{"169.254.169.254:80", "metadata.vendor.example:80"} {
		var mode atomic.Bool
		calls, observations := 0, 0
		sentinel := errors.New("fake dial failure")
		dial := newWatchMetadataSafeDialContext(func() *scanner.Scanner { return sc }, func(context.Context, string, string) (net.Conn, error) { calls++; return nil, sentinel }, mode.Load, func(string) { observations++ })
		for _, watch := range []bool{false, true, true, false, false} {
			mode.Store(watch)
			beforeCalls, beforeObservations := calls, observations
			_, err := dial(t.Context(), "tcp", addr)
			if watch {
				if !errors.Is(err, sentinel) || calls != beforeCalls+1 || observations != beforeObservations+1 {
					t.Fatalf("watch dial=%d observed=%d err=%v", calls, observations, err)
				}
			} else {
				var refused *MetadataDialBlockError
				if !errors.As(err, &refused) || calls != beforeCalls || observations != beforeObservations {
					t.Fatalf("enforced dial escaped: %v", err)
				}
			}
		}
	}
}
