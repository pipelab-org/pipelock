// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestCompiledEntropyExceptionsExpire(t *testing.T) {
	now := time.Date(2026, time.October, 19, 23, 59, 59, 0, time.UTC)
	cfg := config.Defaults()
	cfg.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{{Host: "api.vendor.example", PathPrefix: "/files/", Expires: now.Format(time.DateOnly)}}
	cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{{Host: "api.vendor.example", Path: "/files/download", Param: "id", Expires: now.Format(time.DateOnly)}}
	s, err := NewWithOptions(cfg, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	u, err := url.Parse("https://api.vendor.example/files/download?id=value")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		match func() bool
	}{
		{"path", func() bool { return s.isPathEntropyExcluded(u) }},
		{"query", func() bool { return s.isQueryEntropyParamExcluded(u, "id") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.match() {
				t.Fatal("exception inactive during its UTC expiry day")
			}
			now = now.Add(time.Second)
			if tc.match() {
				t.Error("compiled exception still active after its UTC expiry day")
			}
			now = now.Add(-time.Second)
		})
	}
}

func TestScannerEntropyProtectionResumesAfterExpiry(t *testing.T) {
	var opaque strings.Builder
	for _, bounds := range [][2]rune{{'a', 'z'}, {'A', 'Z'}, {'0', '9'}} {
		for r := bounds[0]; r <= bounds[1]; r++ {
			opaque.WriteRune(r)
		}
	}
	for _, family := range []string{"path", "query"} {
		t.Run(family, func(t *testing.T) {
			now := time.Date(2026, time.October, 19, 23, 59, 59, 0, time.UTC)
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
			cfg.FetchProxy.Monitoring.MaxDataPerMinute = 0
			cfg.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{{Host: "api.vendor.example", PathPrefix: "/files/", Expires: now.Format(time.DateOnly)}}
			cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{{Host: "api.vendor.example", Path: "/files", Param: "id", Expires: now.Format(time.DateOnly)}}
			s, err := NewWithOptions(cfg, Options{Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(s.Close)
			target := "https://api.vendor.example/files/" + opaque.String()
			if family == "query" {
				target = "https://api.vendor.example/files?id=" + opaque.String()
			}
			if got := s.Scan(context.Background(), target); !got.Allowed {
				t.Fatalf("active exception did not admit control: %+v", got)
			}
			now = now.Add(time.Second)
			for range 2 {
				if got := s.Scan(context.Background(), target); got.Allowed || got.Scanner != ScannerEntropy {
					t.Fatalf("expired exception did not restore entropy protection: %+v", got)
				}
			}
		})
	}
}

func TestCompiledEntropyExceptionExpiryForms(t *testing.T) {
	for _, expires := range []string{"", "not-a-date", "2026-02-30"} {
		t.Run(expires, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{{Host: "api.vendor.example", PathPrefix: "/files/", Expires: expires}}
			cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{{Host: "api.vendor.example", Path: "/files/download", Param: "id", Expires: expires}}
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(s.Close)
			u, err := url.Parse("https://api.vendor.example/files/download?id=value")
			if err != nil {
				t.Fatal(err)
			}
			want := expires == ""
			if s.isPathEntropyExcluded(u) != want || s.isQueryEntropyParamExcluded(u, "id") != want {
				t.Fatal("optional and malformed expiry did not honor permanent/fail-closed semantics")
			}
		})
	}
}

func TestScannerLapsedPathDefaults(t *testing.T) {
	for _, optOut := range []bool{false, true} {
		t.Run(map[bool]string{false: "last entry lapses", true: "explicit empty"}[optOut], func(t *testing.T) {
			cfg := config.Defaults()
			cfg.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{{Host: "api.vendor.example", PathPrefix: "/files/", Expires: time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)}}
			if optOut {
				cfg.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{}
			}
			if _, err := cfg.LapseExpiredScannerExceptions(time.Now()); err != nil {
				t.Fatal(err)
			}
			cfg = cfg.Clone()
			cfg.ApplyDefaults()
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(s.Close)
			shipped := config.ShippedPathEntropyExclusions()[0]
			u := &url.URL{Scheme: config.QueryEntropyParamDefaultScheme, Host: shipped.Host, Path: shipped.PathPrefix + "resource"}
			if s.isPathEntropyExcluded(u) == optOut {
				t.Fatal("lapse lost shipped defaults or resurrected an opt-out")
			}
			u.Host, u.Path = "api.vendor.example", "/files/resource"
			if s.isPathEntropyExcluded(u) {
				t.Fatal("expired operator entry remained exempt")
			}
		})
	}
}
