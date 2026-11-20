// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"reflect"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestOutboundMatchWorkWholeView(t *testing.T) {
	patterns := []string{
		`(?s)alpha.*omega`,
		`(?mi)^second\b.*é$`,
		`\bstart\s+end\z`,
		`\Astart[^x]*end`,
		`(?m)^$`,
		`(?:a?)*[β\x{FFFD}]$`,
		`hello\Bworld`,
	}
	texts := []string{
		"alpha\nshared line\n",
		"alpha\nshared line\nomega",
		"other\nshared line\nomega",
		"next\nsecond line é",
		"next\nSECOND line É",
		"start\n\nend",
		"start\nendx",
		"start\nxend",
		"start\nend",
		"helloworld",
		"hello world",
		"anything\xff",
		"",
	}
	for _, limit := range []int{0, outboundMatchBytes} {
		work := &outboundMatchWork{}
		for _, expression := range patterns {
			re := regexp.MustCompile(expression)
			proof := work.regex(re)
			if proof == nil {
				t.Fatalf("regex is ineligible: %q", expression)
			}
			work.used = limit
			for _, text := range texts {
				if got, want := proof.provesEmpty(t.Context(), text), !re.MatchString(text); got != want {
					t.Fatalf("budget %d pattern %q text %q: empty=%v, want %v", limit, expression, text, got, want)
				}
			}
			work.used = 0
		}
	}
}

func TestOutboundMatchWorkCancellation(t *testing.T) {
	work := &outboundMatchWork{}
	proof := work.regex(regexp.MustCompile(`alpha.*omega`))
	if proof == nil {
		t.Fatal("missing proof")
	}
	text := strings.Repeat("ordinary line\n", 2000)
	if !proof.provesEmpty(t.Context(), text) {
		t.Fatal("clean view was inconclusive")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if proof.provesEmpty(ctx, text) {
		t.Fatal("canceled check was reported as complete")
	}
}

func TestOutboundMatchWorkScannerParity(t *testing.T) {
	cfg := config.Defaults()
	cfg.DLP.ScanEnv = false
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = config.ActionBlock
	cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{
		Name: "Cross-Line Fixture", Regex: `(?s)vendor_marker_begin.*vendor_marker_end`,
	}}
	scanner := MustNew(cfg)
	t.Cleanup(scanner.Close)
	ctx := WithOutboundInjectionWork(t.Context())
	filler := strings.Repeat("Ordinary status update.\n", 1000)
	for _, sample := range []struct {
		text  string
		clean bool
	}{
		{"vendor_marker_end\n" + filler + "vendor_marker_begin", true},
		{"vendor_marker_begin\n" + filler + "vendor_marker_end", false},
	} {
		want := scanner.ScanResponseOutbound(t.Context(), sample.text)
		got := scanner.ScanResponseOutbound(ctx, sample.text)
		if !reflect.DeepEqual(got, want) || got.Clean != sample.clean || got.Failed() {
			t.Fatalf("outbound result differs from ordinary matching: got %+v, want %+v", got, want)
		}
	}
}

func FuzzOutboundMatchWorkParity(f *testing.F) {
	f.Add(`(?m)^alpha\b.*omega$`, "another line\nalpha omega\n")
	f.Add(`(?s)alpha.*omega`, "alpha\nrepeat\nomega")
	f.Add(`\bfoo\B.*\z`, "fooβ\n")
	f.Add(`(?:a?)*[β\x{FFFD}]$`, "a\xff")
	f.Fuzz(func(t *testing.T, pattern, text string) {
		if len(pattern) > 128 || len(text) > 2048 {
			t.Skip()
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Skip()
		}
		// Keep pathological nested repeats out of the fuzz workload.
		tree, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil || len(tree.String()) > 256 {
			t.Skip()
		}
		work := &outboundMatchWork{}
		proof := work.regex(re)
		if proof == nil {
			t.Skip()
		}
		for _, sample := range []string{text, "prefix\n" + text, text + "\ntail", text + "\n" + text, text} {
			if got, want := proof.provesEmpty(t.Context(), sample), !re.MatchString(sample); got != want {
				t.Fatalf("pattern %q text %q: empty=%v, want %v", pattern, sample, got, want)
			}
		}
	})
}
