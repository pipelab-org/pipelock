// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// errAfterCalls is live for the first n Err calls and canceled after that.
// It lets a merged scan finish its first pass and then hit a deadline.
type errAfterCalls struct {
	context.Context
	left int
}

func (c *errAfterCalls) Err() error {
	if c.left <= 0 {
		return context.Canceled
	}
	c.left--
	return nil
}

func (c *errAfterCalls) Done() <-chan struct{} {
	if c.left <= 0 {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return c.Context.Done()
}

func (c *errAfterCalls) Deadline() (time.Time, bool) {
	if c.left <= 0 {
		return time.Time{}, true
	}
	return c.Context.Deadline()
}

func TestScanTextForDLPReportsIncomplete(t *testing.T) {
	sc := MustNew(config.Defaults())
	t.Cleanup(sc.Close)
	text := "key " + "AKIA" + "IOSFODNN7EXAMPLE"

	if got := sc.ScanTextForDLP(context.Background(), text); got.Incomplete || got.Clean {
		t.Fatalf("live context: want a complete dirty result, got %+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for name, scan := range map[string]func(context.Context, string) TextDLPResult{
		"outbound": sc.ScanTextForDLP,
		"quiet":    sc.ScanTextForDLPQuiet,
		"inbound":  sc.ScanTextForDLPInbound,
		"body":     sc.ScanRequestBodyTextForDLP,
		"body-parts": func(ctx context.Context, text string) TextDLPResult {
			return sc.ScanRequestBodyTextPartsForDLP(ctx, []string{text}, " ")
		},
		"body-card-parts": func(ctx context.Context, text string) TextDLPResult {
			return sc.ScanRequestBodyTextPartsWithCardViews(ctx, []string{text}, []string{text}, " ")
		},

		"card": func(ctx context.Context, text string) TextDLPResult {
			return sc.ScanTextForDLPWithCardView(ctx, text, text)
		},
		"quiet-card": func(ctx context.Context, text string) TextDLPResult {
			return sc.ScanTextForDLPQuietWithCardView(ctx, text, text)
		},
		"inbound-card": func(ctx context.Context, text string) TextDLPResult {
			return sc.ScanTextForDLPInboundWithCardView(ctx, text, text)
		},
		"typed-card": func(ctx context.Context, text string) TextDLPResult {
			return sc.ScanTextForDLPWithTypedCardView(ctx, text, text)
		},
		"quiet-typed-card": func(ctx context.Context, text string) TextDLPResult {
			return sc.ScanTextForDLPQuietWithTypedCardView(ctx, text, text)
		},
		"inbound-typed-card": func(ctx context.Context, text string) TextDLPResult {
			return sc.ScanTextForDLPInboundWithTypedCardView(ctx, text, text)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if noMatch := scan(ctx, "ordinary content"); noMatch.Clean || !errors.Is(noMatch.Err(), ErrTextDLPIncomplete) || len(noMatch.Matches) != 0 {
				t.Fatalf("incomplete no-match scan = %+v", noMatch)
			}
			got := scan(ctx, text)
			if !got.Incomplete {
				t.Fatalf("ended context: want Incomplete, got %+v", got)
			}
			if got.Clean || len(got.Matches) == 0 {
				t.Fatalf("an incomplete result must keep the findings it has: %+v", got)
			}
		})
	}
}

// The first pass still sees a live context. A deadline during a later pass
// has to survive the merge, or the caller treats that scan as verified.
func TestScanTextDLPViewsKeepsLaterDeadline(t *testing.T) {
	sc := MustNew(config.Defaults())
	t.Cleanup(sc.Close)
	text := "key " + "AKIA" + "IOSFODNN7EXAMPLE"
	live := sc.ScanTextForDLP(context.Background(), text)
	if live.Incomplete || live.Clean {
		t.Fatalf("live context: want a complete dirty result, got %+v", live)
	}
	got := sc.ScanTextForDLP(&errAfterCalls{Context: context.Background(), left: 1}, text)
	if !got.Incomplete {
		t.Fatal("deadline after the first pass was dropped")
	}
	if got.Clean || len(got.Matches) == 0 {
		t.Fatalf("incomplete merge dropped findings: %+v", got)
	}
}

func TestTextDLPResultIncompleteError(t *testing.T) {
	for _, incomplete := range []bool{false, true} {
		for _, matches := range [][]TextDLPMatch{nil, {{PatternName: "fixture"}}} {
			result := TextDLPResult{Clean: !incomplete && len(matches) == 0, Incomplete: incomplete, Matches: matches}
			if got := errors.Is(result.Err(), ErrTextDLPIncomplete); got != incomplete {
				t.Fatalf("result %+v: incomplete error = %v", result, result.Err())
			}
		}
	}
}
