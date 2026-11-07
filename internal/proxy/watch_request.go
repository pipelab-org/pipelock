// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// watchObservation uses the audit and metric channels without manufacturing a
// blocked request. Reasons must be diagnostics, never matched payload bytes.
func watchObservation(logger *audit.Logger, m *metrics.Metrics, transport, layer, reason, action string, count int64, enforced bool) {
	logger.LogWatchOnly(transport, layer, reason, action, count, enforced)
	m.RecordWatchOnly(transport, layer, action, count)
}

type watchRequestCoverage struct{ layer, reason string }

type watchRequestOptions struct {
	Coverage  *watchRequestCoverage
	Config    *config.Config
	Scanner   *scanner.Scanner
	Logger    *audit.Logger
	Metrics   *metrics.Metrics
	Transport string
}

// watchRequestReplayBody keeps ownership of the source while replaying the bounded
// inspection prefix. The remaining stream is never buffered without a bound.
type watchRequestReplayBody struct {
	io.Reader
	source io.Closer
	onRead func(int)
}

func (b *watchRequestReplayBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if n > 0 && b.onRead != nil {
		b.onRead(n)
	}
	return n, err
}

func (b *watchRequestReplayBody) Close() error { return b.source.Close() }

// watchRequestBody reuses the request scanner on a copy. A limit or failed
// decoder never destroys bytes needed to continue the actual request. The
// returned bool is reserved for a detected core credential, not a policy block.
func watchUninspectedRequestRead(opts watchRequestOptions, layer, reason string) func(int) {
	if opts.Coverage != nil {
		opts.Coverage.layer, opts.Coverage.reason = layer, reason
		return nil
	}
	return func(n int) {
		watchObservation(opts.Logger, opts.Metrics, opts.Transport, layer, reason, "uninspected", int64(n), false)
	}
}

func watchRequestBody(ctx context.Context, r *http.Request, opts watchRequestOptions) bool {
	cfg, sc := opts.Config, opts.Scanner
	observe := func(layer, reason, action string, enforced bool) {
		watchObservation(opts.Logger, opts.Metrics, opts.Transport, layer, reason, action, 0, enforced)
	}
	if r.Body == nil || r.Body == http.NoBody {
		return false
	}
	source := r.Body
	limit := cfg.RequestBodyScanning.MaxBodyBytes
	if limit <= 0 {
		limit = config.Defaults().RequestBodyScanning.MaxBodyBytes
	}
	if hasNonIdentityEncoding(strings.Join(r.Header.Values("Content-Encoding"), ",")) {
		observe(scannerLabelBodyDLP, "encoded request body", "uninspected", false)
		r.Body = &watchRequestReplayBody{Reader: source, source: source, onRead: watchUninspectedRequestRead(opts, scannerLabelBodyDLP, "encoded request body")}
		return false
	}
	raw, readErr := io.ReadAll(io.LimitReader(source, int64(limit)+1))
	r.Body = &watchRequestReplayBody{Reader: io.MultiReader(bytes.NewReader(raw), source), source: source}
	if readErr != nil || len(raw) > limit {
		reason := "request body exceeds inspection limit"
		if readErr != nil {
			reason = "request body could not be completely read"
		}
		observe(scannerLabelBodyDLP, reason, "uninspected", false)
		r.Body = &watchRequestReplayBody{Reader: io.MultiReader(bytes.NewReader(raw), source), source: source, onRead: watchUninspectedRequestRead(opts, scannerLabelBodyDLP, reason)}
		// The bounded prefix can still contain a definite credential. This cannot
		// attest to the unread tail; all forwarded bytes remain marked uninspected.
		matches := scanBodyTextsForDLP(ctx, sc, []string{string(raw)}, r.URL.String(), cfg.Suppress, bodyDLPDisabledSet(cfg.RequestBodyScanning.DisablePatterns), false, nil)
		for _, match := range matches {
			if !match.Warn && scanner.IsCoreCriticalMatch(match) {
				observe(scannerLabelBodyDLP, match.PatternName, config.ActionBlock, true)
				return true
			}
		}
		return false
	}
	req := BodyScanRequest{
		Body: bytes.NewReader(raw), Trailer: r.Trailer,
		Scheme: r.URL.Scheme, Method: r.Method, ContentType: r.Header.Get("Content-Type"),
		MaxBytes: limit, Scanner: sc, Host: r.URL.Hostname(), Path: r.URL.Path,
		EntropyRoutePath: r.URL.EscapedPath(), Target: r.URL.String(), Suppress: cfg.Suppress,
		Action: cfg.RequestBodyScanning.Action, DisablePatterns: cfg.RequestBodyScanning.DisablePatterns,
		PatternActions: cfg.RequestBodyScanning.PatternActions, AudienceSurface: "body",
	}
	applyContentEntropyConfig(&req, cfg)
	applySigV4CredentialRouteConfig(&req, cfg)
	_, result := scanRequestBody(ctx, req)
	a2a := watchA2ARequest(ctx, r, raw, opts)
	core := containsCoreFloorMatch(result.DLPMatches) || a2a.Core
	if !result.Clean && len(result.DLPMatches) == 0 {
		// A parser refusal must not hide a credential that is already visible in
		// the original representation that watch-only is about to release.
		for _, match := range scanBodyTextsForDLP(ctx, sc, []string{string(raw)}, r.URL.String(), cfg.Suppress, bodyDLPDisabledSet(cfg.RequestBodyScanning.DisablePatterns), false, nil) {
			if !match.Warn && scanner.IsCoreCriticalMatch(match) {
				core = true
				observe(scannerLabelBodyDLP, match.PatternName, config.ActionBlock, true)
			}
		}
	}

	for _, match := range result.DLPMatches {
		action := result.Action
		if action == "" {
			action = config.ActionBlock
		}
		enforced := !match.Warn && scanner.IsCoreCriticalMatch(match)
		if enforced {
			action = config.ActionBlock
		}
		observe(scannerLabelBodyDLP, match.PatternName, action, enforced)
	}
	if len(result.InjectionMatches) > 0 {
		observe(scannerLabelBodyPromptInjection, "request injection finding", result.Action, false)
	}
	if result.EntropyFinding != nil {
		observe(scannerLabelBodyEntropy, result.Reason, result.Action, false)
	}
	if !result.Clean && len(result.DLPMatches) == 0 && len(result.InjectionMatches) == 0 && result.EntropyFinding == nil {
		observe(scannerLabelBodyDLP, result.Reason, "uninspected", false)
		r.Body = &watchRequestReplayBody{Reader: bytes.NewReader(raw), source: source, onRead: watchUninspectedRequestRead(opts, scannerLabelBodyDLP, result.Reason)}
	}
	// Redaction operates on a separate copy solely to observe its decision.
	// The credential floor above saw the original, never the redacted body.
	if cfg.Redaction.Enabled {
		redaction := currentRedactionRuntimeForConfig(cfg, nil)
		applyBodyScanRedaction(&req, redaction)
		req.Body = bytes.NewReader(raw)
		rewritten, redactedResult := scanRequestBody(ctx, req)
		if !bytes.Equal(rewritten, raw) || !redactedResult.Clean {
			observe(scannerLabelRedaction, "configured request redaction", config.ActionStrip, false)
		}
	}
	if a2a.Uninspected != "" {
		observe(scannerLabelA2A, a2a.Uninspected, "uninspected", false)
		r.Body = &watchRequestReplayBody{Reader: bytes.NewReader(raw), source: source, onRead: watchUninspectedRequestRead(opts, scannerLabelA2A, a2a.Uninspected)}
	}
	return core
}
