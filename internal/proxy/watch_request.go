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
	"github.com/luckyPipewrench/pipelock/internal/mcp"
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

func watchUninspectedRequestRead(opts watchRequestOptions, layer, reason string) func(int) {
	if opts.Coverage != nil {
		opts.Coverage.layer, opts.Coverage.reason = layer, reason
		return nil
	}
	return func(n int) {
		watchObservation(opts.Logger, opts.Metrics, opts.Transport, layer, reason, "uninspected", int64(n), false)
	}
}

// watchRequestBody preserves admitted bytes while reusing the audit-mode body
// refusal contract for credentials and incomplete outbound inspection.
func watchRequestBody(ctx context.Context, r *http.Request, opts watchRequestOptions) bool {
	cfg, sc := opts.Config, opts.Scanner
	observe := func(layer, reason, action string, enforced bool) {
		watchObservation(opts.Logger, opts.Metrics, opts.Transport, layer, reason, action, 0, enforced)
	}
	if r.Body == nil || r.Body == http.NoBody {
		return false
	}
	source := r.Body
	if !cfg.RequestBodyScanning.Enabled {
		if !cfg.A2AScanning.Enabled || !mcp.IsA2ARequest(r.URL.Path, r.Header.Get("Content-Type")) {
			return false
		}
		raw, err := readForwardBodyForProtocolScan(source, strings.Join(r.Header.Values("Content-Encoding"), ","), cfg.RequestBodyScanning.MaxBodyBytes, r.Trailer)
		if err != nil {
			observe(scannerLabelA2A, "A2A request could not be completely inspected", config.ActionBlock, true)
			return true
		}
		r.Body = &watchRequestReplayBody{Reader: bytes.NewReader(raw), source: source}
		return watchA2ARequest(ctx, r, raw, opts).Core
	}
	limit := cfg.RequestBodyScanning.MaxBodyBytes
	if limit <= 0 {
		limit = config.Defaults().RequestBodyScanning.MaxBodyBytes
	}
	req := BodyScanRequest{
		AuditMode: !cfg.EnforceEnabled(),
		Body:      source, Trailer: r.Trailer, ContentEncoding: strings.Join(r.Header.Values("Content-Encoding"), ","),
		Scheme: r.URL.Scheme, Method: r.Method, ContentType: r.Header.Get("Content-Type"),
		MaxBytes: limit, Scanner: sc, Host: r.URL.Hostname(), Path: r.URL.Path,
		EntropyRoutePath: r.URL.EscapedPath(), Target: r.URL.String(), Suppress: cfg.Suppress,
		Action: cfg.RequestBodyScanning.Action, DisablePatterns: cfg.RequestBodyScanning.DisablePatterns,
		PatternActions: cfg.RequestBodyScanning.PatternActions, AudienceSurface: "body",
	}
	applyContentEntropyConfig(&req, cfg)
	applySigV4CredentialRouteConfig(&req, cfg)
	raw, result := scanRequestBody(ctx, req)
	if !result.Clean && isFailClosedBodyResult(result, raw) {
		layer := bodyFailureLayer(result, raw)
		if layer == "" {
			layer = scannerLabelBodyDLP
		}
		observe(layer, result.Reason, config.ActionBlock, true)
		return true
	}
	r.Body = &watchRequestReplayBody{Reader: bytes.NewReader(raw), source: source}
	a2a := watchA2ARequest(ctx, r, raw, opts)
	core := shouldHardBlockRequestDLP(result.DLPMatches, cfg) || a2a.Core
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
		enforced := shouldHardBlockRequestDLP([]scanner.TextDLPMatch{match}, cfg)
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
		if !redactedResult.Clean && isFailClosedBodyResult(redactedResult, rewritten) {
			observe(scannerLabelRedaction, redactedResult.Reason, config.ActionBlock, true)
			return true
		}
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
