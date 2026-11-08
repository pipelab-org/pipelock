// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/shield"
)

var errWatchResponseCoreFloor = errors.New("enforced in watch-only: core credential floor")

type watchResponseOptions struct {
	ExternalByteAccounting bool
	A2ACardBaseline        *mcp.CardBaseline
	Config                 *config.Config
	Scanner                *scanner.Scanner
	Logger                 *audit.Logger
	Metrics                *metrics.Metrics
	Transport              string
	MaxBytes               int64
	Shield                 *shield.Engine
	ConfirmFinding         func(error) error
	OnObservation          func(string, string)
}

func (o watchResponseOptions) record(scannerName, reason, action string, n int64, enforced bool) {
	if o.OnObservation != nil {
		o.OnObservation(scannerName, action)
	}
	if o.ExternalByteAccounting {
		n = 0
	}
	if o.Logger != nil {
		o.Logger.LogWatchOnly(o.Transport, scannerName, reason, action, n, enforced)
	}
	if o.Metrics != nil {
		o.Metrics.RecordWatchOnly(o.Transport, scannerName, action, n)
	}
}

// watchResponseBody observes the existing response scanners without giving
// them ownership of the wire representation. Raw bytes are replayed even when
// inspection or a proposed rewrite fails. The configured scan ceiling still
// bounds memory; bytes outside it are counted as they are delivered.
func watchResponseBody(ctx context.Context, resp *http.Response, o watchResponseOptions) error {
	if resp.StatusCode == http.StatusPartialContent || resp.StatusCode == http.StatusNotModified {
		o.record("browser_cache", fullResponseRefusal(resp), config.ActionBlock, 0, false)
		if resp.Body == nil || resp.Body == http.NoBody {
			o.record("browser_cache", "partial or cached representation", "uninspected", 0, false)
		} else {
			resp.Body = newWatchUninspectedBody(resp.Body, resp.Body, o, "browser_cache", "partial or cached representation")
		}
		return nil
	}
	if resp.Body == nil || resp.Body == http.NoBody {
		return nil
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		o.record("websocket", "upgraded response is not inspected as HTTP", "uninspected", 0, false)
		return nil
	}
	cfg := o.Config
	if hasNonIdentityEncoding(strings.Join(resp.Header.Values("Content-Encoding"), ",")) {
		o.record(responseScanLayer, "encoded response", config.ActionBlock, 0, false)
		resp.Body = newWatchUninspectedBody(resp.Body, resp.Body, o, responseScanLayer, "encoded response")
		return nil
	}
	if o.Scanner == nil {
		resp.Body = newWatchUninspectedBody(resp.Body, resp.Body, o, scannerLabelUnavailable, scannerPatternUnavailable)
		return nil
	}
	target := ""
	host := ""
	if resp.Request != nil && resp.Request.URL != nil {
		target = resp.Request.URL.String()
		host = resp.Request.URL.Hostname()
	}
	if strings.HasPrefix(strings.ToLower(responseContentType(resp.Header)), "text/event-stream") {
		isA2A := cfg.A2AScanning.Enabled && resp.Request != nil && mcp.IsA2ARequest(resp.Request.URL.Path, resp.Request.Header.Get("Content-Type"))
		if !cfg.ResponseScanning.SSEStreaming.Enabled && !isA2A {
			resp.Body = newWatchUninspectedBody(resp.Body, resp.Body, o, LayerSSEStream, "SSE inspection disabled")
			return nil
		}
		source := resp.Body
		reader, writer := io.Pipe()
		streamCtx, cancel := context.WithCancel(ctx)
		resp.Body = &watchSSEBody{PipeReader: reader, source: source, cancel: cancel}
		opts := mcp.GenericSSEScanOptions{
			Target:             target,
			Suppress:           cfg.Suppress,
			ResponseScanExempt: isResponseScanExempt(host, cfg.ResponseScanning.ExemptDomains),
			WatchOnly:          true,
			OnWatchOnly:        o.record,
			ConfirmFinding:     o.ConfirmFinding,
			WatchEvent: func(event []byte) error {
				finding := false
				eventOpts := o
				eventOpts.OnObservation = func(layer, action string) {
					if action != config.ActionAllow {
						finding = true
					}
					if o.OnObservation != nil {
						o.OnObservation(layer, action)
					}
				}
				result := watchA2AResponse(streamCtx, resp, event, eventOpts, o.A2ACardBaseline)
				if result.Core {
					return errWatchResponseCoreFloor
				}
				if result.Uninspected != "" {
					o.record("a2a_response", result.Uninspected, "uninspected", int64(len(event)), false)
				}
				if finding && o.ConfirmFinding != nil {
					return o.ConfirmFinding(errors.New("watch-only A2A response finding"))
				}
				return nil
			},
		}
		go func() {
			defer cancel()
			defer func() { _ = source.Close() }()
			err := mcp.ScanGenericSSEStreamWithOptions(streamCtx, source, writer, nil, o.Scanner, &cfg.ResponseScanning.SSEStreaming, opts)
			_ = writer.CloseWithError(err)
		}()
		return nil
	}
	limit := o.MaxBytes
	if limit <= 0 {
		limit = int64(cfg.FetchProxy.MaxResponseMB) * 1024 * 1024
	}
	if limit <= 0 {
		resp.Body = newWatchUninspectedBody(resp.Body, resp.Body, o, responseScanLayer, "no response inspection capacity")
		return nil
	}
	source := resp.Body
	body, err := io.ReadAll(io.LimitReader(source, limit+1))
	if err != nil {
		o.record(responseScanLayer, "upstream body read failed", "terminate", 0, true)
		_ = source.Close()
		return fmt.Errorf("watch-only response read: %w", err)
	}
	incomplete := int64(len(body)) > limit
	if incomplete {
		o.record(responseScanLayer, "response inspection ceiling exceeded", config.ActionBlock, 0, false)
		// Count the whole representation as uninspected: a scanned prefix does
		// not establish complete-response inspection.
		resp.Body = newWatchUninspectedBody(io.MultiReader(bytes.NewReader(body), source), source, o, responseScanLayer, "response inspection ceiling exceeded")
		body = body[:limit]
	} else {
		resp.Body = &watchReplayBody{Reader: bytes.NewReader(body), closer: source}
	}
	if !utf8.Valid(body) && !isBinaryMIME(responseContentType(resp.Header)) {
		if !incomplete {
			resp.Body = newWatchUninspectedBody(resp.Body, resp.Body, o, responseScanLayer, "invalid UTF-8")
		}
		return nil
	}
	a2aResult := watchA2AResult{}
	if !incomplete {
		a2aResult = watchA2AResponse(ctx, resp, body, o, o.A2ACardBaseline)
	}
	// A size-limited prefix is not a complete A2A document. Its parse failure
	// must not turn the explicit response-size relaxation into a refusal.
	if a2aResult.Core {
		_ = resp.Body.Close()
		return errWatchResponseCoreFloor
	}
	if a2aResult.Uninspected != "" && !incomplete {
		resp.Body = newWatchUninspectedBody(resp.Body, resp.Body, o, "a2a", a2aResult.Uninspected)
		incomplete = true
	}
	media := applyMediaPolicy(cfg, responseContentType(resp.Header), body, mediaPolicyOptions{host: host})
	if media.Blocked {
		o.record("media_policy", media.BlockReason, config.ActionBlock, 0, false)
	}
	if media.StripResult != nil && media.StripResult.Changed() {
		o.record("media_policy", "media rewrite", config.ActionStrip, 0, false)
	}
	result := scanStructuredResponse(ctx, o.Scanner, cfg, body, target, nil)
	if result.Failed() {
		o.record(responseScanLayer, result.ScanError, "uninspected", 0, false)
		if !incomplete {
			resp.Body = newWatchUninspectedBody(resp.Body, resp.Body, o, responseScanLayer, result.ScanError)
			incomplete = true
		}
	} else {
		for _, match := range result.Matches {
			o.record(responseScanLayer, match.PatternName, o.Scanner.ResponseAction(), 0, false)
		}
	}
	if o.Shield != nil && cfg.BrowserShield.Enabled && !isShieldExempt(host, cfg.BrowserShield.ExemptDomains) {
		transformed := runShieldPipelineWithEncoding(o.Shield, body, responseContentType(resp.Header), resp.Header.Clone(), &cfg.BrowserShield, nil, o.Transport)
		if transformed.uninspectableReason != "" {
			if !incomplete {
				resp.Body = newWatchUninspectedBody(resp.Body, resp.Body, o, browserShieldLayer, transformed.uninspectableReason)
			} else {
				o.record(browserShieldLayer, transformed.uninspectableReason, "uninspected", 0, false)
			}
		} else if transformed.svgRefusal != "" {
			o.record("media_policy", transformed.svgRefusal, config.ActionBlock, 0, false)
		} else if !bytes.Equal(transformed.body, body) {
			o.record(browserShieldLayer, "browser shield rewrite", config.ActionStrip, 0, false)
		}
	}
	return nil
}

type watchReplayBody struct {
	io.Reader
	closer io.Closer
}

func (b *watchReplayBody) Close() error { return b.closer.Close() }

type watchUninspectedBody struct {
	io.Reader
	closer      io.Closer
	opts        watchResponseOptions
	scannerName string
	reason      string
	bytes       atomic.Int64
	once        sync.Once
}

func newWatchUninspectedBody(reader io.Reader, closer io.Closer, o watchResponseOptions, scannerName, reason string) *watchUninspectedBody {
	o.record(scannerName, reason, "uninspected", 0, false)
	return &watchUninspectedBody{Reader: reader, closer: closer, opts: o, scannerName: scannerName, reason: reason}
}

func (b *watchUninspectedBody) finish() {
	b.once.Do(func() { b.opts.record(b.scannerName, b.reason, "uninspected", b.bytes.Load(), false) })
}

func (b *watchUninspectedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.bytes.Add(int64(n))
	if err != nil {
		b.finish()
	}
	return n, err
}

func (b *watchUninspectedBody) Close() error {
	err := b.closer.Close()
	b.finish()
	return err
}

type watchSSEBody struct {
	*io.PipeReader
	source io.Closer
	cancel context.CancelFunc
}

func (b *watchSSEBody) Close() error {
	b.cancel()
	_ = b.source.Close()
	return b.PipeReader.Close()
}
