// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/luckyPipewrench/pipelock/internal/session"
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
	RequestID              string
	// OnFinding receives each would-block finding so it can be recorded in a
	// signed receipt before the response is released.
	OnFinding func(layer, reason, action string)
	// OnKinds receives the finding kinds of the response for session taint.
	OnKinds func([]session.HostileFindingKind)
}

func (o watchResponseOptions) kinds(kinds []session.HostileFindingKind) {
	if o.OnKinds != nil && len(kinds) > 0 {
		o.OnKinds(kinds)
	}
}

func (o watchResponseOptions) record(scannerName, reason, action string, n int64, enforced bool) {
	if o.OnObservation != nil {
		o.OnObservation(scannerName, action)
	}
	if !enforced && o.OnFinding != nil {
		o.OnFinding(scannerName, reason, action)
	}
	if o.ExternalByteAccounting {
		n = 0
	}
	if o.Logger != nil {
		o.Logger.LogWatchOnlyRequest(o.RequestID, o.Transport, scannerName, reason, action, n, enforced)
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
			return nil
		}
		if resp.StatusCode == http.StatusPartialContent {
			inspected, err := o.inspectPartialA2A(ctx, resp)
			if err != nil || inspected {
				return err
			}
		}
		resp.Body = newWatchUninspectedBody(resp.Body, resp.Body, o, "browser_cache", "partial or cached representation")
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
		// SSE findings are confirmed per event while streaming; the buffered
		// finding log is released before the body and would never drain them.
		stream := o
		stream.OnFinding = nil
		reader, writer := io.Pipe()
		streamCtx, cancel := context.WithCancel(ctx)
		resp.Body = &watchSSEBody{PipeReader: reader, source: source, cancel: cancel}
		opts := mcp.GenericSSEScanOptions{
			Target:             target,
			Suppress:           cfg.Suppress,
			ResponseScanExempt: isResponseScanExempt(host, cfg.ResponseScanning.ExemptDomains),
			WatchOnly:          true,
			OnWatchOnly:        stream.record,
			ConfirmFinding:     o.ConfirmFinding,
			OnFinding:          func(err error) { o.kinds(observedSSEFindingKinds(err)) },
			WatchEvent: func(event []byte) error {
				finding := false
				eventOpts := stream
				eventOpts.OnObservation = func(layer, action string) {
					if action != config.ActionAllow {
						finding = true
					}
					if o.OnObservation != nil {
						o.OnObservation(layer, action)
					}
				}
				result := watchA2AResponse(streamCtx, resp, event, eventOpts, o.A2ACardBaseline)
				o.kinds(result.Kinds)
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
	limit := o.scanLimit()
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
		o.kinds(a2aResult.Kinds)
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
		// An exempt domain's findings are pinned to warn, as the enforcing
		// response path does, so watch-only does not report a would-block
		// decision enforcement would never make.
		action := o.Scanner.ResponseAction()
		if isResponseScanExempt(host, cfg.ResponseScanning.ExemptDomains) {
			action = config.ActionWarn
		}
		for _, match := range result.Matches {
			o.record(responseScanLayer, match.PatternName, action, 0, false)
		}
		if !result.Clean {
			o.kinds(responseScanFindingKinds(result))
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

// scanLimit is the number of response bytes watch-only buffers for inspection.
func (o watchResponseOptions) scanLimit() int64 {
	if o.MaxBytes > 0 {
		return o.MaxBytes
	}
	return int64(o.Config.FetchProxy.MaxResponseMB) * 1024 * 1024
}

// inspectPartialA2A applies the A2A credential floor to a 206 body that is a
// complete JSON document. A server can answer 206 with a whole A2A message, so
// the status alone does not make the bytes uninspectable; a body that is not a
// valid JSON text (RFC 8259) is a genuine fragment and keeps its passthrough.
// inspected reports that the body was scanned as a complete A2A document.
func (o watchResponseOptions) inspectPartialA2A(ctx context.Context, resp *http.Response) (inspected bool, err error) {
	cfg := o.Config
	if !cfg.A2AScanning.Enabled || o.Scanner == nil || resp.Request == nil || resp.Request.URL == nil ||
		!mcp.IsA2ARequest(resp.Request.URL.Path, resp.Request.Header.Get("Content-Type")) ||
		hasNonIdentityEncoding(strings.Join(resp.Header.Values("Content-Encoding"), ",")) {
		return false, nil
	}
	limit := o.scanLimit()
	if limit <= 0 {
		return false, nil
	}
	source := resp.Body
	body, readErr := io.ReadAll(io.LimitReader(source, limit+1))
	if readErr != nil {
		o.record(responseScanLayer, "upstream body read failed", "terminate", 0, true)
		_ = source.Close()
		return false, fmt.Errorf("watch-only response read: %w", readErr)
	}
	if int64(len(body)) > limit {
		resp.Body = &watchReplayBody{Reader: io.MultiReader(bytes.NewReader(body), source), closer: source}
		return false, nil
	}
	resp.Body = &watchReplayBody{Reader: bytes.NewReader(body), closer: source}
	if !json.Valid(body) {
		return false, nil
	}
	result := watchA2AResponse(ctx, resp, body, o, o.A2ACardBaseline)
	o.kinds(result.Kinds)
	if result.Core {
		_ = resp.Body.Close()
		return true, errWatchResponseCoreFloor
	}
	return result.Uninspected == "", nil
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
	held        atomic.Bool
}

func newWatchUninspectedBody(reader io.Reader, closer io.Closer, o watchResponseOptions, scannerName, reason string) *watchUninspectedBody {
	o.record(scannerName, reason, "uninspected", 0, false)
	return &watchUninspectedBody{Reader: reader, closer: closer, opts: o, scannerName: scannerName, reason: reason}
}

func (b *watchUninspectedBody) finish() {
	if b.held.Load() {
		return
	}
	b.once.Do(func() { b.opts.record(b.scannerName, b.reason, "uninspected", b.bytes.Load(), false) })
}

// holdAccounting defers the uninspected-byte count until the owner reports how
// many bytes reached the client. Reading the body is not delivery: a fetch
// client can disconnect after the representation is buffered.
func (b *watchUninspectedBody) holdAccounting() { b.held.Store(true) }

// commit records the bytes the client accepted and ends the hold.
func (b *watchUninspectedBody) commit(delivered int64) {
	b.held.Store(false)
	b.once.Do(func() { b.opts.record(b.scannerName, b.reason, "uninspected", delivered, false) })
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
