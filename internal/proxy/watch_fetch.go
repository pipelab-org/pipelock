// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/responseencoding"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// maxFetchRedirects is the existing fetch-client redirect-chain ceiling.
const maxFetchRedirects = 5

func (p *Proxy) handleWatchFetch(w http.ResponseWriter, r *http.Request, o watchHTTPOptions) {
	start := time.Now()
	cfg, sc, agent := o.Config, o.Scanner, o.Agent
	if o.ActionID == "" {
		o.ActionID = receipt.NewActionID()
	}
	o.findings, o.requestFinding = &watchFindingLog{}, new(atomic.Bool)
	delivered := &watchDeliveryWriter{ResponseWriter: w}
	w = delivered
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, FetchResponse{Error: "only GET allowed"})
		return
	}
	rawURL := extractTargetURL(r)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, rawURL, nil)
	if err != nil || req.URL == nil || (req.URL.Scheme != schemeHTTP && req.URL.Scheme != schemeHTTPS) {
		o.observe("fetch", "invalid forwarding URL", config.ActionBlock, 0, true)
		writeJSON(w, http.StatusBadRequest, FetchResponse{Error: "invalid URL: must be http or https"})
		return
	}

	if o.killed() {
		o.observe("kill_switch", killSwitchActiveReason, config.ActionBlock, 0, true)
		o.recordRefusal(req, "kill_switch", start)
		writeJSON(w, http.StatusServiceUnavailable, FetchResponse{Blocked: true, Error: "enforced in watch-only: kill switch active"})
		return
	}
	if err := p.verifyInboundEnvelope(r, cfg); err != nil {
		o.observe(blockLayerMediationEnvelope, inboundEnvelopeFailurePattern(err), config.ActionBlock, 0, true)
		o.recordRefusal(req, blockLayerMediationEnvelope, start)
		writeJSON(w, http.StatusForbidden, FetchResponse{Blocked: true, Error: "enforced in watch-only: inbound authentication failed"})
		return
	}
	access := r.Clone(r.Context())
	access.URL = req.URL
	if !watchAuthorityAllowed(w, access, o, start) {
		return
	}
	req.Header.Set("User-Agent", cfg.FetchProxy.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain,*/*;q=0.8")
	o.DeferClean = true
	o.Refusal = &watchRequestCoverage{}
	adm := watchAdmit(req, o)
	if adm.Core {
		layer, reason := scannerLabelBodyDLP, "core credential floor"
		if o.Refusal.refusalLayer != "" {
			layer, reason = o.Refusal.refusalLayer, o.Refusal.refusalReason
		}
		o.receipt(req, config.ActionBlock, layer, reason+" enforced")
		o.recordRefusal(req, layer, start)
		writeJSON(w, http.StatusForbidden, FetchResponse{URL: audit.RedactContentBearingURL(rawURL), Blocked: true, Error: "enforced in watch-only: " + reason})
		return
	}
	findingsOK := o.confirmFindings(req)
	admissionReceipt := o.receiptWithID(req, o.ActionID, config.ActionAllow, "watch_only", "fetch admitted without policy rewriting")
	if (!admissionReceipt || !findingsOK) && cfg.FlightRecorder.RequireReceipts {
		o.recordRefusal(req, receiptEmissionFailedLayer, start)
		writeJSON(w, http.StatusServiceUnavailable, FetchResponse{Blocked: true, Error: "enforced in watch-only: required receipt unavailable"})
		return
	}
	// The destination policy admitted is the one dialed, redirected from, and
	// signed over: carry the scan snapshot, request identity and the envelope
	// snapshot to every hop.
	ctx := watchOutboundContext(req.Context(), o, req, adm)
	ctx = context.WithValue(ctx, ctxKeyClientIP, o.ClientIP)
	ctx = context.WithValue(ctx, ctxKeyRequestID, o.RequestID)
	ctx = context.WithValue(ctx, ctxKeyAgent, agent)
	ctx = context.WithValue(ctx, ctxKeyReceiptShard, o.ReceiptShard)
	ctx = context.WithValue(ctx, ctxKeyEnvelopeEmitter, envelopeEmitterSnapshot{emitter: o.EnvelopeEmitter})
	req = req.WithContext(ctx)
	if err := o.signWatchOutbound(req, http.MethodGet); err != nil {
		info, reason, _ := o.upstreamRefusal(req, err)
		o.recordRefusal(req, info.Layer, start)
		writeBlockedJSON(w, info, http.StatusForbidden, FetchResponse{
			URL: audit.RedactContentBearingURL(rawURL), Agent: agent, Blocked: true, BlockReason: reason,
			Error: "enforced in watch-only: " + reason,
		})
		return
	}
	client := *p.client
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		refuse := func(layer, reason string) error {
			err := newRedirectBlockedRequest(layer, reason)
			err.target = next.URL.String()
			return err
		}
		if len(via) >= maxFetchRedirects {
			return fmt.Errorf("too many redirects (max %d)", maxFetchRedirects)
		}
		access := r.Clone(next.Context())
		access.URL = next.URL
		if err := watchAuthorityError(access, o); err != nil {
			return refuse(blockLayerAuthority, "redirect authority refused")
		}
		if o.killed() {
			return refuse("kill_switch", killSwitchActiveReason)
		}
		hop := o
		hop.Refusal = &watchRequestCoverage{}
		hopAdmission := watchAdmit(next, hop)
		if hopAdmission.Core {
			layer, reason := "redirect", "audit safety floor"
			if hop.Refusal.refusalLayer != "" {
				layer, reason = hop.Refusal.refusalLayer, hop.Refusal.refusalReason
			}
			return refuse(layer, reason)
		}
		*next = *next.WithContext(watchOutboundContext(next.Context(), o, next, hopAdmission))
		hopFindingsOK := o.confirmFindings(next)
		if (!o.receipt(next, config.ActionAllow, "watch_only", "redirect admitted") || !hopFindingsOK) && cfg.FlightRecorder.RequireReceipts {
			return refuse(receiptEmissionFailedLayer, "required receipt unavailable")
		}
		return p.refreshEnvelopeForRedirect(next, via, cfg)
	}
	resp, err := client.Do(req)
	if err != nil {
		if info, reason, blocked := o.upstreamRefusal(req, err); blocked {
			o.recordRefusal(req, info.Layer, start)
			writeBlockedJSON(w, info, http.StatusForbidden, FetchResponse{
				URL: audit.RedactContentBearingURL(rawURL), Agent: agent, Blocked: true, BlockReason: reason,
				Error: "enforced in watch-only: " + reason,
			})
			return
		}
		o.observe("upstream", "fetch upstream unavailable", config.ActionBlock, 0, true)
		writeJSON(w, http.StatusBadGateway, FetchResponse{URL: audit.RedactContentBearingURL(rawURL), Error: "upstream unavailable"})
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if err := responseencoding.DecodeResponse(resp); err != nil {
		writeJSON(w, http.StatusBadGateway, FetchResponse{Error: "upstream response encoding unavailable"})
		return
	}
	limit := p.responseScanBodyLimit(cfg)
	var responseFinding atomic.Bool
	var responseKinds watchKinds
	var responseSession, taintSession *SessionState
	if sm := p.sessionMgrPtr.Load(); sm != nil {
		taintSession = sm.GetOrCreate(responseTaintSessionKey(cfg, agent, o.ClientIP, o.ActorAuth))
		if cfg.SessionProfiling.Enabled {
			responseSession = sm.GetOrCreate(sessionKeyFor(cfg, agent, o.ClientIP, o.ActorAuth))
		}
	}
	responseOpts := watchResponseOptions{
		Config: cfg, Scanner: sc, Logger: p.logger, Metrics: p.metrics,
		Transport: TransportFetch, MaxBytes: limit, Shield: p.shieldEngine, RequestID: o.RequestID,
		A2ACardBaseline: p.a2aCardBaseline,
		OnObservation:   o.responseObserver(resp.Request, responseSession, &responseFinding),
		OnFinding:       o.findings.add,
		OnKinds:         responseKinds.merge,
	}
	// Streamed findings are confirmed per event before delivery, as on the
	// forward path.
	if cfg.FlightRecorder.RequireReceipts {
		responseOpts.ConfirmFinding = func(finding error) error {
			if !o.receipt(req, config.ActionWarn, LayerSSEStream, finding.Error()) {
				return errWatchReceiptUnavailable
			}
			return nil
		}
	}
	// Exposure is recorded for any response that arrived, delivered or not.
	defer func() {
		if taintSession == nil {
			return
		}
		observeHTTPResponseFindings(taintSession, cfg, resp.Request.URL.String(), responseTaintContentType(resp.Header), "fetch_response", responseKinds.list())
	}()
	// A response refusal arrives either from watchResponseBody or, for a
	// streamed body scanned in the background, as the body read error. Either
	// way it is a refusal, not an upstream failure.
	refuseResponse := func(err error) {
		switch {
		case errors.Is(err, errWatchResponseCoreFloor):
			o.observe(scannerLabelA2A, "core credential floor", config.ActionBlock, 0, true)
			o.receipt(req, config.ActionBlock, scannerLabelA2A, "audit safety floor enforced")
			o.recordRefusal(req, scannerLabelA2A, start)
			writeBlockedJSON(w, blockInfoFor(blockreason.DLPMatch, scannerLabelA2A).WithRequestID(o.RequestID), http.StatusForbidden, FetchResponse{
				URL: audit.RedactContentBearingURL(rawURL), Agent: agent, Blocked: true, BlockReason: "audit safety floor",
				Error: "enforced in watch-only: audit safety floor",
			})
		case errors.Is(err, errWatchReceiptUnavailable):
			o.recordRefusal(req, receiptEmissionFailedLayer, start)
			writeJSON(w, http.StatusServiceUnavailable, FetchResponse{URL: audit.RedactContentBearingURL(rawURL), Blocked: true, Error: errWatchReceiptUnavailable.Error()})
		default:
			writeJSON(w, http.StatusBadGateway, FetchResponse{URL: audit.RedactContentBearingURL(rawURL), Error: "upstream response unavailable"})
		}
	}
	if err := watchResponseBody(r.Context(), resp, responseOpts); err != nil {
		refuseResponse(err)
		return
	}
	// The uninspected-byte count follows bytes the client accepts, not bytes
	// read into the buffer: a client can disconnect after buffering.
	var uninspected *watchUninspectedBody
	if held, ok := resp.Body.(*watchUninspectedBody); ok {
		held.holdAccounting()
		uninspected = held
	}
	var consumed int
	source := resp.Body
	resp.Body = &watchRequestReplayBody{Reader: source, source: source, onRead: func(n int) { consumed += n }}
	defer func() {
		sc.RecordRequest(req.URL.Hostname(), consumed)
		if o.Budget != nil {
			_ = o.Budget.RecordRequest(req.URL.Hostname(), 0)
			_ = o.Budget.RecordBytes(int64(consumed))
		}
	}()
	prefix, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		refuseResponse(err)
		return
	}
	meta := FetchResponse{URL: rawURL, Agent: agent, StatusCode: resp.StatusCode, ContentType: responseContentType(resp.Header)}
	var surface fetchResponseSurface
	withinLimit := int64(len(prefix)) <= limit
	if withinLimit {
		surface = deriveFetchResponse(prefix, meta.ContentType, resp.Request.URL)
		meta.Content, meta.Title = surface.content, surface.title
		// Readability can join text the raw body keeps apart (an instruction
		// split across tags), so the delivered text is scanned as well. Other
		// representations are the raw body, which was already scanned.
		if surface.html && sc.ResponseScanningEnabled() {
			scanned := scanFetchResponse(r.Context(), sc, cfg, surface, resp.Request.URL.String())
			action := sc.ResponseAction()
			if isResponseScanExempt(resp.Request.URL.Hostname(), cfg.ResponseScanning.ExemptDomains) {
				action = config.ActionWarn
			}
			for _, result := range []*scanner.ResponseScanResult{&scanned.result, scanned.hidden} {
				if result == nil || result.Clean {
					continue
				}
				if result.Failed() {
					responseOpts.record(responseScanLayer, result.ScanError, "uninspected", 0, false)
					continue
				}
				for _, match := range result.Matches {
					responseOpts.record(responseScanLayer, match.PatternName, action, 0, false)
				}
				responseOpts.kinds(responseScanFindingKinds(*result))
			}
		}
	}
	// Buffered response findings are recorded in signed receipts before release;
	// with required receipts a failed write refuses it. Streamed findings were
	// confirmed per event above.
	if !o.confirmFindings(req) && cfg.FlightRecorder.RequireReceipts {
		o.recordRefusal(req, receiptEmissionFailedLayer, start)
		writeJSON(w, http.StatusServiceUnavailable, FetchResponse{URL: audit.RedactContentBearingURL(rawURL), Blocked: true, Error: "enforced in watch-only: required receipt unavailable"})
		return
	}
	if withinLimit {
		writeJSON(w, http.StatusOK, meta)
		if uninspected != nil {
			committed := int64(consumed)
			if delivered.err != nil {
				committed = 0
			}
			uninspected.commit(committed)
		}
	} else {
		// The fetch API returns JSON text. Stream the complete over-limit source
		// through JSON escaping instead of allocating an unbounded content string.
		w.Header().Set("Content-Type", "application/json")
		encoded, marshalErr := json.Marshal(meta)
		if marshalErr != nil {
			return
		}
		if _, err := w.Write(encoded[:len(encoded)-1]); err != nil {
			return
		}
		if _, err := io.WriteString(w, `,"content":"`); err != nil {
			return
		}
		streamErr := writeWatchJSONString(w, io.MultiReader(bytes.NewReader(prefix), resp.Body))
		if uninspected != nil {
			uninspected.commit(int64(consumed))
		}
		if streamErr != nil {
			if delivered.err == nil {
				// The upstream body failed after a 200 and partial JSON were
				// sent. Ending the response normally would present invalid JSON
				// as complete, so record the failed delivery and abort it.
				o.observe("upstream", "upstream body failed after the fetch response began", "terminate", 0, true)
				o.recordRefusal(req, "upstream", start)
				panic(http.ErrAbortHandler)
			}
			return
		}
		_, _ = io.WriteString(w, `"}`)
	}
	if delivered.err == nil && cfg.FlightRecorder.RequireReceipts {
		delivered.err = flushResponseBeforeOutcome(w, r, cfg)
	}
	if delivered.err == nil {
		// Clean credit is withheld when either direction recorded a finding.
		if !responseFinding.Load() && !o.requestFinding.Load() && responseSession != nil {
			responseSession.ObserveWatchOnlyCleanAt(o.Generation, adaptiveScopeForHost(resp.Request.URL.Hostname()), &cfg.AdaptiveEnforcement)
		}
		o.Metrics.RecordAllowed(time.Since(start), o.agentLabel())
		o.receipt(req, config.ActionAllow, "watch_only", "fetch delivered without policy rewriting")
	}
}

func writeWatchJSONString(w io.Writer, source io.Reader) error {
	reader := bufio.NewReader(source)
	var part strings.Builder
	flush := func() error {
		encoded, err := json.Marshal(part.String())
		if err != nil {
			return fmt.Errorf("encode fetch content: %w", err)
		}
		if _, err := w.Write(encoded[1 : len(encoded)-1]); err != nil {
			return fmt.Errorf("write fetch content: %w", err)
		}
		part.Reset()
		return nil
	}
	for {
		value, _, err := reader.ReadRune()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return fmt.Errorf("read fetch content: %w", err)
			}
			return flush()
		}
		_, _ = part.WriteRune(value)
		if part.Len() >= tunnelBufSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
}
