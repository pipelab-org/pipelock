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

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/responseencoding"
)

// maxFetchRedirects is the existing fetch-client redirect-chain ceiling.
const maxFetchRedirects = 5

func (p *Proxy) handleWatchFetch(w http.ResponseWriter, r *http.Request, o watchHTTPOptions) {
	cfg, sc, agent := o.Config, o.Scanner, o.Agent
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
		writeJSON(w, http.StatusServiceUnavailable, FetchResponse{Blocked: true, Error: "enforced in watch-only: kill switch active"})
		return
	}
	if err := p.verifyInboundEnvelope(r, cfg); err != nil {
		o.observe(blockLayerMediationEnvelope, inboundEnvelopeFailurePattern(err), config.ActionBlock, 0, true)
		writeJSON(w, http.StatusForbidden, FetchResponse{Blocked: true, Error: "enforced in watch-only: inbound authentication failed"})
		return
	}
	access := r.Clone(r.Context())
	access.URL = req.URL
	if !watchAuthorityAllowed(w, access, o) {
		return
	}
	req.Header.Set("User-Agent", cfg.FetchProxy.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain,*/*;q=0.8")
	o.DeferClean = true
	if watchRequestDecision(req, o) {
		o.receipt(req, config.ActionBlock, scannerLabelBodyDLP, "core credential floor enforced")
		writeJSON(w, http.StatusForbidden, FetchResponse{URL: audit.RedactContentBearingURL(rawURL), Blocked: true, Error: "enforced in watch-only: core credential floor"})
		return
	}
	if !o.receipt(req, config.ActionAllow, "watch_only", "fetch admitted without policy rewriting") && cfg.FlightRecorder.RequireReceipts {
		writeJSON(w, http.StatusServiceUnavailable, FetchResponse{Blocked: true, Error: "enforced in watch-only: required receipt unavailable"})
		return
	}
	req = req.WithContext(context.WithValue(req.Context(), watchModeContextKey{}, o))
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
		if watchRequestDecision(next, o) {
			return refuse("redirect", "audit safety floor")
		}
		if !o.receipt(next, config.ActionAllow, "watch_only", "redirect admitted") && cfg.FlightRecorder.RequireReceipts {
			return refuse(receiptEmissionFailedLayer, "required receipt unavailable")
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		if info, reason, blocked := o.upstreamRefusal(req, err); blocked {
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
	var responseSession *SessionState
	if cfg.SessionProfiling.Enabled {
		if sm := p.sessionMgrPtr.Load(); sm != nil {
			responseSession = sm.GetOrCreate(sessionKeyFor(cfg, agent, o.ClientIP, o.ActorAuth))
		}
	}
	responseOpts := watchResponseOptions{
		Config: cfg, Scanner: sc, Logger: p.logger, Metrics: p.metrics,
		Transport: TransportFetch, MaxBytes: limit, Shield: p.shieldEngine,
		OnObservation: o.responseObserver(resp.Request, responseSession, &responseFinding),
	}
	if err := watchResponseBody(r.Context(), resp, responseOpts); err != nil {
		writeJSON(w, http.StatusBadGateway, FetchResponse{URL: audit.RedactContentBearingURL(rawURL), Error: "upstream response unavailable"})
		return
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
		writeJSON(w, http.StatusBadGateway, FetchResponse{URL: audit.RedactContentBearingURL(rawURL), Error: "upstream response unavailable"})
		return
	}
	meta := FetchResponse{URL: rawURL, Agent: agent, StatusCode: resp.StatusCode, ContentType: responseContentType(resp.Header)}
	if int64(len(prefix)) <= limit {
		surface := deriveFetchResponse(prefix, meta.ContentType, resp.Request.URL)
		meta.Content, meta.Title = surface.content, surface.title
		writeJSON(w, http.StatusOK, meta)
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
		if err := writeWatchJSONString(w, io.MultiReader(bytes.NewReader(prefix), resp.Body)); err != nil {
			return
		}
		_, _ = io.WriteString(w, `"}`)
	}
	if delivered.err == nil {
		if !responseFinding.Load() && responseSession != nil {
			responseSession.ObserveWatchOnlyClean(adaptiveScopeForHost(resp.Request.URL.Hostname()), &cfg.AdaptiveEnforcement)
		}
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
