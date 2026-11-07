// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/authority"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

type watchHTTPOptions struct {
	Intercept        *InterceptContext
	Budget           edition.BudgetChecker
	ActorAuth        envelope.ActorAuth
	InboundVerified  bool
	Config           *config.Config
	Scanner          *scanner.Scanner
	Logger           *audit.Logger
	Metrics          *metrics.Metrics
	Transport        string
	Upstream         http.RoundTripper
	Proxy            *Proxy
	Agent            string
	ClientIP         string
	RequestID        string
	KillSwitch       *killswitch.Controller
	MaxResponseBytes int64
}

type watchModeContextKey struct{}

func (o watchHTTPOptions) observe(layer, reason, action string, count int64, enforced bool) {
	watchObservation(o.Logger, o.Metrics, o.Transport, layer, reason, action, count, enforced)
}

func (o watchHTTPOptions) receipt(r *http.Request, verdict, layer, reason string) bool {
	if o.Proxy == nil || o.Proxy.receiptEmitterPtr.Load() == nil {
		if o.Config.FlightRecorder.RequireReceipts {
			o.observe(receiptEmissionFailedLayer, "receipt recorder unavailable", config.ActionBlock, 0, true)
			return false
		}
		return true
	}
	opts := withReceiptConfig(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: verdict,
		Layer: layer, Pattern: "watch-only: " + reason, Transport: o.Transport,
		Method: r.Method, Target: r.URL.String(), RequestID: o.RequestID, Agent: o.Agent,
	}, o.Config)
	if err := o.Proxy.emitReceipt(opts); err != nil {
		action := "uninspected"
		if o.Config.FlightRecorder.RequireReceipts {
			action = config.ActionBlock
		}
		o.observe(receiptEmissionFailedLayer, "receipt could not be recorded", action, 0, o.Config.FlightRecorder.RequireReceipts)
		return false
	}
	return true
}

func (o watchHTTPOptions) killed() bool {
	if o.KillSwitch == nil {
		return false
	}
	return o.KillSwitch.IsActive()
}

// watchRequestDecision joins the existing scanners and policy evaluator. It
// runs before any egress and retains the audit-mode secret and host floor.
func watchRequestDecision(r *http.Request, o watchHTTPOptions) bool {
	sc, cfg := o.Scanner, o.Config
	if o.Budget != nil {
		if err := o.Budget.CheckAdmission(r.URL.Hostname()); err != nil {
			o.observe("budget", "per-agent admission budget exceeded", config.ActionBlock, 0, false)
		}
	}

	if sc == nil {
		o.observe(scannerLabelUnavailable, scannerPatternUnavailable, config.ActionBlock, 0, true)
		return true
	}
	result := sc.Scan(r.Context(), r.URL.String())

	coreResult := sc.ScanURLCoreFloor(r.URL.String())
	core := !coreResult.Allowed
	if !result.Allowed {
		o.observe(result.Scanner, result.Reason, config.ActionBlock, 0, core && scanner.IsCoreCriticalResult(result))
	}
	if core && !scanner.IsCoreCriticalResult(result) {
		o.observe(coreResult.Scanner, coreResult.Reason, config.ActionBlock, 0, true)
	}
	core = watchA2AHeaders(r, o) || core
	scanHeaders := r.Header
	if o.Intercept != nil {
		if store := o.Intercept.issuerCookieStore(); store != nil {
			var allowances []issuerCookieAllowance
			scanHeaders, allowances = issuerCookieScanHeaders(r.Context(), r.Header, sc, store,
				sessionKeyFor(cfg, o.Agent, o.ClientIP, o.ActorAuth), r.URL, time.Now())
			for _, allowance := range allowances {
				for _, pattern := range allowance.Patterns {
					if err := o.Proxy.recordIssuerCookieAllow(cfg, audit.NewMethodLogContext(r.Method), pattern, allowance.Name, r.URL.String(), o.RequestID, o.Agent, r.Method); err != nil {
						o.observe(receiptEmissionFailedLayer, "issuer cookie evidence unavailable", "uninspected", 0, false)
					}
				}
			}
		}
	}
	headers := scanRequestHeadersForTarget(r.Context(), scanHeaders, cfg, sc, r.URL.String())
	if headers != nil && !headers.Clean {
		for _, match := range headers.DLPMatches {
			enforced := shouldHardBlockRequestDLP([]scanner.TextDLPMatch{match}, cfg)
			core = core || enforced
			action := headers.Action
			if enforced {
				action = config.ActionBlock
			}
			o.observe("dlp_header", match.PatternName, action, 0, enforced)
		}
		if len(headers.DLPMatches) == 0 {
			core = true
			o.observe("dlp_header", "headers could not be completely inspected", config.ActionBlock, 0, true)
		}
	}
	coverage := &watchRequestCoverage{}
	if watchRequestBody(r.Context(), r, watchRequestOptions{Coverage: coverage, Config: cfg, Scanner: sc, Logger: o.Logger, Metrics: o.Metrics, Transport: o.Transport}) {
		core = true
	}
	if o.Proxy != nil {
		p := o.Proxy
		p.recordSessionActivityWithUserAgent(sessionActivityOptions{
			ClientIP: o.ClientIP, Agent: o.Agent, Hostname: r.URL.Hostname(),
			RequestID: o.RequestID, UserAgent: r.UserAgent(), ActorAuth: o.ActorAuth,
			Result: result, Config: cfg, Logger: o.Logger, ObserveOnly: true,
		})
		// Read the existing session state; observation never raises its enforcement
		// level or enters airlock. Findings remain distinct from enforced signals.
		if sm := p.sessionMgrPtr.Load(); sm != nil {
			rec := sm.GetOrCreate(sessionKeyFor(cfg, o.Agent, o.ClientIP, o.ActorAuth))
			if rec == nil {
				o.observe(sessionCapacityLayer, "session observation capacity exhausted", "uninspected", 0, false)
			} else {
				td := evaluateHTTPTaint(cfg, rec, r.Method, r.URL)
				if td.Result.Decision != session.PolicyAllow {
					o.observe("taint", td.Result.Reason, td.Result.Decision.String(), 0, false)
				}
				level := rec.EffectiveEscalationLevel(adaptiveScopeForHost(r.URL.Hostname()))
				action := config.ActionAllow
				if !result.Allowed {
					action = config.ActionWarn
				}
				if decide.UpgradeAction(action, level, &cfg.AdaptiveEnforcement) != action {
					o.observe(adaptiveEnforcementLayer, "adaptive action upgrade observed", "escalate", 0, false)
				}
				tier := airlockTierForScope(rec, adaptiveScopeForHost(r.URL.Hostname()))
				if allowed, reason := ClassifyAction(tier, r.Method, o.Transport, true); !allowed {
					o.observe("airlock", reason, config.ActionBlock, 0, false)
				}
			}
		}
		if cfg.CrossRequestDetection.Enabled {
			sessionKey := ceeSessionKey(cfg, o.Agent, o.ClientIP, o.ActorAuth)
			var partitionKey []byte
			if fb := p.fragmentBufferPtr.Load(); fb != nil {
				partitionKey = fb.PartitionKey()
			}
			payloads := extractOutboundPayloads(r, ceeJSONBodyPartitioningEnabled(cfg), sessionKey, partitionKey)
			cee := p.admitCurrentCEE(r.Context(), ceeAdmitRequest{
				ActorAuth: o.ActorAuth, Outbound: payloads.outbound,
				BodyFragmentPayloads: payloads.bodyFragmentPayloads, BodyFragmentLeaves: payloads.bodyFragmentLeaves, PartitionReason: payloads.partitionReason,
				KeyPayload: queryParamKeys(r.URL), PathPayload: pathSegments(r.URL), TargetURL: r.URL.String(), Agent: o.Agent, ClientIP: o.ClientIP, RequestID: o.RequestID, IncludeFragments: true,
			})
			if cee.Result.Blocked {
				core = true
			}
		}

		in := requestPolicyInput{
			Config: cfg,
			Host:   r.URL.Hostname(), Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery,
			ContentType: r.Header.Get("Content-Type"), Headers: r.Header, Transport: o.Transport, Target: r.URL.String(),
			RequestID: o.RequestID, Agent: o.Agent, AuditCtx: audit.NewMethodLogContext(r.Method),
		}
		_ = p.prepareRequestPolicyBody(r, &in)
		_ = p.applyRequestPolicy(in)
		gate, err := EvaluateGate(ContractGateInput{
			Loader: p.currentContractLoader(), Agent: o.Agent, URL: r.URL.String(),
			Method: r.Method, EffectiveAction: config.ActionAllow, ScannerVerdict: config.ActionAllow, Transport: o.Transport,
		})
		if err != nil {
			o.observe("contract", "contract evaluation unavailable", "uninspected", 0, false)
		} else if gate.Verdict == config.ActionBlock {
			o.observe("contract", gate.Reason, config.ActionBlock, 0, false)
		}
	}

	if o.Proxy != nil {
		action := config.ActionAllow
		if core {
			action = config.ActionBlock
		}
		findings := urlResultToFindings(result)
		o.Proxy.captureObs.ObserveURLVerdict(r.Context(), &capture.URLVerdictRecord{
			Subsurface: "watch_only_url", Transport: o.Transport, SessionID: captureSessionKey(o.Agent, o.ClientIP),
			SessionIDOriginal: captureSessionKeyOriginal(o.Agent, o.ClientIP), RequestID: o.RequestID, ConfigHash: cfg.CanonicalPolicyHash(),
			Agent: o.Agent, ActionClass: captureHTTPActionClass(r.Method), Request: capture.CaptureRequest{Method: r.Method, URL: r.URL.String()},
			RawFindings: findings, EffectiveFindings: findings, EffectiveAction: action, Outcome: captureOutcome(action, !core),
		})
	}
	if !core && coverage.reason != "" && r.Body != nil {
		source := r.Body
		r.Body = &watchRequestReplayBody{Reader: source, source: source, onRead: func(n int) {
			o.observe(coverage.layer, coverage.reason, "uninspected", int64(n), false)
		}}
	}
	return core
}

// serveWatchHTTP keeps the original representation while invoking the same
// scanner functions as enforcement. ReverseProxy owns RFC hop-by-hop handling
// handling; uninspectable upgrades are refused before any stream is relayed.
func serveWatchHTTP(w http.ResponseWriter, r *http.Request, o watchHTTPOptions) {
	start := time.Now()
	if o.Proxy != nil && !o.InboundVerified {
		if err := o.Proxy.verifyInboundEnvelope(r, o.Config); err != nil {
			o.observe(blockLayerMediationEnvelope, inboundEnvelopeFailurePattern(err), config.ActionBlock, 0, true)
			writeBlockedError(w, blockInfoFor(blockreason.EnvelopeVerifyFailed, blockLayerMediationEnvelope), "enforced in watch-only: inbound authentication failed", http.StatusForbidden)
			return
		}
	}

	if !watchAuthorityAllowed(w, r, o) {
		return
	}
	envelope.StripInbound(r.Header)
	stripInternalIdentity(r)
	if o.killed() {
		o.observe("kill_switch", killSwitchActiveReason, config.ActionBlock, 0, true)
		o.receipt(r, config.ActionBlock, "kill_switch", killSwitchActiveReason)
		writeBlockedError(w, blockInfoFor(blockreason.KillSwitchActive, "kill_switch").WithRequestID(o.RequestID), "enforced in watch-only: kill switch active", http.StatusServiceUnavailable)
		return
	}
	if watchRequestDecision(r, o) {
		o.receipt(r, config.ActionBlock, scannerLabelBodyDLP, "audit safety floor enforced")
		writeBlockedError(w, blockInfoFor(blockreason.DLPMatch, scannerLabelBodyDLP).WithRequestID(o.RequestID), "enforced in watch-only: audit safety floor", http.StatusForbidden)
		return
	}
	if o.killed() {
		o.observe("kill_switch", killSwitchActiveReason, config.ActionBlock, 0, true)
		writeBlockedError(w, blockInfoFor(blockreason.KillSwitchActive, "kill_switch"), "enforced in watch-only: kill switch active", http.StatusServiceUnavailable)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), watchModeContextKey{}, o))
	receiptOK := o.receipt(r, config.ActionAllow, "watch_only", "request admitted without policy rewriting")
	if !receiptOK && o.Config.FlightRecorder.RequireReceipts {
		o.observe(receiptEmissionFailedLayer, "required receipt unavailable", config.ActionBlock, 0, true)
		http.Error(w, "enforced in watch-only: required receipt unavailable", http.StatusServiceUnavailable)
		return
	}
	var deliveredResponse *http.Response
	failed := false
	rp := &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			req.Out.RequestURI = ""
			req.Out.URL.RawQuery = req.In.URL.RawQuery
			// Proxy identity assertions were consumed by stripInternalIdentity;
			// Rewrite must not manufacture a replacement identity.
		},
		Transport: o.Upstream,
		ModifyResponse: func(resp *http.Response) error {
			deliveredResponse = resp
			if resp.Request == nil {
				resp.Request = r
			}
			if resp.StatusCode == http.StatusSwitchingProtocols {
				o.observe("websocket", "upgraded stream requires a scanning relay", config.ActionBlock, 0, true)
				return errors.New("enforced in watch-only: uninspectable upgraded stream")
			}
			opts := watchResponseOptions{ExternalByteAccounting: !receiptOK, Config: o.Config, Scanner: o.Scanner, Logger: o.Logger, Metrics: o.Metrics, Transport: o.Transport, MaxBytes: o.MaxResponseBytes}
			if o.Proxy != nil {
				opts.Shield = o.Proxy.shieldEngine
				opts.A2ACardBaseline = o.Proxy.a2aCardBaseline
			}
			err := watchResponseBody(r.Context(), resp, opts)
			if err == nil && !receiptOK && resp.Body != nil {
				opts.ExternalByteAccounting = false
				resp.Body = newWatchUninspectedBody(resp.Body, resp.Body, opts, receiptEmissionFailedLayer, "required decision evidence unavailable")
			}
			return err
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			failed = true
			if info, reason, blocked := o.upstreamRefusal(r, err); blocked {
				writeBlockedError(w, info, "enforced in watch-only: "+reason, http.StatusForbidden)
				return
			}
			if errors.Is(err, errWatchResponseCoreFloor) {
				o.observe(scannerLabelA2A, "core credential floor", config.ActionBlock, 0, true)
				o.receipt(r, config.ActionBlock, scannerLabelA2A, "audit safety floor enforced")
				http.Error(w, "enforced in watch-only: audit safety floor", http.StatusForbidden)
				return
			}
			o.observe("upstream", "upstream request could not be completed", config.ActionBlock, 0, true)
			http.Error(w, "enforced in watch-only: upstream unavailable", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
	if o.Intercept != nil {
		recordDeliveredIssuerCookies(o.Intercept, r, deliveredResponse, !failed)
	}
	if o.Budget != nil {
		_ = o.Budget.RecordRequest(r.URL.Hostname(), 0)
	}
	if !failed {
		o.Metrics.RecordAllowed(time.Since(start), agentAnonymous)
	}
}

func watchAuthorityAllowed(w http.ResponseWriter, r *http.Request, o watchHTTPOptions) bool {
	if err := watchAuthorityError(r, o); err != nil {
		writeBlockedError(w, blockInfoFor(blockreason.AuthorityMismatch, blockLayerAuthority), "enforced in watch-only: authority verification failed", http.StatusForbidden)
		return false
	}
	return true
}

func watchAuthorityError(r *http.Request, o watchHTTPOptions) error {
	if o.Proxy == nil {
		return nil
	}
	ref, refErr := consumeAuthorityHeader(r)
	agent := o.Agent
	if agent == "" {
		agent = agentAnonymous
	}
	err := o.Proxy.authorizeForward(r.Context(), ref, refErr, authority.Request{
		Actor:  agent,
		Action: string(receipt.ClassifyHTTP(r.Method)), Destination: r.URL.String(),
	}, audit.NewMethodLogContext(r.Method), o.Transport)
	if err != nil {
		o.observe(blockLayerAuthority, "authority verification failed", config.ActionBlock, 0, true)
		o.receipt(r, config.ActionBlock, blockLayerAuthority, "authority verification failed")
	}
	return err
}

// upstreamRefusal shares the typed dial and redirect refusal contract used by
// the enforcing HTTP paths. Transport failures remain upstream errors.
func (o watchHTTPOptions) upstreamRefusal(r *http.Request, err error) (blockreason.Info, string, bool) {
	var ssrfErr *ssrfDialBlockError
	if errors.As(err, &ssrfErr) {
		o.observe(scanner.ScannerSSRF, string(ssrfErr.reason), config.ActionBlock, 0, true)
		o.receipt(r, config.ActionBlock, scanner.ScannerSSRF, string(ssrfErr.reason))
		return ssrfErr.blockInfo().WithRequestID(o.RequestID), string(ssrfErr.reason), true
	}
	if blockedErr, ok := blockedRequestErrorFrom(err); ok {
		o.observe(blockedErr.layer, blockedErr.reason, config.ActionBlock, 0, true)
		target := r
		if blockedErr.target != "" {
			if redirected, parseErr := http.NewRequestWithContext(r.Context(), r.Method, blockedErr.target, nil); parseErr == nil {
				target = redirected
			}
		}
		o.receipt(target, config.ActionBlock, blockedErr.layer, blockedErr.decisivePattern())
		return redirectBlockedInfo(blockedErr).WithRequestID(o.RequestID), blockedErr.reason, true
	}
	return blockreason.Info{}, "", false
}
