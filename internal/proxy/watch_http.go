// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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
	DeferClean       bool
	Refusal          *watchRequestCoverage
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
	AgentLabel       string
	ClientIP         string
	RequestID        string
	KillSwitch       *killswitch.Controller
	MaxResponseBytes int64

	// ReceiptShard is the receipt chain chosen at admission. With several
	// chains a receipt without it cannot be emitted.
	ReceiptShard receipt.EmitOpts
	// EnvelopeEmitter signs the outbound request when mediation envelopes are
	// enabled, exactly as the enforcing forward and fetch paths do.
	EnvelopeEmitter *envelope.Emitter
	// ActionID correlates the signed envelope with the admission receipt.
	ActionID string
	// Generation is the watch-only mode generation the request was admitted
	// under. Shadow-score updates from an older generation are discarded.
	Generation uint64

	findings       *watchFindingLog
	requestFinding *atomic.Bool
}

type watchModeContextKey struct{}

// errWatchReceiptUnavailable refuses release of a response whose finding could
// not be recorded in a required receipt.
var errWatchReceiptUnavailable = errors.New("enforced in watch-only: required receipt unavailable")

type watchFinding struct{ layer, reason, action string }

// watchFindingLog collects the would-block findings of one exchange so they can
// be recorded in signed receipts before the affected traffic is released.
type watchFindingLog struct {
	mu    sync.Mutex
	items []watchFinding
	seen  map[watchFinding]struct{}
}

// watchFindingAction reports whether an observed action is a policy finding
// (as opposed to an inspection gap, an escalation edge or a clean decision).
func watchFindingAction(action string) bool {
	switch action {
	case config.ActionBlock, config.ActionStrip, config.ActionAsk, config.ActionWarn:
		return true
	}
	return false
}

func (l *watchFindingLog) add(layer, reason, action string) {
	if l == nil || !watchFindingAction(action) {
		return
	}
	f := watchFinding{layer: layer, reason: reason, action: action}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, dup := l.seen[f]; dup {
		return
	}
	if l.seen == nil {
		l.seen = make(map[watchFinding]struct{})
	}
	l.seen[f] = struct{}{}
	l.items = append(l.items, f)
}

func (l *watchFindingLog) drain() []watchFinding {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	items := l.items
	l.items = nil
	return items
}

func (o watchHTTPOptions) observe(layer, reason, action string, count int64, enforced bool) {
	if !enforced && watchFindingAction(action) {
		if o.requestFinding != nil {
			o.requestFinding.Store(true)
		}
		o.findings.add(layer, reason, action)
	}
	watchObservationFor(o.RequestID, o.Logger, o.Metrics, o.Transport, layer, reason, action, count, enforced)
}

func (o watchHTTPOptions) agentLabel() string {
	if o.AgentLabel != "" {
		return o.AgentLabel
	}
	return agentAnonymous
}

// recordRefusal counts an enforced watch-only refusal in the ordinary blocked
// request counters, so /stats and requests_total include it once.
func (o watchHTTPOptions) recordRefusal(r *http.Request, layer string, start time.Time) {
	if o.Metrics != nil {
		o.Metrics.RecordBlocked(r.URL.Hostname(), layer, time.Since(start), o.agentLabel())
	}
}

func (o watchHTTPOptions) receipt(r *http.Request, verdict, layer, reason string) bool {
	return o.receiptWithID(r, receipt.NewActionID(), verdict, layer, reason)
}

func (o watchHTTPOptions) receiptWithID(r *http.Request, actionID, verdict, layer, reason string) bool {
	if o.Proxy == nil || o.Proxy.receiptEmitterPtr.Load() == nil {
		if o.Config.FlightRecorder.RequireReceipts {
			o.observe(receiptEmissionFailedLayer, "receipt recorder unavailable", config.ActionBlock, 0, true)
			return false
		}
		return true
	}
	opts := withReceiptShard(withReceiptConfig(receipt.EmitOpts{
		ActionID: actionID, Verdict: verdict,
		Layer: layer, Pattern: "watch-only: " + audit.RedactWatchOnlyReason(reason), Transport: o.Transport,
		Method: r.Method, Target: r.URL.String(), RequestID: o.RequestID, Agent: o.Agent,
	}, o.Config), o.ReceiptShard)
	if err := o.Proxy.emitAllowPathReceipt(o.Config, opts); err != nil {
		action := "uninspected"
		if o.Config.FlightRecorder.RequireReceipts {
			action = config.ActionBlock
		}
		o.observe(receiptEmissionFailedLayer, "receipt could not be recorded", action, 0, o.Config.FlightRecorder.RequireReceipts)
		return false
	}
	return true
}

// confirmFindings records each pending would-block finding in a signed receipt.
// With required receipts, a finding that cannot be recorded refuses release.
func (o watchHTTPOptions) confirmFindings(r *http.Request) bool {
	for _, f := range o.findings.drain() {
		if !o.receipt(r, config.ActionWarn, f.layer, f.reason) && o.Config.FlightRecorder.RequireReceipts {
			return false
		}
	}
	return true
}

func (o watchHTTPOptions) killed() bool {
	if o.KillSwitch == nil {
		return false
	}
	return o.KillSwitch.IsActive()
}

// watchAdmission is the outcome of the request-side checks. Core is true when
// an audit-mode floor or access control refuses the request; Result is the URL
// scan, kept so the allowed destination's resolved addresses can be carried to
// the dial.
type watchAdmission struct {
	Core   bool
	Result scanner.Result
}

// watchRequestDecision joins the existing scanners and policy evaluator. It
// runs before any egress and retains the audit-mode secret and host floor.
func watchRequestDecision(r *http.Request, o watchHTTPOptions) bool {
	return watchAdmit(r, o).Core
}

func (o *watchHTTPOptions) refuse(layer, reason string) {
	if o.Refusal != nil && o.Refusal.refusalLayer == "" {
		o.Refusal.refusalLayer, o.Refusal.refusalReason = layer, reason
	}
}

func watchAdmit(r *http.Request, o watchHTTPOptions) watchAdmission {
	sc, cfg := o.Scanner, o.Config
	if o.Budget != nil {
		if err := o.Budget.CheckAdmission(r.URL.Hostname()); err != nil {
			o.observe("budget", "per-agent admission budget exceeded", config.ActionBlock, 0, false)
		}
	}

	if sc == nil {
		o.observe(scannerLabelUnavailable, scannerPatternUnavailable, config.ActionBlock, 0, true)
		return watchAdmission{Core: true}
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
	// A relay that follows a URL-shaped query value reaches that destination
	// without this proxy dialing it, so the dial-time SSRF guard cannot refuse
	// it. The full scan stops at its first failing stage, so check the nested
	// SSRF floor on its own whenever the scan did not already report it.
	if !result.Allowed {
		nested := result
		if !scanner.IsNestedSSRFResult(nested) {
			nested = sc.ScanNestedSSRFFloor(r.Context(), r.URL.String())
		}
		if scanner.IsNestedSSRFResult(nested) {
			core = true
			o.observe(nested.Scanner, nested.Reason, config.ActionBlock, 0, true)
			o.refuse(nested.Scanner, nested.Reason)
		}
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
	headerFinding, headerSignal := false, session.SignalWarning
	if headers != nil && !headers.Clean {
		for _, match := range headers.DLPMatches {
			enforced := shouldHardBlockRequestDLP([]scanner.TextDLPMatch{match}, cfg)
			core = core || enforced
			action := headers.Action
			if enforced {
				action = config.ActionBlock
			}
			// Same mapping as the enforcing path: a finding that would block
			// is a block signal, anything else a warning.
			headerFinding = true
			if action == config.ActionBlock {
				headerSignal = session.SignalBlock
			}
			o.observe("dlp_header", match.PatternName, action, 0, enforced)
		}
		if len(headers.DLPMatches) == 0 {
			core = true
			o.observe("dlp_header", "headers could not be completely inspected", config.ActionBlock, 0, true)
		}
	}
	coverage := o.Refusal
	if coverage == nil {
		coverage = &watchRequestCoverage{}
	}
	if watchRequestBody(r.Context(), r, watchRequestOptions{Coverage: coverage, Config: cfg, Scanner: sc, Logger: o.Logger, Metrics: o.Metrics, Transport: o.Transport, RequestID: o.RequestID, Proxy: o.Proxy, Observe: o.observe}) {
		core = true
	}
	if gitPush := evaluateGitPushAllowlist(cfg.GitProtection, r.Method, r.URL); gitPush.Block {
		// The Git push allowlist is a destination access control that the
		// enforcing path applies in every mode, so it is not an observation.
		core = true
		o.observe("git_protection", gitPush.Reason, config.ActionBlock, 0, true)
		o.refuse("git_protection", gitPush.Reason)
	}
	if o.Proxy != nil {
		p := o.Proxy
		p.recordSessionActivityWithUserAgent(sessionActivityOptions{
			ClientIP: o.ClientIP, Agent: o.Agent, Hostname: r.URL.Hostname(),
			RequestID: o.RequestID, UserAgent: r.UserAgent(), ActorAuth: o.ActorAuth,
			Result: result, Config: cfg, Logger: o.Logger, ObserveOnly: true, DeferClean: o.DeferClean,
		})
		// Read the existing session state; observation never raises its enforcement
		// level or enters airlock. Findings remain distinct from enforced signals.
		scope := adaptiveScopeForHost(r.URL.Hostname())
		if sm := p.sessionMgrPtr.Load(); sm != nil {
			rec := sm.GetOrCreate(sessionKeyFor(cfg, o.Agent, o.ClientIP, o.ActorAuth))
			if rec == nil {
				o.observe(sessionCapacityLayer, "session observation capacity exhausted", "uninspected", 0, false)
			} else {
				if headerFinding && cfg.AdaptiveEnforcement.Enabled && !isAdaptiveExempt(r.URL.Hostname(), cfg.AdaptiveEnforcement.ExemptDomains) {
					if changed, from, to := rec.ObserveWatchOnlySignalAt(o.Generation, scope, headerSignal, &cfg.AdaptiveEnforcement, decide.EscalationParams{
						Threshold: cfg.AdaptiveEnforcement.EscalationThreshold, ClientIP: o.ClientIP, RequestID: o.RequestID,
					}); changed {
						o.observe(adaptiveEnforcementLayer, "adaptive level would change from "+from+" to "+to, "escalate", 0, false)
					}
				}
				level := rec.EffectiveEscalationLevel(scope)
				action := config.ActionAllow
				if !result.Allowed {
					action = config.ActionWarn
				}
				if decide.UpgradeAction(action, level, &cfg.AdaptiveEnforcement) != action {
					o.observe(adaptiveEnforcementLayer, "adaptive action upgrade observed", "escalate", 0, false)
				}
				tier := airlockTierForScope(rec, scope)
				if allowed, reason := ClassifyAction(tier, r.Method, o.Transport, true); !allowed {
					o.observe("airlock", reason, config.ActionBlock, 0, false)
				}
			}
			// Taint is recorded and read under the key the response observer
			// writes, so exposure from an earlier response informs this request.
			if taintRec := sm.GetOrCreate(responseTaintSessionKey(cfg, o.Agent, o.ClientIP, o.ActorAuth)); taintRec != nil {
				td := evaluateHTTPTaint(cfg, taintRec, r.Method, r.URL)
				if td.Result.Decision != session.PolicyAllow {
					o.observe("taint", td.Result.Reason, td.Result.Decision.String(), 0, false)
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
				WatchOnly: true,
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
			WatchObserve: o.observe,
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
	return watchAdmission{Core: core, Result: result}
}

// watchOutboundContext binds an admitted destination to the dial: a hostname
// the scan resolved and the policy granted must reach the same addresses at
// connection time, which the scan snapshot carries.
func watchOutboundContext(ctx context.Context, o watchHTTPOptions, target *http.Request, adm watchAdmission) context.Context {
	ctx = context.WithValue(ctx, watchModeContextKey{}, o)
	return withAllowedSSRFDialScanSnapshot(ctx, o.Scanner, target.URL.Hostname(), effectiveURLPort(target.URL), adm.Result)
}

// signWatchOutbound attaches the mediation envelope (and RFC 9421 signature
// when a signer is installed) to an admitted request, as the enforcing forward
// and fetch paths do. A signing failure refuses the request.
func (o watchHTTPOptions) signWatchOutbound(out *http.Request, method string) error {
	if o.EnvelopeEmitter == nil {
		return nil
	}
	agent := o.Agent
	if agent == "" {
		agent = agentAnonymous
	}
	if err := o.EnvelopeEmitter.InjectAndSign(out, nil, envelope.BuildOpts{
		ActionID:   o.ActionID,
		Action:     string(receipt.ClassifyHTTP(method)),
		Verdict:    config.ActionAllow,
		SideEffect: string(receipt.SideEffectFromMethod(method)),
		Actor:      agent,
		ActorAuth:  o.ActorAuth,
		PolicyHash: envelope.PolicyHashFromHex(o.Config.CanonicalPolicyHash()),
	}); err != nil {
		return newEnvelopeBlockedRequest(err)
	}
	return nil
}

// watchForwardHost keeps the client's Host header when it already names the
// admitted authority (same host, same effective port), so the forwarded
// representation is unchanged, and otherwise binds it to the admitted URL.
func watchForwardHost(inHost string, admitted *url.URL) string {
	host, port := inHost, effectiveURLPort(admitted)
	if h, p, err := net.SplitHostPort(inHost); err == nil {
		host, port = h, p
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if strings.EqualFold(host, strings.TrimSuffix(admitted.Hostname(), ".")) && port == effectiveURLPort(admitted) {
		return inHost
	}
	return admitted.Host
}

// serveWatchHTTP keeps the original representation while invoking the same
// scanner functions as enforcement. ReverseProxy owns RFC hop-by-hop handling
// handling; uninspectable upgrades are refused before any stream is relayed.
func serveWatchHTTP(w http.ResponseWriter, r *http.Request, o watchHTTPOptions) {
	start := time.Now()
	if o.ActionID == "" {
		o.ActionID = receipt.NewActionID()
	}
	o.findings, o.requestFinding = &watchFindingLog{}, new(atomic.Bool)
	if o.Proxy != nil && !o.InboundVerified {
		if err := o.Proxy.verifyInboundEnvelope(r, o.Config); err != nil {
			o.observe(blockLayerMediationEnvelope, inboundEnvelopeFailurePattern(err), config.ActionBlock, 0, true)
			o.recordRefusal(r, blockLayerMediationEnvelope, start)
			writeBlockedError(w, blockInfoFor(blockreason.EnvelopeVerifyFailed, blockLayerMediationEnvelope), "enforced in watch-only: inbound authentication failed", http.StatusForbidden)
			return
		}
	}

	if !watchAuthorityAllowed(w, r, o, start) {
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
	o.DeferClean = true
	o.Refusal = &watchRequestCoverage{}
	adm := watchAdmit(r, o)
	if adm.Core {
		layer, reason, code := scannerLabelBodyDLP, "audit safety floor", blockreason.DLPMatch
		if o.Refusal.refusalLayer != "" {
			layer, reason = o.Refusal.refusalLayer, o.Refusal.refusalReason
			code = reasonFromScanner(layer)
			if layer == "git_protection" {
				code = blockreason.RequestPolicyDeny
			}
		}
		o.receipt(r, config.ActionBlock, layer, reason)
		o.recordRefusal(r, layer, start)
		writeBlockedError(w, blockInfoFor(code, layer).WithRequestID(o.RequestID), "enforced in watch-only: "+reason, http.StatusForbidden)
		return
	}
	if o.killed() {
		o.observe("kill_switch", killSwitchActiveReason, config.ActionBlock, 0, true)
		o.recordRefusal(r, "kill_switch", start)
		writeBlockedError(w, blockInfoFor(blockreason.KillSwitchActive, "kill_switch"), "enforced in watch-only: kill switch active", http.StatusServiceUnavailable)
		return
	}
	r = r.WithContext(watchOutboundContext(r.Context(), o, r, adm))
	findingsOK := o.confirmFindings(r)
	receiptOK := o.receiptWithID(r, o.ActionID, config.ActionAllow, "watch_only", "request admitted without policy rewriting")
	if (!findingsOK || !receiptOK) && o.Config.FlightRecorder.RequireReceipts {
		o.observe(receiptEmissionFailedLayer, "required receipt unavailable", config.ActionBlock, 0, true)
		o.recordRefusal(r, receiptEmissionFailedLayer, start)
		http.Error(w, "enforced in watch-only: required receipt unavailable", http.StatusServiceUnavailable)
		return
	}
	// Evidence gaps for this exchange are counted when bytes are delivered.
	evidenceOK := receiptOK && findingsOK
	var responseFinding atomic.Bool
	var responseKinds watchKinds
	var responseSession, taintSession *SessionState
	if o.Proxy != nil {
		if sm := o.Proxy.sessionMgrPtr.Load(); sm != nil {
			taintSession = sm.GetOrCreate(responseTaintSessionKey(o.Config, o.Agent, o.ClientIP, o.ActorAuth))
			if o.Config.SessionProfiling.Enabled {
				responseSession = sm.GetOrCreate(sessionKeyFor(o.Config, o.Agent, o.ClientIP, o.ActorAuth))
			}
		}
	}
	var deliveredResponse *http.Response
	failed := false
	var upstream http.RoundTripper = o.Upstream
	if upstream == nil {
		upstream = http.DefaultTransport
	}
	// A silent upstream must not hold the request open after headers. The
	// no-progress bound is the one the reverse and intercept paths use; streams
	// and upgrades stay exempt inside the wrapper.
	if seconds := o.Config.FetchProxy.TimeoutSeconds; seconds > 0 {
		upstream = watchStallTransport{base: upstream, stall: time.Duration(seconds) * time.Second}
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			req.Out.RequestURI = ""
			req.Out.URL.RawQuery = req.In.URL.RawQuery
			// The scanned URL authority is the destination policy admitted. An
			// HTTP/2 request can carry a different Host alongside an absolute
			// target, which a virtual-host gateway would route on.
			req.Out.Host = watchForwardHost(req.In.Host, req.Out.URL)
			// Proxy identity assertions were consumed by stripInternalIdentity;
			// Rewrite must not manufacture a replacement identity.
		},
		Transport: watchEvidenceTransport{base: upstream, sign: func(out *http.Request) error { return o.signWatchOutbound(out, r.Method) }},
		ModifyResponse: func(resp *http.Response) error {
			deliveredResponse = resp
			if resp.Request == nil {
				resp.Request = r
			}
			if resp.StatusCode == http.StatusSwitchingProtocols {
				o.observe("websocket", "upgraded stream requires a scanning relay", config.ActionBlock, 0, true)
				return errors.New("enforced in watch-only: uninspectable upgraded stream")
			}
			opts := watchResponseOptions{ExternalByteAccounting: !evidenceOK, Config: o.Config, Scanner: o.Scanner, Logger: o.Logger, Metrics: o.Metrics, Transport: o.Transport, MaxBytes: o.MaxResponseBytes, RequestID: o.RequestID}
			opts.OnObservation = o.responseObserver(r, responseSession, &responseFinding)
			opts.OnFinding = o.findings.add
			opts.OnKinds = responseKinds.merge
			if o.Config.FlightRecorder.RequireReceipts {
				opts.ConfirmFinding = func(finding error) error {
					if !o.receipt(r, config.ActionWarn, LayerSSEStream, finding.Error()) {
						return errors.New("required SSE finding receipt unavailable")
					}
					return nil
				}
			}
			if o.Proxy != nil {
				opts.Shield = o.Proxy.shieldEngine
				opts.A2ACardBaseline = o.Proxy.a2aCardBaseline
			}
			err := watchResponseBody(r.Context(), resp, opts)
			if err != nil {
				return err
			}
			// A buffered response finding is released only once recorded.
			if !o.confirmFindings(r) && o.Config.FlightRecorder.RequireReceipts {
				_ = resp.Body.Close()
				return errWatchReceiptUnavailable
			}
			if !evidenceOK && resp.Body != nil {
				opts.ExternalByteAccounting = false
				resp.Body = newWatchUninspectedBody(resp.Body, resp.Body, opts, receiptEmissionFailedLayer, "required decision evidence unavailable")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			failed = true
			if errors.Is(err, errWatchReceiptUnavailable) {
				o.recordRefusal(r, receiptEmissionFailedLayer, start)
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			if info, reason, blocked := o.upstreamRefusal(r, err); blocked {
				o.recordRefusal(r, info.Layer, start)
				writeBlockedError(w, info, "enforced in watch-only: "+reason, http.StatusForbidden)
				return
			}
			if errors.Is(err, errWatchResponseCoreFloor) {
				o.observe(scannerLabelA2A, "core credential floor", config.ActionBlock, 0, true)
				o.receipt(r, config.ActionBlock, scannerLabelA2A, "audit safety floor enforced")
				o.recordRefusal(r, scannerLabelA2A, start)
				http.Error(w, "enforced in watch-only: audit safety floor", http.StatusForbidden)
				return
			}
			o.observe("upstream", "upstream request could not be completed", config.ActionBlock, 0, true)
			http.Error(w, "enforced in watch-only: upstream unavailable", http.StatusBadGateway)
		},
	}
	delivered := &watchDeliveryWriter{ResponseWriter: w}
	rp.ServeHTTP(delivered, r)
	if o.Scanner != nil {
		o.Scanner.RecordRequest(r.URL.Hostname(), int(delivered.bytes))
	}
	if o.Intercept != nil {
		recordDeliveredIssuerCookies(o.Intercept, r, deliveredResponse, !failed)
	}
	if o.Budget != nil {
		_ = o.Budget.RecordRequest(r.URL.Hostname(), 0)
		_ = o.Budget.RecordBytes(delivered.bytes)
	}
	if deliveredResponse != nil && deliveredResponse.Request != nil && taintSession != nil {
		observeHTTPResponseFindings(taintSession, o.Config, deliveredResponse.Request.URL.String(), responseTaintContentType(deliveredResponse.Header), "forward_response", responseKinds.list())
	}
	// Clean credit is withheld for the whole exchange when either direction
	// recorded a finding: it would decay the very score that recorded it.
	if !failed && !responseFinding.Load() && !o.requestFinding.Load() && responseSession != nil {
		responseSession.ObserveWatchOnlyCleanAt(o.Generation, adaptiveScopeForHost(r.URL.Hostname()), &o.Config.AdaptiveEnforcement)
	}
	if !failed {
		o.Metrics.RecordAllowed(time.Since(start), o.agentLabel())
	}
}

// watchKinds accumulates the finding kinds of one response for taint.
type watchKinds struct {
	mu    sync.Mutex
	kinds []session.HostileFindingKind
}

func (k *watchKinds) merge(kinds []session.HostileFindingKind) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.kinds = session.MergeFindingKinds(k.kinds, kinds)
}

func (k *watchKinds) list() []session.HostileFindingKind {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]session.HostileFindingKind(nil), k.kinds...)
}

// responseObserver feeds the existing shadow scoring for response findings.
func (o watchHTTPOptions) responseObserver(r *http.Request, responseSession *SessionState, responseFinding *atomic.Bool) func(string, string) {
	return func(layer, action string) {
		if action == config.ActionAllow {
			return
		}
		responseFinding.Store(true)
		if responseSession == nil || !o.Config.AdaptiveEnforcement.Enabled || isAdaptiveExempt(r.URL.Hostname(), o.Config.AdaptiveEnforcement.ExemptDomains) || isResponseScanExempt(r.URL.Hostname(), o.Config.ResponseScanning.ExemptDomains) {
			return
		}
		var signal session.SignalType
		switch action {
		case config.ActionStrip:
			signal = session.SignalStrip
		case config.ActionBlock, config.ActionAsk:
			signal = session.SignalBlock
		case config.ActionWarn:
			signal = session.SignalWarning
		default:
			return
		}
		if changed, from, to := responseSession.ObserveWatchOnlySignalAt(o.Generation, adaptiveScopeForHost(r.URL.Hostname()), signal, &o.Config.AdaptiveEnforcement, decide.EscalationParams{DenialScanner: layer, PolicyHash: o.Config.CanonicalPolicyHash()}); changed {
			o.observe(adaptiveEnforcementLayer, "adaptive level would change from "+from+" to "+to, "escalate", 0, false)
		}
	}
}

func watchAuthorityAllowed(w http.ResponseWriter, r *http.Request, o watchHTTPOptions, start time.Time) bool {
	if err := watchAuthorityError(r, o); err != nil {
		o.recordRefusal(r, blockLayerAuthority, start)
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
		if blockedErr.layer == blockLayerMediationEnvelope && !strings.HasPrefix(blockedErr.reason, "redirect blocked") {
			return blockInfoFor(blockreason.OutboundEnvelopeFailed, blockedErr.layer).WithRequestID(o.RequestID), blockedErr.reason, true
		}
		return redirectBlockedInfo(blockedErr).WithRequestID(o.RequestID), blockedErr.reason, true
	}
	return blockreason.Info{}, "", false
}
