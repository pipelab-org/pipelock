// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const gitReceivePackService = "git-receive-pack"

// gitPushAllowlistReason is the fixed refusal text for a visible smart-HTTP
// push the allowlist does not accept. It carries no repository or URL: both
// are taken from the request.
const gitPushAllowlistReason = "git push to non-allowlisted repo"

type gitPushDecision struct {
	Block bool
	Repo  string
	// AllowlistMismatch is the positive origin mark. It is set only when a
	// fully parsed smart-HTTP push missed a fully evaluated, non-empty
	// allowlist of usable patterns. An empty list, a list with no usable
	// pattern, and a pattern that cannot be evaluated stay unmarked, and an
	// unmarked refusal still refuses in audit mode.
	AllowlistMismatch bool
	Reason            string
}

func evaluateGitPushAllowlist(cfg config.GitProtection, method string, u *url.URL) gitPushDecision {
	if method != http.MethodPost {
		return gitPushDecision{}
	}
	if !cfg.Enabled || u == nil {
		return gitPushDecision{}
	}
	repo, ok := gitPushRepoFromURL(u)
	if !ok {
		return gitPushDecision{}
	}
	if len(cfg.AllowedPushRepos) == 0 {
		return gitPushDecision{Block: true, Repo: repo, Reason: gitPushAllowlistReason}
	}
	allowed, evaluated := gitPushRepoAllowed(repo, cfg.AllowedPushRepos)
	if allowed {
		return gitPushDecision{}
	}
	return gitPushDecision{
		Block:             true,
		Repo:              repo,
		Reason:            gitPushAllowlistReason,
		AllowlistMismatch: evaluated,
	}
}

func gitPushRepoFromURL(u *url.URL) (string, bool) {
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return "", false
	}
	path := strings.TrimPrefix(u.Path, "/")
	if path == "" {
		return "", false
	}
	var repoPath string
	switch {
	case strings.HasSuffix(path, "/"+gitReceivePackService):
		repoPath = strings.TrimSuffix(path, "/"+gitReceivePackService)
	case strings.HasSuffix(path, "/info/refs") && u.Query().Get("service") == gitReceivePackService:
		repoPath = strings.TrimSuffix(path, "/info/refs")
	default:
		return "", false
	}
	repoPath = strings.TrimSuffix(repoPath, ".git")
	repoPath = strings.Trim(repoPath, "/")
	if repoPath == "" {
		return "", false
	}
	return host + "/" + strings.ToLower(repoPath), true
}

// gitPushRepoAllowed reports whether one usable pattern matched. evaluated is
// true only when every non-empty pattern was applied. A match wins even when
// another pattern cannot be evaluated. A list of only blank entries is not
// evaluated: it is the empty allowlist after trimming.
func gitPushRepoAllowed(repo string, allowlist []string) (allowed, evaluated bool) {
	repo = strings.ToLower(strings.TrimSpace(repo))
	sawPattern := false
	evaluated = true
	for _, raw := range allowlist {
		pattern := strings.ToLower(strings.TrimSpace(raw))
		if pattern == "" {
			continue
		}
		sawPattern = true
		matched, err := gitPushRepoPatternMatch(pattern, repo)
		if err != nil {
			evaluated = false
			continue
		}
		if matched {
			return true, true
		}
	}
	if !sawPattern {
		return false, false
	}
	return false, evaluated
}

func gitPushRepoPatternMatch(pattern, value string) (bool, error) {
	if pattern == value {
		return true, nil
	}
	parts := strings.Split(pattern, "/")
	if len(parts) == 2 && parts[1] == "*" && strings.HasPrefix(value, parts[0]+"/") {
		return true, nil
	}
	return filepath.Match(pattern, value)
}

// auditEnforcementOff reports that both the admitted config and the live
// config have enforcement off. A nil proxy, a nil config on either side, or
// enforcement on either side refuses. Request policy and the git-push
// allowlist share this rule.
func (p *Proxy) auditEnforcementOff(admitted *config.Config) bool {
	if p == nil || admitted == nil || admitted.EnforceEnabled() {
		return false
	}
	live := p.cfgPtr.Load()
	return live != nil && !live.EnforceEnabled()
}

// gitPushAuditLift reports whether this refusal is a configured allowlist
// mismatch that audit mode observes.
func (p *Proxy) gitPushAuditLift(admitted *config.Config, d gitPushDecision) bool {
	return d.Block && d.AllowlistMismatch && p.auditEnforcementOff(admitted)
}

// refuseGitPushAllowlist reports whether the caller must refuse. A configured
// mismatch is observed when both configs have enforcement off: the anomaly is
// recorded and the request continues. Every other refusal is logged as a
// blocked event and returned as a block. blockedDetail is the enforce-mode
// reason, unchanged from the call site.
func (p *Proxy) refuseGitPushAllowlist(admitted *config.Config, logger *audit.Logger, ctx audit.LogContext, d gitPushDecision, blockedDetail string) (block, observed bool) {
	if !d.Block {
		return false, false
	}
	if p.gitPushAuditLift(admitted, d) {
		p.recordGitPushObservation(logger, ctx, d)
		return false, true
	}
	if logger != nil {
		logger.LogBlockedDetail(ctx, scanner.AuditGitProtection, blockedDetail, audit.BlockDetail{Class: forwardDenialClass(forwardDenialGitPush)})
	}
	return true, false
}

func (p *Proxy) recordGitPushObservation(logger *audit.Logger, ctx audit.LogContext, d gitPushDecision) {
	if p != nil && p.metrics != nil {
		p.metrics.RecordGitPushDecision(requestPolicyAuditAction)
	}
	if logger != nil {
		logger.LogAnomaly(ctx, scanner.AuditGitProtection, d.Reason+requestPolicyWouldBlockSuffix, 0)
	}
}
