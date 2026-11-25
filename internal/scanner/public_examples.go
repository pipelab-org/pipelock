// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/sha256"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/carddlp"
)

func (p *compiledPattern) forReceipt() *compiledPattern {
	if !p.genericCard {
		return p
	}
	copyPattern := *p
	copyPattern.cardReceipt = true
	return &copyPattern
}

// withPublicExamples records exact matches and lets the matcher keep looking
// for enforcing matches in the same view.
// Existing per-span exclusions still apply.
func (p *compiledPattern) withPublicExamples(text string, example *textByteSpan) *compiledPattern {
	if !p.genericCard {
		return p
	}
	pattern := *p
	pattern.skipSpan = func(start, end int) bool {
		if p.skipSpan != nil && p.skipSpan(start, end) {
			return true
		}
		if !p.isPublicExample(text, start, end) {
			return false
		}
		if example != nil && example.end == 0 {
			*example = textByteSpan{start, end}
		}
		return true
	}
	return &pattern
}

func (p *compiledPattern) isPublicExample(text string, start, end int) bool {
	value := text[start:end]
	if p.cardReceipt {
		value = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(value, "\t", ""), "\r", ""), "\n", "")
	}
	switch {
	case p.genericCard:
		return carddlp.IsPublicTestPAN(value)
	default:
		return false
	}
}

func (p *compiledPattern) textDLPFinding(text, encoding string, start, end int, informational bool) TextDLPMatch {
	confidence := ""
	if p.cardPrefixRetry {
		confidence = "high"
		if p.isPublicExample(text, start, end) {
			confidence = "public_example"
		}
	}
	return TextDLPMatch{
		CardConfidence: confidence, keywordGated: p.keywords != nil,
		genericCard:                         p.genericCard,
		cardPrefixRetry:                     p.cardPrefixRetry,
		PatternName:                         p.name,
		Severity:                            p.severity,
		Encoded:                             encoding,
		Bundle:                              p.bundle,
		BundleVersion:                       p.bundleVersion,
		Warn:                                p.warn || informational,
		informational:                       informational,
		credentialAudienceHosts:             p.credentialAudienceHosts,
		credentialAudienceAuthorizationOnly: p.credentialAudienceAuthorizationOnly,
		credentialAudienceCarrierMask:       p.credentialAudienceCarrierMask,
		credentialAudienceGitHosts:          p.credentialAudienceGitHosts,
		credentialAudienceRegistryHosts:     p.credentialAudienceRegistryHosts,
		valueIdentity:                       sha256.Sum256([]byte(text[start:end])),
		hasValueIdentity:                    true,
		span:                                newMatchSpan(start, end, dlpViewLabel(encoding), p.name, p.bundle, p.bundleVersion),
	}
}
