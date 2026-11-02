// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"strings"
)

// urlUserinfoValues preserves both the escaped spelling and decoded fields of
// RFC 3986 section 3.2.1 userinfo. HTTP senders should avoid this deprecated
// carrier (RFC 9110 section 4.2.4); supported legacy Basic clients still need
// the same inspection as other URL components. PathUnescape preserves '+'.
// joined adds the decoded "username:password" pair, whose noise-stripped view
// rejoins a credential split at the colon, as path and query views already do.
func urlUserinfoValues(u *url.URL, joined bool) []dlpTarget {
	if u.User == nil {
		return nil
	}
	// The second field is recovered from the escaped form so it reads as
	// inspected content: String escapes each field and PathUnescape reverses
	// that exactly, matching Userinfo's own decoded value.
	rawUser, rawSecond, hasSecond := strings.Cut(u.User.String(), ":")
	values := []dlpTarget{{rawUser, "url_userinfo_username_escaped", ""}, {u.User.Username(), "url_userinfo_username", ""}}
	if hasSecond {
		second, err := url.PathUnescape(rawSecond)
		if err != nil {
			second = rawSecond
		}
		values = append(values, dlpTarget{rawSecond, "url_userinfo_password_escaped", ""}, dlpTarget{second, "url_userinfo_password", ""})
		if joined {
			values = append(values, dlpTarget{u.User.Username() + ":" + second, "url_userinfo", ""})
		}
	}
	return values
}

// urlUserinfoDLPTargets includes the joined pair. Entropy keeps per-field
// scoring so a benign Basic-auth pair is not judged as one longer string.
func urlUserinfoDLPTargets(u *url.URL, decodes *decodingMemo) []dlpTarget {
	return userinfoTargets(urlUserinfoValues(u, true), decodes)
}

func userinfoTargets(values []dlpTarget, decodes *decodingMemo) []dlpTarget {
	var targets []dlpTarget
	seen := make(map[string]bool)
	for _, source := range values {
		texts := []dlpTarget{source}
		form, percent := IterativeDecode(source.text), normalizePercentUserinfo(source.text)
		if form != source.text {
			texts = append(texts, dlpTarget{form, spanViewLabel("url_decoded", source.viewLabel), ""})
		}
		if percent != source.text && percent != form {
			texts = append(texts, dlpTarget{percent, spanViewLabel("percent_decoded", source.viewLabel), ""})
		}
		for _, target := range texts {
			if target.text == "" || seen[target.text] {
				continue
			}
			seen[target.text] = true
			targets = append(targets, target)
			if stripped := stripURLNoise(target.text); stripped != target.text {
				targets = append(targets, dlpTarget{stripped, spanViewLabel("url_noise_stripped", target.viewLabel), target.text})
			}
			for _, decoded := range decodes.decode(target.text, true) {
				targets = append(targets, dlpTarget{decoded.text, spanViewLabel(decoded.encoding+"_decoded", target.viewLabel), ""})
			}
		}
	}
	return targets
}

func normalizePercentUserinfo(value string) string {
	// Use the shared partial percent decoder without form-style '+' conversion.
	_, percent := urlComponentDecodes(value)
	if percent == "" {
		return value
	}
	return percent
}

func (s *Scanner) checkUserinfoEntropy(u *url.URL) Result {
	if s.entropyThreshold <= 0 {
		return Result{Allowed: true}
	}
	var decodes decodingMemo
	for _, target := range userinfoTargets(urlUserinfoValues(u, false), &decodes) {
		if finding, blocked := s.queryValueEntropy(target.text, 0); blocked {
			return Result{
				Allowed: false, Scanner: ScannerEntropy, Class: ClassHeuristicEntropy,
				Reason: fmt.Sprintf("high entropy URL userinfo (%.2f > %.2f threshold)", finding.entropy, s.entropyThreshold),
				Score:  math.Min(finding.entropy/8.0, 1.0),
			}
		}
	}
	return Result{Allowed: true}
}

// textURLUserinfoMatches joins the component views to text DLP without making
// a network request or inferring an audience from a URL inside untrusted text.
func (s *Scanner) textURLUserinfoMatches(ctx context.Context, text string, decodes *decodingMemo, opts textDLPOptions) []TextDLPMatch {
	var matches []TextDLPMatch
	opts.skipURLUserinfo = true
	opts.emitWarns = false
	for _, token := range textURLTokenRe.FindAllString(text, -1) {
		u, err := url.Parse(token)
		if err != nil {
			u = &url.URL{User: lenientURLUserinfo(token)}
		}
		if u.User == nil {
			continue
		}
		for _, target := range urlUserinfoDLPTargets(u, decodes) {
			result := s.scanTextForDLPWithDecodes(ctx, target.text, opts, decodes)
			for _, match := range append(result.Matches, result.InformationalMatches...) {
				match.span.ViewLabel = spanViewLabel(match.span.ViewLabel, target.viewLabel)
				matches = append(matches, match)
			}
		}
		if opts.patterns != textDLPCardPatterns && !s.checkUserinfoEntropy(u).Allowed {
			const pattern = "URL Userinfo Entropy"
			matches = append(matches, TextDLPMatch{
				PatternName: pattern, Severity: "high",
				span: newMatchSpan(0, len(u.User.String()), "url_userinfo", pattern, "", ""),
			})
		}
	}
	return matches
}

// lenientURLUserinfo recovers userinfo from a URL token that url.Parse refuses,
// such as one with a non-ASCII byte or a malformed percent escape. Other HTTP
// clients accept those tokens and still send the pair as Basic credentials,
// so text inspection cannot depend on Go's stricter parser. The authority ends
// at the first '/', '?' or '#', and userinfo ends at its last '@' (RFC 3986
// section 3.2). Fields keep their spelling; the target views decode them.
func lenientURLUserinfo(token string) *url.Userinfo {
	_, authority, ok := strings.Cut(token, "://")
	if !ok {
		return nil
	}
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return nil
	}
	if user, second, hasSecond := strings.Cut(authority[:at], ":"); hasSecond {
		return url.UserPassword(user, second)
	}
	return url.User(authority[:at])
}
