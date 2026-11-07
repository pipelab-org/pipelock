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
func urlUserinfoValues(escapedUser, escapedSecond string, hasSecond, joined bool) []dlpTarget {
	user, err := url.PathUnescape(escapedUser)
	if err != nil {
		user = escapedUser
	}
	values := []dlpTarget{{escapedUser, "url_userinfo_username_escaped", ""}, {user, "url_userinfo_username", ""}}
	if hasSecond {
		second, err := url.PathUnescape(escapedSecond)
		if err != nil {
			second = escapedSecond
		}
		values = append(values, dlpTarget{escapedSecond, "url_userinfo_password_escaped", ""}, dlpTarget{second, "url_userinfo_password", ""})
		if joined {
			values = append(values, dlpTarget{user + ":" + second, "url_userinfo", ""})
		}
	}
	return values
}

func parsedURLUserinfoValues(u *url.URL, joined bool) []dlpTarget {
	if u.User == nil {
		return nil
	}
	user, second, hasSecond := strings.Cut(u.User.String(), ":")
	return urlUserinfoValues(user, second, hasSecond, joined)
}

// urlUserinfoDLPTargets includes the joined pair. Entropy keeps per-field
// scoring so a benign Basic-auth pair is not judged as one longer string.
func urlUserinfoDLPTargets(u *url.URL, decodes *decodingMemo) []dlpTarget {
	return userinfoTargets(parsedURLUserinfoValues(u, true), decodes)
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
			decodes.reassemblyDerive(source.text, target.text)
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
	return s.checkUserinfoValuesEntropy(parsedURLUserinfoValues(u, false))
}

func (s *Scanner) checkUserinfoValuesEntropy(values []dlpTarget) Result {
	if s.entropyThreshold <= 0 {
		return Result{Allowed: true}
	}
	var decodes decodingMemo
	for _, target := range userinfoTargets(values, &decodes) {
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
	if !strings.Contains(text, textURLTokenSeparator) {
		return nil
	}
	var matches []TextDLPMatch
	opts.skipURLUserinfo = true
	opts.emitWarns = false
	kind := decodes.reassemblyDerivedKind(text)
	seen := make(map[string]struct{})
	for _, token := range textURLTokenRe.FindAllString(text, -1) {
		if ctx.Err() != nil {
			return matches
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		var user, second string
		var hasSecond, present bool
		u, err := url.Parse(token)
		if err != nil {
			user, second, hasSecond, present = lenientURLUserinfo(token)
		} else if u.User != nil {
			user, second, hasSecond = strings.Cut(u.User.String(), ":")
			present = true
		}
		if !present {
			continue
		}
		values := urlUserinfoValues(user, second, hasSecond, true)
		for _, value := range values {
			decodes.reassemblySetKind(value.text, kind)
		}
		for _, target := range userinfoTargets(values, decodes) {
			result := s.scanTextForDLPWithDecodes(ctx, target.text, opts, decodes)
			for _, match := range append(result.Matches, result.InformationalMatches...) {
				match.span.ViewLabel = spanViewLabel(match.span.ViewLabel, target.viewLabel)
				matches = append(matches, match)
			}
		}
		if opts.patterns != textDLPCardPatterns && !s.checkUserinfoValuesEntropy(urlUserinfoValues(user, second, hasSecond, false)).Allowed {
			const pattern = "URL Userinfo Entropy"
			length := len(user)
			if hasSecond {
				length += 1 + len(second)
			}
			matches = append(matches, TextDLPMatch{
				PatternName: pattern, Severity: "high",
				span: newMatchSpan(0, length, "url_userinfo", pattern, "", ""),
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
func lenientURLUserinfo(token string) (user, second string, hasSecond, present bool) {
	_, authority, ok := strings.Cut(token, "://")
	if !ok {
		return "", "", false, false
	}
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return "", "", false, false
	}
	user, second, hasSecond = strings.Cut(authority[:at], ":")
	return escapeUserinfoField(user), escapeUserinfoField(second), hasSecond, true
}

// escapeUserinfoField preserves net/url's userinfo spelling (RFC 3986 section
// 3.2.1). PathEscape shares its unreserved bytes; userinfo additionally permits
// semicolons and commas, while escaping the colon and at sign.
func escapeUserinfoField(value string) string {
	return userinfoFieldEscapes.Replace(url.PathEscape(value))
}

var userinfoFieldEscapes = strings.NewReplacer(":", "%3A", "@", "%40", "%3B", ";", "%2C", ",")
