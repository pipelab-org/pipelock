// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

const (
	// issuedNumericMinDigits and issuedNumericMaxDigits bound the length of a
	// single whole pure-ASCII-digit query value eligible for per-span relief
	// when joined into a built-in Luhn Credit Card Number match. A 15-19 digit
	// card can therefore be formed only from at most two such operands; shorter
	// chunks (such as 4x4 or 7+9) and full card lengths (>=15) never qualify.
	issuedNumericMinDigits = 8
	issuedNumericMaxDigits = 14
)

type issuerNumericCardJoinAllowanceContextKey struct{}

// IssuerNumericCardJoinAllowance reports whether every raw pure-ASCII-digit
// query value contributing to a built-in Credit Card Number span on a raw
// joined query view (query_concat or query_subsequence) was introduced
// server-first to this session by the exact destination HTTPS origin.
type IssuerNumericCardJoinAllowance func(values []string) bool

// WithIssuerNumericCardJoinAllowance scopes per-span server-first numeric
// relief to the built-in Luhn "Credit Card Number" pattern on raw query_concat
// and query_subsequence views only. Decoded views, noise-stripped views,
// path-to-query seams, single-value views, other patterns, core floor,
// canaries, and env/file leak detection never consult it.
func WithIssuerNumericCardJoinAllowance(ctx context.Context, allows IssuerNumericCardJoinAllowance) context.Context {
	return context.WithValue(ctx, issuerNumericCardJoinAllowanceContextKey{}, allows)
}

// issuerNumericCardJoinState extracts the request's numeric card join
// allowance and non-empty raw query values, failing closed if url.ParseQuery
// rejects the query (such as a ';' separator or malformed escape) or fewer
// than two non-empty query values are present.
func issuerNumericCardJoinState(ctx context.Context, parsed *url.URL) (IssuerNumericCardJoinAllowance, []string) {
	allows, ok := ctx.Value(issuerNumericCardJoinAllowanceContextKey{}).(IssuerNumericCardJoinAllowance)
	if !ok || allows == nil || parsed == nil || parsed.RawQuery == "" {
		return nil, nil
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(query) == 0 {
		return nil, nil
	}
	rawParts := rawQueryNonEmptyValues(parsed.RawQuery)
	if len(rawParts) < 2 {
		return nil, nil
	}
	return allows, rawParts
}

// rawQueryNonEmptyValues extracts raw non-empty query parameter values in URL
// order, matching orderedQueryConcat and querySubsequenceValues exactly.
func rawQueryNonEmptyValues(rawQuery string) []string {
	var values []string
	for _, pair := range strings.Split(rawQuery, "&") {
		_, value, _ := strings.Cut(pair, "=")
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	return values
}

// isIssuedNumericShape reports whether raw is a whole pure-ASCII-digit value
// matching ^[0-9]{8,14}$. Checked on the raw query value before decoding or
// normalization so percent-encoded or Unicode digits are rejected.
func isIssuedNumericShape(raw string) bool {
	if len(raw) < issuedNumericMinDigits || len(raw) > issuedNumericMaxDigits {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return false
		}
	}
	return true
}

type numericSpanPart struct {
	raw       string
	start     int
	end       int
	isNumeric bool
}

// numericSpanMap maps byte spans in a normalized raw joined query view back to
// the exact raw query values that formed them.
type numericSpanMap struct {
	parts []numericSpanPart
}

// buildNumericSpanMap verifies that cleaned is byte-for-byte the concatenation
// of each raw part's independently decoded and DLP-normalized form. Any
// cross-boundary normalization interaction fails closed.
func buildNumericSpanMap(rawParts []string, cleaned string) (numericSpanMap, bool) {
	if len(rawParts) < 2 {
		return numericSpanMap{}, false
	}
	parts := make([]numericSpanPart, 0, len(rawParts))
	pos := 0
	for _, raw := range rawParts {
		isNum := isIssuedNumericShape(raw)
		var norm string
		if isNum {
			// Pure ASCII digits are unchanged by IterativeDecode and ForDLP.
			norm = raw
		} else {
			norm = normalize.ForDLP(IterativeDecode(raw))
		}
		end := pos + len(norm)
		if end > len(cleaned) || cleaned[pos:end] != norm {
			return numericSpanMap{}, false
		}
		parts = append(parts, numericSpanPart{
			raw:       raw,
			start:     pos,
			end:       end,
			isNumeric: isNum,
		})
		pos = end
	}
	if pos != len(cleaned) {
		return numericSpanMap{}, false
	}
	return numericSpanMap{parts: parts}, true
}

// relieves reports whether the matched span [start, end) is formed exclusively
// by two or more whole ^[0-9]{8,14}$ raw query values (with no partial slice
// and no intervening stripped/non-numeric parameter) and allows vouches for
// every contributing value.
func (m numericSpanMap) relieves(start, end int, allow IssuerNumericCardJoinAllowance) bool {
	if allow == nil || start < 0 || end <= start {
		return false
	}
	first := -1
	for i, part := range m.parts {
		if part.start == start && part.end > part.start {
			first = i
			break
		}
	}
	if first < 0 {
		return false
	}
	last := -1
	for i := first; i < len(m.parts); i++ {
		part := m.parts[i]
		if !part.isNumeric {
			return false
		}
		if part.end == end {
			last = i
			break
		}
		if part.end > end {
			return false
		}
	}
	if last < 0 {
		return false
	}
	count := last - first + 1
	if count < 2 {
		return false
	}
	values := make([]string, count)
	for i := 0; i < count; i++ {
		values[i] = m.parts[first+i].raw
	}
	return allow(values)
}

// numericCardJoinSkipSpan returns a per-span relief predicate for p on a raw
// joined query view, or nil when p or the view is ineligible. Only the
// built-in Luhn "Credit Card Number" rule (carrying loader-verified built-in
// provenance with no custom keywords) on a raw query_concat or
// query_subsequence view qualifies.
func numericCardJoinSkipSpan(p *compiledPattern, rawParts []string, cleaned, hostname string, decodes *decodingMemo) func(start, end int) bool {
	if decodes == nil || decodes.issuedNumericCardJoin == nil || len(rawParts) < 2 {
		return nil
	}
	if !p.builtInCreditCard || p.keywords != nil || p.exemptsHost(hostname) {
		return nil
	}
	spanMap, ok := buildNumericSpanMap(rawParts, cleaned)
	if !ok {
		return nil
	}
	return func(start, end int) bool {
		return spanMap.relieves(start, end, decodes.issuedNumericCardJoin)
	}
}

// numericCardJoinPathQuerySkipSpan returns a per-span relief predicate for
// spans lying wholly within the query portion of a raw path_query_concat view.
// Offsets are adjusted for the normalized path prefix after verifying no
// cross-boundary normalization occurred; any span consuming a path byte stays
// ineligible.
func numericCardJoinPathQuerySkipSpan(p *compiledPattern, rawParts []string, rawQuery, rawTarget, cleaned, hostname string, decodes *decodingMemo) func(start, end int) bool {
	if decodes == nil || decodes.issuedNumericCardJoin == nil || len(rawParts) < 2 {
		return nil
	}
	if !p.builtInCreditCard || p.keywords != nil || p.exemptsHost(hostname) {
		return nil
	}
	queryConcat := orderedQueryConcat(rawQuery)
	if queryConcat == "" {
		return nil
	}
	rawPathPrefix, ok := strings.CutSuffix(rawTarget, queryConcat)
	if !ok {
		return nil
	}
	normPrefix := decodes.normalize(rawPathPrefix)
	if !strings.HasPrefix(cleaned, normPrefix) {
		return nil
	}
	prefixLen := len(normPrefix)
	spanMap, ok := buildNumericSpanMap(rawParts, cleaned[prefixLen:])
	if !ok {
		return nil
	}
	return func(start, end int) bool {
		if start < prefixLen {
			return false
		}
		return spanMap.relieves(start-prefixLen, end-prefixLen, decodes.issuedNumericCardJoin)
	}
}
