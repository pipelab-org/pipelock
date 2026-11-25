// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package cardcorpus generates version-independent inputs for the card migration
// oracle. It deliberately imports no scanner, normalizer or card validator.
package cardcorpus

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Case records the actual presentation separately from its surrounding syntax.
type Case struct{ ID, Family, Separator, Context, Value, Text, JSON, URL string }

type issuer struct {
	name, prefix string
	size         int
}

var issuers = []issuer{
	{"visa", "4019", 16},
	{"mastercard", "5191", 16},
	{"mastercard2", "2221", 16},
	{"discover", "6011", 16},
	{"discover65", "6519", 16},
	{"jcb", "3528", 16},
	{"amex", "3719", 15},
	{"visa19", "4019", 19},
	{"discover19", "6011", 19},
	{"jcb19", "3528", 19},
	{"diners14", "3619", 14},
	{"unionpay", "6219", 16},
	{"mir", "2201", 16},
	{"maestro", "5018", 16},
}

// number follows ISO/IEC 7812's Luhn arithmetic, independent of production.
func number(prefix string, size, seed int) string {
	stem := prefix + fmt.Sprintf("%0*d", size-len(prefix)-1, 1731+seed*7919)
	for check := range 10 {
		s := stem + strconv.Itoa(check)
		sum := 0
		for i := len(s) - 1; i >= 0; i-- {
			d := int(s[i] - '0')
			if (len(s)-i)%2 == 0 {
				d *= 2
				if d > 9 {
					d -= 9
				}
			}
			sum += d
		}
		if sum%10 == 0 {
			return s
		}
	}
	panic("unreachable Luhn check digit")
}

func groups(pan string, mask int) []string {
	var out []string
	start := 0
	for i := 1; i < len(pan); i++ {
		if mask&(1<<(i-1)) != 0 {
			out = append(out, pan[start:i])
			start = i
		}
	}
	return append(out, pan[start:])
}

func present(g []string, sep string) string {
	var b strings.Builder
	for i, s := range g {
		if i > 0 {
			switch sep {
			case "mixed-space-dash":
				if i%2 == 0 {
					b.WriteByte('-')
				} else {
					b.WriteByte(' ')
				}
			case "mixed-dot-dash":
				if i%2 == 0 {
					b.WriteByte('-')
				} else {
					b.WriteByte('.')
				}
			default:
				b.WriteString(sep)
			}
		}
		b.WriteString(s)
	}
	return b.String()
}

var (
	separators = []string{"", " ", "-", " - ", "  ", "   ", ".", "/", "_", "__", ",", "\t", "\n", "\r\n", "mixed-space-dash", "mixed-dot-dash"}
	contexts   = []string{"bare", "prose", "json-string", "json-number", "json-numbers", "json-strings", "path", "query", "subdomain", "cell", "decimal-prefix", "adjacent", "base64", "hex", "percent", "zero-width"}
)

func quoted(s string) string { b, _ := json.Marshal(s); return string(b) }

func makeCase(id, family, sep, context string, g []string) Case {
	value := present(g, sep)
	text := value
	switch context {
	case "prose":
		text = "payment: " + value + " end"
	case "json-string":
		text = `{"value":` + quoted(value) + `}`
	case "json-number":
		text = `{"value":` + strings.Join(g, "") + `}`
	case "json-numbers":
		pieces := make([]string, len(g))
		for i, p := range g {
			p = strings.TrimLeft(p, "0")
			if p == "" {
				p = "0"
			}
			pieces[i] = p
		}
		text = "[" + strings.Join(pieces, ",") + "]"
	case "json-strings":
		pieces := make([]string, len(g))
		for i, p := range g {
			pieces[i] = quoted(p)
		}
		text = "[" + strings.Join(pieces, ",") + "]"
	case "path":
		text = "https://api.vendor.example/path/" + url.PathEscape(value)
	case "query":
		text = "https://api.vendor.example/?value=" + url.QueryEscape(value)
	case "subdomain":
		text = "https://a." + strings.Join(g, ".") + ".vendor.example/"
	case "cell":
		text = "F27=" + value
	case "decimal-prefix":
		text = "0." + value
	case "adjacent":
		text = "90210 " + value + " 1200"
	case "neighbor":
		text = value + " " + number("5191", 16, 2)
	case "base64":
		text = base64.StdEncoding.EncodeToString([]byte(value))
	case "hex":
		text = hex.EncodeToString([]byte(value))
	case "percent":
		var b strings.Builder
		for i := range len(value) {
			fmt.Fprintf(&b, "%%%02X", value[i])
		}
		text = b.String()
	case "zero-width":
		text = strings.Join(strings.Split(value, ""), "\u200b")
	}
	body := `{"value":` + quoted(text) + `}`
	if strings.HasPrefix(context, "json-") {
		body = text
	}
	target := "https://api.vendor.example/?value=" + url.QueryEscape(text)
	if context == "path" || context == "query" || context == "subdomain" {
		target = text
	}
	// These contexts replace the supplied separators with JSON/URL syntax or
	// contiguous digits. Exemption classification must inspect that presentation.
	actual := value
	switch context {
	case "json-number":
		actual = strings.Join(g, "")
	case "json-numbers", "json-strings":
		actual = text
	case "subdomain":
		actual = strings.Join(g, ".")
	case "neighbor":
		actual = text
	}
	return Case{id, family, sep, context, actual, text, body, target}
}

// Cases factorizes the large matrix: 4,096 masks per primary length, every
// 2/3-group partition for every supported family and seed, and a full
// separator/context cross for the canonical and decimal/column groupings.
// Enumeration order and arithmetic sampling are fixed, with no random source.
func Cases() []Case {
	var out []Case
	add := func(family, pan string, mask, si, ci int) {
		id := strconv.Itoa(len(out))
		out = append(out, makeCase(id, family, separators[si%len(separators)], contexts[ci%len(contexts)], groups(pan, mask)))
	}
	for fi, iss := range issuers {
		for seed := range 3 {
			pan := number(iss.prefix, iss.size, seed)
			for twin := range 2 {
				p := pan
				if twin == 1 {
					p = p[:len(p)-1] + strconv.Itoa((int(p[len(p)-1]-'0')+1)%10)
				}
				// All 2/3 partitions, including the first group being shorter than four.
				for a := 1; a < iss.size; a++ {
					mask := 1 << (a - 1)
					add(iss.name, p, mask, fi+seed+a, fi+seed+twin+a)
					for b := a + 1; b < iss.size; b++ {
						add(iss.name, p, mask|1<<(b-1), fi+seed+a+b, fi+seed+twin+a+b)
					}
				}
				// Representative groups cross every separator and context independently.
				masks := []int{0, 1<<3 | 1<<7 | 1<<11, 1 << 3, 1 << 7}
				if iss.size == 15 {
					masks[1] = 1<<3 | 1<<9
				}
				for _, mask := range masks {
					for si := range separators {
						for ci := range contexts {
							// Full cross once per family, other seeds retain all partitions above.
							if seed == 0 {
								add(iss.name, p, mask, si, ci)
							}
						}
					}
				}
			}
		}
	}
	// A bijection on masks supplies 4,096 distinct compositions for each length,
	// plus their invalid-checksum twins, rotating separators and contexts.
	for _, size := range []int{16, 15} {
		iss := issuers[0]
		if size == 15 {
			iss = issuers[6]
		}
		for i := range 4096 {
			mask := ((i*4051 + 7919) & ((1 << (size - 1)) - 1))
			pan := number(iss.prefix, size, i%3)
			for twin := range 2 {
				p := pan
				if twin == 1 {
					p = p[:size-1] + strconv.Itoa((int(p[size-1]-'0')+1)%10)
				}
				add(iss.name, p, mask, i, i/len(separators))
			}
		}
	}
	// Independently transcribed from https://docs.stripe.com/testing#cards.
	for _, p := range published() {
		for si := range separators {
			for ci := range contexts {
				add("published", p, 1<<3|1<<7|1<<11, si, ci)
			}
		}
	}
	// A published decoy must never excuse a lost real neighbor. Its actual
	// presentation includes both numbers, so the exception classifier refuses it.
	for _, p := range published() {
		for _, sep := range separators {
			for _, mask := range []int{1<<3 | 1<<7 | 1<<11, 1 << 7} {
				out = append(out, makeCase(strconv.Itoa(len(out)), "published", sep, "neighbor", groups(p, mask)))
			}
		}
	}
	return out
}

func published() []string {
	return []string{strings.Repeat("4242", 4), "4000" + "056655665556", "5555" + "555555554444", "2223" + "003122003222", "5200" + "828282828210", "5105" + "105105105100", "3782" + "82246310005", "3714" + "49635398431", "6011" + "111111111117", "6011" + "000990139424", "6011" + "981111111113", "3056" + "930009020004", "3622" + "7206271667", "6555" + "900000604105", "3566" + "002020360505", "6200" + "000000000005", "6200" + "000000000047", "6205" + "500000000000004"}
}

var lossDigits = regexp.MustCompile(`[0-9]+`)

// AllowedLoss classifies the exact bytes scanned by a surface without case
// metadata or production validators. The binding migration contract permits
// only exact published candidates, single decimal joins, and control joins.
func AllowedLoss(surface, input string) string {
	switch surface {
	case "text", "json-body", "url", "redact":
	default:
		return ""
	}
	views := lossInputs(input)
	if len(views) == 0 {
		return ""
	}

	found := ""
	for _, view := range views {
		groups := lossDigits.FindAllStringIndex(view.text, -1)
		for _, g := range groups {
			if completeCardField(view.text[g[0]:g[1]]) {
				return ""
			}
		}
		for i, g := range groups {
			digits := ""
			joins := []string{}
			for j := i; j < len(groups); j++ {
				if j > i {
					sep := view.text[groups[j-1][1]:groups[j][0]]
					if strings.IndexFunc(sep, func(r rune) bool { return !strings.ContainsRune(" .-/_,\t\r\n", r) }) >= 0 {
						break
					}
					joins = append(joins, sep)
				}
				digits += view.text[groups[j][0]:groups[j][1]]
				if len(digits) > 19 {
					break
				}
				public := false
				for _, p := range published() {
					public = public || digits == p
				}
				if len(digits) < 14 {
					continue
				}
				valid := completeCardField(digits)
				class := ""
				if public {
					class = "published"
				} else if surface != "url" && surface != "redact" && !view.url && !view.joined {
					if len(joins) == 1 && joins[0] == "." &&
						(i == 0 || view.text[groups[i-1][1]:g[0]] != ".") &&
						(j+1 == len(groups) || view.text[groups[j][1]:groups[j+1][0]] != ".") {
						class = "decimal"
					}
					controls := len(joins) > 0
					for _, sep := range joins {
						controls = controls && strings.Trim(sep, "\t\r\n") == ""
					}
					if controls {
						class = "control-boundary"
					}
				}
				if class != "published" && (i > 0 && strings.ContainsAny(view.text[groups[i-1][1]:g[0]], ".-/_,") ||
					j+1 < len(groups) && strings.ContainsAny(view.text[groups[j][1]:groups[j+1][0]], ".-/_,")) {
					class = ""
				}
				if class == "" {
					if !valid && !public {
						continue
					}
					return ""
				}
				if found == "" || class != "published" {
					found = class
				}
			}
		}
	}
	return found
}

// lossInputs unwraps actual transport/encoding syntax independently of production
// normalization. Each JSON scalar remains a field, so syntax cannot manufacture
// a decimal or control exception. URL components are likewise independent.
type lossInput struct {
	text        string
	url, joined bool
	// bounds holds the offsets in a joined view where one array member ends
	// and the next begins.
	bounds []int
}

func lossInputs(input string) []lossInput {
	input = strings.ReplaceAll(input, "\u200b", "")
	// Long all-digit hex can also be parsed as a JSON number. Preserve the
	// scanner's encoded view before that parse consumes its literal spelling.
	if len(input) > 19 && allDigits(input) {
		if decoded, err := hex.DecodeString(input); err == nil {
			return lossInputs(string(decoded))
		}
	}

	dec := json.NewDecoder(strings.NewReader(input))
	dec.UseNumber()
	if out, err := lossJSONInputs(dec); err == nil {
		if _, err = dec.Token(); errors.Is(err, io.EOF) {
			return out
		}
	}

	if strings.Contains(input, "://") {
		u, err := url.Parse(input)
		if err != nil {
			return nil
		}
		out := []string{u.Hostname(), u.Path, u.Fragment}
		for _, pair := range strings.Split(u.RawQuery, "&") {
			key, value, eq := strings.Cut(pair, "=")
			key, err = url.QueryUnescape(key)
			if err != nil {
				return nil
			}
			out = append(out, key)
			if eq {
				value, err = url.QueryUnescape(value)
				if err != nil {
					return nil
				}
				out = append(out, value)
			}
		}
		// Components without digits cannot be part of a card candidate.
		var numeric []lossInput
		for _, v := range out {
			for _, decoded := range lossInputs(v) {
				if lossDigits.MatchString(decoded.text) {
					decoded.url = true
					numeric = append(numeric, decoded)
				}
			}
		}
		return numeric
	}
	if strings.Contains(input, "%") {
		if decoded, err := url.QueryUnescape(input); err == nil && decoded != input {
			return lossInputs(decoded)
		}
	}
	if decoded, err := hex.DecodeString(input); err == nil && len(decoded) > 0 && (!allDigits(input) || len(input) > 19) {
		return lossInputs(string(decoded))
	}
	if decoded, err := base64.StdEncoding.DecodeString(input); err == nil && len(decoded) > 0 && !allDigits(input) && !strings.ContainsAny(input, "\t\r\n") {
		if n := numericPresentation(string(decoded)); n != "" || strings.Contains(string(decoded), "://") {
			return lossInputs(string(decoded))
		}
	}
	return []lossInput{{text: input}}
}

// lossJSONInputs retains source order and duplicate object members. Decoding to
// a map would let a later published fixture hide an earlier enforcing value.
func lossJSONInputs(dec *json.Decoder) ([]lossInput, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch v := token.(type) {
	case string:
		return lossInputs(v), nil
	case json.Number:
		return []lossInput{{text: v.String()}}, nil
	case json.Delim:
		var out []lossInput
		for dec.More() {
			if v == '{' {
				key, err := dec.Token()
				if err != nil {
					return nil, err
				}
				if text, ok := key.(string); ok {
					out = append(out, lossInputs(text)...)
				}
			}
			fields, err := lossJSONInputs(dec)
			if err != nil {
				return nil, err
			}
			out = append(out, fields...)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		if v == '[' {
			var joined strings.Builder
			var bounds []int
			for _, field := range out {
				if !field.joined {
					if joined.Len() > 0 {
						bounds = append(bounds, joined.Len())
					}
					joined.WriteString(field.text)
				}
			}
			out = append(out, lossInput{text: joined.String(), joined: true, bounds: bounds})
		}
		return out, nil
	}
	return nil, nil
}

func numericPresentation(input string) string {
	start, end := -1, 0
	for i, r := range input {
		if r >= '0' && r <= '9' {
			if start < 0 {
				start = i
			}
			end = i + 1
		}
	}
	if start < 0 {
		return ""
	}
	value := input[start:end]
	for _, r := range value {
		if r >= '0' && r <= '9' || strings.ContainsRune(" .-/_,\t\r\n", r) {
			continue
		}
		return ""
	}
	return value
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// PartitionCount exposes the sampled coverage invariant without production code.
func PartitionCount(size int) int {
	seen := map[int]bool{}
	for i := range 4096 {
		seen[(i*4051+7919)&((1<<(size-1))-1)] = true
	}
	return len(seen)
}

// Category describes added coverage, derived from dimensions rather than verdicts.
func (c Case) Category() string {
	if c.Family == "diners14" || c.Family == "unionpay" || c.Family == "mir" || c.Family == "maestro" {
		return "new-iin/" + c.Family
	}
	if c.Context == "path" || c.Context == "query" || c.Context == "subdomain" {
		return "url/" + c.Context
	}
	if c.Context == "base64" || c.Context == "hex" || c.Context == "percent" || c.Context == "zero-width" {
		return "encoded/" + c.Context
	}
	if c.Separator != "" && c.Separator != " " && c.Separator != "-" {
		return "separator/" + strconv.Quote(c.Separator)
	}
	return "overlapping-or-grouping/" + c.Context
}

// lossIssuerRanges is independent of the generator seeds and production
// validator. Visa/Mastercard/Amex/Discover/JCB lengths follow the migration's
// existing issuer contract; additions use the same published range sources:
// https://developer.cybersource.com/docs/cybs/en-us/test-data/developer/all/so/test-data/best_practices_intro/card_type_id.html
// https://www.jcb.co.jp/merchant/services/payment/unionpay.html
// https://github.com/braintree/credit-card-type/blob/main/src/lib/card-types.ts
// https://www.microfocus.com/documentation/idol/IDOL_24_3/EductionSDK_24.3_Documentation/Guides/html/Content/Reference/StandardGrammars/StandardGrammarCompiled_N.htm
var lossIssuerRanges = []struct {
	first, last string
	min, max    int
}{
	{"4", "4", 16, 16},
	{"4", "4", 19, 19},
	{"51", "55", 16, 16},
	{"2221", "2720", 16, 16},
	{"34", "34", 15, 15},
	{"37", "37", 15, 15},
	{"3528", "3589", 16, 19},
	{"6011", "6011", 16, 16},
	{"6011", "6011", 19, 19},
	{"644", "649", 16, 16},
	{"644", "649", 19, 19},
	{"622126", "622925", 16, 16},
	{"622126", "622925", 19, 19},
	{"65", "65", 16, 16},
	{"65", "65", 19, 19},
	{"300", "305", 14, 14},
	{"3095", "3095", 14, 14},
	{"36", "36", 14, 14},
	{"38", "39", 14, 14},
	{"36", "36", 16, 16},
	{"38", "39", 16, 16},
	{"62", "62", 16, 19},
	{"81", "81", 16, 16},
	{"2200", "2204", 16, 16},
	{"5018", "5018", 16, 19},
	{"5020", "5020", 16, 19},
	{"5038", "5038", 16, 19},
	{"5893", "5893", 16, 19},
	{"6304", "6304", 16, 19},
	{"6759", "6759", 16, 19},
	{"6761", "6763", 16, 19},
}

// completeCardField independently checks card issuer ranges and Luhn
// arithmetic. A control boundary only excuses joins, never a complete field.
func completeCardField(field string) bool {
	var digits strings.Builder
	for _, r := range field {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		} else if r != ' ' && r != '-' {
			return false
		}
	}
	value := digits.String()
	known := false
	for _, issuer := range lossIssuerRanges {
		if len(value) >= issuer.min && len(value) <= issuer.max {
			prefix := value[:len(issuer.first)]
			known = known || prefix >= issuer.first && prefix <= issuer.last
		}
	}
	if !known {
		return false
	}
	for _, p := range published() {
		if value == p {
			return false
		}
	}
	sum := 0
	for i := len(value) - 1; i >= 0; i-- {
		d := int(value[i] - '0')
		if (len(value)-i)%2 == 0 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// AllowedBareWarning independently limits the opt-in differential to literal
// contiguous digit fields. Encodings, URLs, grouped candidates and corroborated
// inputs are never authorized by this oracle. Unknown syntax fails closed.
var warningPromotion = regexp.MustCompile(`(?i)(?:\b(?:card(?:[ _-]*(?:number|num|no|holder))?|cc|ccn|pan|visa|mastercard|amex|unionpay|cvv2?|cvc2?|expiry|expiration)\b|\b(?:0[1-9]|1[0-2])/[0-9]{2,4}\b)`)

var warningEncodedTokens = regexp.MustCompile(`[A-Za-z0-9+/=]{20,}`)

func AllowedBareWarning(surface, input string) bool {
	for _, token := range warningEncodedTokens.FindAllString(input, -1) {
		decoded, err := base64.StdEncoding.DecodeString(token)
		if err == nil && numericPresentation(string(decoded)) != "" {
			return false
		}
		decoded, err = hex.DecodeString(token)
		if err == nil && numericPresentation(string(decoded)) != "" {
			return false
		}
	}
	if warningPromotion.MatchString(input) {
		return false
	}
	if surface != "text" && surface != "json-body" {
		return false
	}
	if strings.Contains(input, "://") || strings.Contains(input, "%") || strings.Contains(input, `\u`) {
		return false
	}
	views := []lossInput{{text: input}}
	if trimmed := strings.TrimLeft(input, " \t\r\n"); strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "\"") {
		dec := json.NewDecoder(strings.NewReader(input))
		dec.UseNumber()
		var err error
		views, err = lossJSONInputs(dec)
		if err != nil {
			return false
		}
		if _, err := dec.Token(); err != io.EOF {
			return false
		}
	}
	found := false
	for _, view := range views {
		// A card reconstructed from several array members is not a bare
		// presentation, even when a sibling value is.
		if view.joined && joinedCard(view.text, view.bounds) {
			return false
		}
		if view.url || view.joined {
			continue
		}
		text := view.text
		groups := lossDigits.FindAllStringIndex(text, -1)
		for i := range groups {
			digits := ""
			for j := i; j < len(groups); j++ {
				if j > i {
					sep := text[groups[j-1][1]:groups[j][0]]
					if strings.Trim(sep, " .-/_,\t\r\n") != "" {
						break
					}
				}
				digits += text[groups[j][0]:groups[j][1]]
				if len(digits) > 19 {
					break
				}
				if !completeCardField(digits) {
					continue
				}
				if j == i {
					found = true
					continue
				}
				legacy, canonicalSep, dotted := true, true, true
				dots := 0
				var lengths []int
				for k := i; k <= j; k++ {
					lengths = append(lengths, groups[k][1]-groups[k][0])
					if k == i {
						continue
					}
					sep := text[groups[k-1][1]:groups[k][0]]
					legacy = legacy && strings.Trim(sep, " -") == ""
					canonicalSep = canonicalSep && len(sep) <= 2 && strings.Trim(sep, " -./_") == ""
					dotted = dotted && strings.Trim(sep, " -.") == ""
					dots += strings.Count(sep, ".")
				}
				canonical := len(lengths) == 3 && lengths[0] == 4 && lengths[1] == 6 && (lengths[2] == 4 || lengths[2] == 5)
				if len(lengths) == 4 {
					canonical = lengths[0] == 4 && lengths[1] == 4 && lengths[2] == 4 && lengths[3] >= 2 && lengths[3] <= 4
				}
				if len(lengths) == 5 {
					canonical = lengths[0] == 4 && lengths[1] == 4 && lengths[2] == 4 && lengths[3] == 4 && lengths[4] >= 1 && lengths[4] <= 3
				}
				if legacy || canonicalSep && canonical || dotted && dots > 0 && (j-i != 1 || groups[j][1]-groups[i][0] != len(digits)+1) {
					return false
				}
			}
		}
	}
	return found
}

// joinedCard reports whether a joined array view reconstructs a complete card
// field that spans a member boundary. A card wholly inside one member is that
// member's own presentation and is judged there.
func joinedCard(text string, bounds []int) bool {
	for _, group := range lossDigits.FindAllStringIndex(text, -1) {
		for start := group[0]; start < group[1]; start++ {
			for end := start + 14; end <= group[1] && end-start <= 19; end++ {
				if spansBound(start, end, bounds) && completeCardField(text[start:end]) {
					return true
				}
			}
		}
	}
	return false
}

func spansBound(start, end int, bounds []int) bool {
	for _, b := range bounds {
		if start < b && b < end {
			return true
		}
	}
	return false
}
