// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package cardcorpus generates version-independent inputs for the card migration
// oracle. It deliberately imports no scanner, normalizer or card validator.
package cardcorpus

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
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

// AllowedLoss derives the exception from the presentation, without consulting
// any production classifier or a list of failing case IDs. Redaction retains
// its legacy shape contract: only exact published examples may lose redaction.
func (c Case) AllowedLoss(redaction bool) string {
	var digits strings.Builder
	dots, controls := 0, 0
	for _, r := range c.Value {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case r == '.':
			dots++
		case r == '\t' || r == '\r' || r == '\n':
			controls++
		case r == ' ' || r == '-' || r == '/' || r == '_' || r == ',' || r == '[' || r == ']' || r == '"':
		default:
			return ""
		}
	}
	if digits.Len() < 14 || digits.Len() > 19 {
		return ""
	}
	for _, p := range published() {
		if digits.String() == p {
			return "published"
		}
	}
	if redaction {
		return ""
	}
	// URL punctuation is a reconstruction channel, never a decimal exception.
	if c.Context == "path" || c.Context == "query" || c.Context == "subdomain" {
		return ""
	}
	if controls > 0 {
		for _, field := range strings.FieldsFunc(c.Value, func(r rune) bool { return r == '\t' || r == '\r' || r == '\n' }) {
			if completeCardField(field) {
				return ""
			}
		}
		return "control-boundary"
	}
	if dots == 1 && strings.Count(c.Value, ".") == 1 {
		parts := strings.Split(c.Value, ".")
		if allDigits(parts[0]) && allDigits(parts[1]) {
			// A dot join excuses only a split card. One side that is already
			// a complete non-published card stays enforceable.
			if completeCardField(parts[0]) || completeCardField(parts[1]) {
				return ""
			}
			return "decimal"
		}
	}
	return ""
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

// completeCardField independently checks the corpus issuer families and Luhn
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
	for _, issuer := range issuers {
		known = known || len(value) == issuer.size && strings.HasPrefix(value, issuer.prefix)
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
