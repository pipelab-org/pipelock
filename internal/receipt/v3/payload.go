// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type payloadParser struct {
	data []byte
	pos  int
}

func (p *payloadParser) eat(ch byte) bool {
	if p.pos == len(p.data) || p.data[p.pos] != ch {
		return false
	}
	p.pos++
	return true
}

func (p *payloadParser) object(depth int) (map[string]any, bool) {
	if depth > maxDepth || !p.eat('{') {
		return nil, false
	}
	result := make(map[string]any)
	if p.eat('}') {
		return result, true
	}
	last := ""
	for {
		key, ok := p.string()
		if !ok || !memberName(key) || key <= last || !p.eat(':') {
			return nil, false
		}
		value, ok := p.value(depth)
		if !ok {
			return nil, false
		}
		result[key], last = value, key
		if !p.eat(',') {
			return result, p.eat('}')
		}
	}
}

func (p *payloadParser) array(depth int) ([]any, bool) {
	if depth > maxDepth || !p.eat('[') {
		return nil, false
	}
	values := []any{}
	if p.eat(']') {
		return values, true
	}
	for {
		value, ok := p.value(depth)
		if !ok {
			return nil, false
		}
		values = append(values, value)
		if !p.eat(',') {
			return values, p.eat(']')
		}
	}
}

func (p *payloadParser) value(depth int) (any, bool) {
	if p.pos == len(p.data) {
		return nil, false
	}
	switch p.data[p.pos] {
	case '{':
		return p.object(depth + 1)
	case '[':
		return p.array(depth + 1)
	case '"':
		return p.string()
	case 't':
		return true, p.literal("true")
	case 'f':
		return false, p.literal("false")
	default:
		return p.integer()
	}
}

func (p *payloadParser) literal(text string) bool {
	if len(p.data)-p.pos < len(text) || string(p.data[p.pos:p.pos+len(text)]) != text {
		return false
	}
	p.pos += len(text)
	return true
}

func (p *payloadParser) integer() (int64, bool) {
	start := p.pos
	negative := p.eat('-')
	if p.eat('0') {
		return 0, !negative
	}
	first := p.pos
	for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
		p.pos++
	}
	if first == p.pos || p.pos-start > 17 {
		return 0, false
	}
	number, err := strconv.ParseInt(string(p.data[start:p.pos]), 10, 64)
	return number, err == nil && number >= -maxInteger && number <= maxInteger
}

func (p *payloadParser) string() (string, bool) {
	start := p.pos
	if !p.eat('"') {
		return "", false
	}
	for p.pos < len(p.data) {
		next := p.data[p.pos]
		p.pos++
		switch {
		case next == '"':
			var decoded string
			err := json.Unmarshal(p.data[start:p.pos], &decoded)
			return decoded, err == nil
		case next == '\\':
			if !p.escape() {
				return "", false
			}
		case next < 0x20:
			return "", false
		case next >= utf8.RuneSelf:
			decoded, size := utf8.DecodeRune(p.data[p.pos-1:])
			if decoded == utf8.RuneError && size == 1 {
				return "", false
			}
			p.pos += size - 1
		}
	}
	return "", false
}

func (p *payloadParser) escape() bool {
	if p.pos == len(p.data) {
		return false
	}
	escape := p.data[p.pos]
	p.pos++
	switch escape {
	case '"', '\\', 'b', 'f', 'n', 'r', 't':
		return true
	case 'u':
		if !p.literal("00") || len(p.data)-p.pos < 2 ||
			!lowerHex(p.data[p.pos]) || !lowerHex(p.data[p.pos+1]) {
			return false
		}
		ch, _ := strconv.ParseUint(string(p.data[p.pos:p.pos+2]), 16, 8)
		p.pos += 2
		switch ch {
		case 8, 9, 10, 12, 13:
			return false
		default:
			return ch < 0x20
		}
	}
	return false
}

func memberName(name string) bool {
	if len(name) == 0 || len(name) > maxMemberBytes || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, c := range name[1:] {
		valid := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
		if !valid {
			return false
		}
	}
	return true
}

// matchObject distinguishes unknown enum values from structural errors.
func matchObject(object map[string]any, shape string) (unknown, valid bool) {
	fields := wireFields[shape]
	for name, value := range object {
		field, known := fields[name]
		if !known {
			return false, false
		}
		newEnum, valid := matchField(value, field.kind, field.required)
		if !valid {
			return false, false
		}
		unknown = unknown || newEnum
	}
	for name, field := range fields {
		if _, found := object[name]; field.required && !found {
			return false, false
		}
	}
	return unknown, checkConditions(object, wireConditions[shape])
}

func checkConditions(object map[string]any, conditions []conditionalSpec) bool {
	for _, condition := range conditions {
		if object[condition.field] != condition.value {
			continue
		}
		for _, key := range condition.require {
			if object[key] == nil {
				return false
			}
		}
		for _, key := range condition.forbid {
			if object[key] != nil {
				return false
			}
		}
		for key, value := range condition.equals {
			if object[key] != value {
				return false
			}
		}
	}
	return true
}

func matchField(value any, kind string, required bool) (unknown, valid bool) {
	if itemKind, array := strings.CutPrefix(kind, "[]"); array {
		items, ok := value.([]any)
		if !ok || !required && len(items) == 0 {
			return false, false
		}
		for _, item := range items {
			newEnum, valid := matchField(item, itemKind, true)
			if !valid {
				return false, false
			}
			unknown = unknown || newEnum
		}
		return unknown, true
	}
	if enum, ok := strings.CutPrefix(kind, "@"); ok {
		text, stringValue := value.(string)
		return !slices.Contains(wireEnums[enum], text), stringValue && text != ""
	}
	switch value := value.(type) {
	case map[string]any:
		if !required && len(value) == 0 {
			return false, false
		}
		if kind == "object" {
			return false, true
		}
		if wireFields[kind] != nil {
			return matchObject(value, kind)
		}
	case string:
		return false, matchString(value, kind)
	case int64:
		switch kind {
		case "uint":
			return false, value >= 0
		case "positive":
			return false, value > 0
		case "version":
			return false, value == 3
		}
	case bool:
		return false, kind == "bool"
	}
	return false, false
}

func matchString(text, kind string) bool {
	if text == "" {
		return false
	}
	switch kind {
	case "string":
		return true
	case "name":
		return memberName(text)
	case "id128":
		return isLowerHex(text, 32)
	case "digest":
		return isDigest(text)
	case "action_id":
		return len(text) <= 128 && strings.IndexFunc(text, func(c rune) bool {
			valid := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
				c >= '0' && c <= '9' || strings.ContainsRune("._:-", c)
			return !valid
		}) == -1
	case "target":
		return len(text) <= maxTargetBytes
	case "instance":
		return len(text) <= maxWriterInstanceBytes
	case "key":
		_, ok := decodeBase64(text, layoutPublicKeyBytes)
		return ok
	case "time":
		const layout = "2006-01-02T15:04:05.000Z"
		parsed, err := time.Parse(layout, text)
		return err == nil && parsed.Format(layout) == text
	}
	return false
}

func sortedStrings(value any, unique bool) bool {
	items, present := value.([]any)
	if !present {
		return value == nil
	}
	previous := ""
	for _, item := range items {
		text, ok := item.(string)
		if !ok || text < previous || unique && text == previous {
			return false
		}
		previous = text
	}
	return true
}
