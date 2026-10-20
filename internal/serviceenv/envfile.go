// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package serviceenv

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// parseEnvironmentFile implements the EnvironmentFile= value grammar in
// systemd.exec(5), not shell or dotenv syntax. Unsupported malformed input
// fails closed; errors deliberately contain no input bytes.
// https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#EnvironmentFile=
func parseEnvironmentFile(body []byte) ([]string, error) {
	if !utf8.Valid(body) {
		return nil, errors.New("environment file is not UTF-8")
	}
	for _, r := range string(body) {
		if r == 0 || r == '\ufeff' || r >= 0xfdd0 && r <= 0xfdef || r&0xffff == 0xfffe || r&0xffff == 0xffff {
			return nil, errors.New("environment file contains a prohibited Unicode character")
		}
	}
	var out []string
	s := string(body)
	for pos := 0; pos < len(s); {
		for pos < len(s) && strings.ContainsRune(" \t\r\n", rune(s[pos])) {
			pos++
		}
		if pos == len(s) {
			break
		}
		// Upstream env-file.c COMMENT_ESCAPE consumes the next byte, including
		// a newline, and remains in COMMENT. A continued comment hides that line.
		if s[pos] == '#' || s[pos] == ';' {
			for pos < len(s) {
				c := s[pos]
				pos++
				if c == '\\' && pos < len(s) {
					pos++
					continue
				}
				if c == '\n' {
					break
				}
			}
			continue
		}
		start := pos
		for pos < len(s) && s[pos] != '=' && s[pos] != '\n' {
			pos++
		}
		if pos == len(s) || s[pos] == '\n' {
			continue
		}
		key := strings.TrimRight(s[start:pos], " \t\r")
		if !validName(key) {
			return nil, errors.New("environment file has an invalid variable name")
		}
		pos++
		var value strings.Builder
		// State 0 accepts surrounding whitespace and quoted text. State 'u'
		// preserves quotes encountered after unquoted text has begun.
		state := byte(0)
		trailing := 0
		for pos < len(s) {
			c := s[pos]
			pos++
			switch state {
			case 0:
				switch c {
				case ' ', '\t', '\r':
					continue
				case '\n':
					goto complete
				case '\'', '"':
					state = c
					continue
				default:
					state = 'u'
				}
			case '\'':
				if c == '\'' {
					state = 0
				} else {
					value.WriteByte(c)
				}
				continue
			case '"':
				if c == '"' {
					state = 0
					continue
				}
				if c == '\\' {
					if pos == len(s) {
						return nil, errors.New("environment file has an incomplete quoted escape")
					}
					next := s[pos]
					pos++
					if next == '\n' {
						continue
					}
					if !strings.ContainsRune("\\\"`$", rune(next)) {
						value.WriteByte('\\')
					}
					value.WriteByte(next)
				} else {
					value.WriteByte(c)
				}
				continue
			}
			if c == '\n' {
				goto complete
			}
			if c == '\\' {
				if pos == len(s) {
					return nil, errors.New("environment file has an incomplete escape")
				}
				c = s[pos]
				pos++
				if c == '\n' {
					continue
				}
				value.WriteByte(c)
				trailing = 0
			} else {
				value.WriteByte(c)
				if strings.ContainsRune(" \t\r", rune(c)) {
					trailing++
				} else {
					trailing = 0
				}
			}
		}
		if state == '\'' || state == '"' {
			return nil, errors.New("environment file has an unterminated quoted value")
		}
	complete:
		v := value.String()
		out = append(out, key+"="+v[:len(v)-trailing])
	}
	return out, nil
}

// Variable-name syntax is specified by systemd.exec(5), Environment=.
func validName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range []byte(s) {
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}
