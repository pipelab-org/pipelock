// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// A decimal byte list of a credential must decode when every gap is the same
// letter, underscore, dot, or hyphen. Comma, space, and the other existing
// separators stay detected. Ordinary numbers stay clean.
func TestDecimalByteListGlue(t *testing.T) {
	s := gluedBoundaryScanner(t)
	secret := "AKIA" + "0123456789ABCDEF"
	for _, glue := range []string{"x", "a", "_", ".", "-", ",", " ", "+", "|", ";", "/"} {
		t.Run("glue-"+glueLabel(glue), func(t *testing.T) {
			encoded := decimalByteList(secret, glue)
			recovered := recoverDecimalByteList(t, encoded, glue)
			if recovered != secret {
				t.Fatalf("receiver recovered %q", recovered)
			}
			text := "values " + encoded + " end"
			got := s.ScanTextForDLP(context.Background(), text)
			// Plus is not a separator in either decoder. Log it instead of
			// asserting the study's claim until a run shows it is detected.
			if glue == "+" {
				t.Logf("plus glue detected=%v", gluedBoundaryFound(got.Matches, got.InformationalMatches, "AWS Access ID"))
				return
			}
			if !gluedBoundaryFound(got.Matches, got.InformationalMatches, "AWS Access ID") {
				t.Fatalf("text DLP missed glue %q: clean=%v matches=%v", glue, got.Clean, gluedMatchNames(got.Matches))
			}
			target := "https://api.vendor.example/v1/items?ref=" + url.QueryEscape(encoded)
			urlResult := s.Scan(context.Background(), target)
			if !gluedBoundaryURLBlock(urlResult, "AWS Access ID") {
				t.Fatalf("URL glue %q allowed=%v scanner=%q reason=%q", glue, urlResult.Allowed, urlResult.Scanner, urlResult.Reason)
			}
		})
	}
}

func TestDecimalByteListOrdinaryTextStaysClean(t *testing.T) {
	s := gluedBoundaryScanner(t)
	samples := []string{
		"version 1.2.3",
		"shipped on 2026-11-11",
		"address 203.0.113.10",
		"call 555-010-0199",
		"id_123_456",
		"token ab12cd34ef56ab78",
		"sections 123-456-789-012-345-678-901-234",
		"mixed 65x75,73x65",
		strings.Repeat(`\u0041`, 16),
		"1.2.3.4.5.6.7.8",
		"room 101 and room 202 are down the hall from 8",
	}
	for _, text := range samples {
		t.Run(text, func(t *testing.T) {
			got := s.ScanTextForDLP(context.Background(), text)
			if !got.Clean || len(got.InformationalMatches) != 0 {
				t.Fatalf("ordinary text produced a finding: enforced=%v informational=%v", gluedMatchNames(got.Matches), gluedMatchNames(got.InformationalMatches))
			}
		})
	}
}

func TestDecimalByteListNonUniformGlueStaysClean(t *testing.T) {
	s := gluedBoundaryScanner(t)
	secret := "AKIA" + "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(secret); i++ {
		if i > 0 {
			if i%2 == 0 {
				b.WriteByte('x')
			} else {
				b.WriteByte('y')
			}
		}
		b.WriteString(strconv.Itoa(int(secret[i])))
	}
	got := s.ScanTextForDLP(context.Background(), "values "+b.String()+" end")
	if !got.Clean || len(got.InformationalMatches) != 0 {
		t.Fatalf("mixed glue produced a finding: %+v", gluedMatchNames(got.Matches))
	}
}

func decimalByteList(secret, glue string) string {
	parts := make([]string, len(secret))
	for i := 0; i < len(secret); i++ {
		parts[i] = strconv.Itoa(int(secret[i]))
	}
	return strings.Join(parts, glue)
}

func recoverDecimalByteList(t *testing.T, encoded, glue string) string {
	t.Helper()
	parts := strings.Split(encoded, glue)
	out := make([]byte, 0, len(parts))
	for _, part := range parts {
		n, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			t.Fatalf("byte %q: %v", part, err)
		}
		out = append(out, byte(n)) // #nosec G115 -- ParseUint bitSize 8 rejects values above 255.
	}
	return string(out)
}

func glueLabel(glue string) string {
	switch glue {
	case " ":
		return "space"
	case "+":
		return "plus"
	case "|":
		return "pipe"
	case ";":
		return "semicolon"
	case "/":
		return "slash"
	case ",":
		return "comma"
	case "_":
		return "underscore"
	case ".":
		return "dot"
	case "-":
		return "hyphen"
	default:
		return glue
	}
}
