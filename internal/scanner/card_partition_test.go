// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestCardMatchKeepsEncodedCredentialInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	secret := "sk-ant-" + "api03-" + strings.Repeat("Ab1", 20)
	encoded := base64.RawStdEncoding.EncodeToString([]byte(secret))
	card := "4111" + "111111111111"
	for _, prefix := range []string{"", card + " "} {
		text := `{"note":"charge ` + prefix + "via https://api.vendor.example/" + encoded + `/x"}`
		for name, scan := range map[string]func() TextDLPResult{
			"outbound": func() TextDLPResult { return sc.ScanTextForDLP(context.Background(), text) },
			"inbound":  func() TextDLPResult { return sc.ScanTextForDLPInbound(context.Background(), text) },
			"quiet":    func() TextDLPResult { return sc.ScanTextForDLPQuiet(context.Background(), text) },
			"paired":   func() TextDLPResult { return sc.ScanTextForDLPWithCardView(context.Background(), text, text) },
		} {
			t.Run(name+"/"+prefix, func(t *testing.T) {
				result := scan()
				found := false
				for _, match := range result.Matches {
					found = found || match.PatternName == "Anthropic API Key" && match.Encoded == "base64"
				}
				if !found {
					t.Fatalf("encoded credential hidden: %+v", result)
				}
			})
		}
	}
}

func TestCardPatternCandidatesMatchFullPrefilter(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Prefixed card", Regex: `4111[0-9]{12}`, Validator: config.ValidatorLuhn, Severity: config.SeverityHigh})
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	card := "4111" + strings.Repeat("1", 12)
	for _, text := range []string{"", "ordinary response", card, "prefix " + card + " suffix", card[:len(card)-1], card[:len(card)-1] + "2"} {
		var lowered dlpLoweredBytes
		lowered.add(text)
		all := sc.matchDLPPatternsLowered(text, encodingBase64, text, &lowered, textDLPAllPatterns)
		want := textDLPCardPatterns.selectMatches(all)
		got := sc.matchDLPPatternsLowered(text, encodingBase64, text, nil, textDLPCardPatterns)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("card partition changed findings for %q: got %+v want %+v", text, got, want)
		}
	}
}

func TestCardPatternPartitionsKeepTheirClass(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	key := "sk-ant-" + "api03-" + strings.Repeat("Ab1", 20)
	card := "4111" + "111111111111"
	for name, encode := range map[string]func(string) string{
		"literal": func(s string) string { return s },
		"url":     func(s string) string { return strings.ReplaceAll(s, "-", "%2D") },
		"html":    func(s string) string { return strings.ReplaceAll(s, "-", "&#45;") },
		"base64":  func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
		"segment": func(s string) string {
			return "https://api.vendor.example/" + base64.RawStdEncoding.EncodeToString([]byte(s)) + "/x"
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, set := range []textDLPPatternSet{textDLPCardPatterns, textDLPNonCardPatterns} {
				text := encode(key) + " ; " + encode(card)
				var decodes decodingMemo
				result := sc.scanTextForDLPWithDecodes(t.Context(), text, textDLPOptions{patterns: set}, &decodes)
				if result.Clean {
					t.Fatal("positive control lost")
				}
				for _, match := range result.Matches {
					if match.genericCard != (set == textDLPCardPatterns) {
						t.Fatalf("partition returned another class: %+v", match)
					}
				}
			}
		})
	}
}
