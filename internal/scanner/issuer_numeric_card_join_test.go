// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"
)

func numericJoinTestCard19() (string, string) {
	return "42000" + "123456", "7890" + "1239"
}

func numericJoinTestCard16A() (string, string) {
	return "4" + strings.Repeat("1", 7), strings.Repeat("1", 8)
}

func numericJoinTestCard16B() (string, string) {
	return "5105" + "1051", "0510" + "5100"
}

func newNumericJoinTestScanner(t *testing.T, mutate func(*config.Config)) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	if mutate != nil {
		mutate(cfg)
	}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	return sc
}

func allowSet(allowed ...string) IssuerNumericCardJoinAllowance {
	set := make(map[string]struct{}, len(allowed))
	for _, v := range allowed {
		set[v] = struct{}{}
	}
	return func(values []string) bool {
		if len(values) < 2 {
			return false
		}
		for _, v := range values {
			if _, ok := set[v]; !ok {
				return false
			}
		}
		return true
	}
}

func TestScanURL_IssuerNumericCardJoinRelief(t *testing.T) {
	id11, id8 := numericJoinTestCard19()
	cardA1, cardA2 := numericJoinTestCard16A()
	cardB1, cardB2 := numericJoinTestCard16B()
	sc := newNumericJoinTestScanner(t, nil)

	t.Run("raw query_concat 11+8 blocks without allowance and passes with allowance", func(t *testing.T) {
		raw := "https://api.vendor.example/records/detail?wo=" + id11 + "&site=" + id8
		if res := sc.Scan(context.Background(), raw); res.Allowed {
			t.Fatalf("baseline without allowance should block, got %+v", res)
		}
		var seen []string
		ctx := WithIssuerNumericCardJoinAllowance(context.Background(), func(values []string) bool {
			seen = append([]string(nil), values...)
			return slices.Equal(values, []string{id11, id8})
		})
		if res := sc.Scan(ctx, raw); !res.Allowed {
			t.Fatalf("expected raw 11+8 query_concat to pass, got %+v", res)
		}
		if !slices.Equal(seen, []string{id11, id8}) {
			t.Fatalf("allowance saw %v, want [%s %s]", seen, id11, id8)
		}
	})

	t.Run("raw query_subsequence interleaved param blocks without allowance and passes with allowance", func(t *testing.T) {
		raw := "https://api.vendor.example/records/detail?wo=" + id11 + "&tab=summary&site=" + id8
		if res := sc.Scan(context.Background(), raw); res.Allowed {
			t.Fatalf("baseline without allowance should block, got %+v", res)
		}
		ctx := WithIssuerNumericCardJoinAllowance(context.Background(), allowSet(id11, id8))
		if res := sc.Scan(ctx, raw); !res.Allowed {
			t.Fatalf("expected raw query_subsequence 11+8 to pass, got %+v", res)
		}
	})

	t.Run("path_query_concat relieves query-only spans on delimiter-ended paths and blocks boundary-crossing spans", func(t *testing.T) {
		for _, path := range []string{"/a/b-", "/a/b_", "/a/b="} {
			t.Run("relieved on "+path, func(t *testing.T) {
				raw := "https://api.vendor.example" + path + "?wo=" + id11 + "&site=" + id8
				if res := sc.Scan(context.Background(), raw); res.Allowed {
					t.Fatalf("baseline without allowance on %s should block, got %+v", path, res)
				}
				ctx := WithIssuerNumericCardJoinAllowance(context.Background(), allowSet(id11, id8))
				if res := sc.Scan(ctx, raw); !res.Allowed {
					t.Fatalf("expected query-only span on %s to pass with allowance, got %+v", path, res)
				}
				// Per-span relief on path_query_concat keeps scanning and blocks an unissued second card.
				withUnissued := "https://api.vendor.example" + path + "?a=" + cardA1 + "&b=" + cardA2 + "&sep=,&c=" + cardB1 + "&d=" + cardB2
				ctxA := WithIssuerNumericCardJoinAllowance(context.Background(), allowSet(cardA1, cardA2))
				if res := sc.Scan(ctxA, withUnissued); res.Allowed || res.Scanner != ScannerDLP {
					t.Fatalf("issued pair + unissued card on %s should block via DLP, got %+v", path, res)
				}
			})
		}

		// A span consuming any byte of the path (crossing the path/query boundary)
		// must stay blocked even when every piece is vouched for by the allowance.
		allowAll := WithIssuerNumericCardJoinAllowance(context.Background(), allowSet(cardA1, cardA2))
		for _, tc := range []struct {
			name string
			url  string
		}{
			{"direct path to query seam with two params", "https://api.vendor.example/" + cardA1 + "?a=" + cardA2 + "&sep=,"},
			{"hyphen-delimited path to query seam with two params", "https://api.vendor.example/a-" + cardA1 + "-?a=" + cardA2 + "&sep=,"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if base := sc.Scan(context.Background(), tc.url); base.Allowed {
					t.Fatalf("%s baseline should block (vacuous test), got %+v", tc.name, base)
				}
				if res := sc.Scan(allowAll, tc.url); res.Allowed {
					t.Fatalf("%s crossed path/query boundary and must block, got %+v", tc.name, res)
				}
			})
		}
	})

	t.Run("per-span relief keeps scanning query_concat and blocks unissued second card", func(t *testing.T) {
		raw := "https://api.vendor.example/records/detail?a=" + cardA1 + "&b=" + cardA2 + "&sep=,&c=" + cardB1 + "&d=" + cardB2
		ctx := WithIssuerNumericCardJoinAllowance(context.Background(), allowSet(cardA1, cardA2))
		res := sc.Scan(ctx, raw)
		if res.Allowed || res.Scanner != ScannerDLP {
			t.Fatalf("issued pair + unissued split card in query_concat should block via DLP, got %+v", res)
		}
	})

	t.Run("per-span relief keeps scanning query_subsequence and blocks unissued second card", func(t *testing.T) {
		raw := "https://api.vendor.example/records/detail?a=" + cardA1 + "&b=" + cardA2 + "&c=" + cardB1 + "&d=" + cardB2
		ctx := WithIssuerNumericCardJoinAllowance(context.Background(), allowSet(cardA1, cardA2))
		res := sc.Scan(ctx, raw)
		if res.Allowed || res.Scanner != ScannerDLP {
			t.Fatalf("issued pair + unissued split card in query_subsequence should block via DLP, got %+v", res)
		}
	})

	t.Run("issued pair plus other secret in same query still blocks", func(t *testing.T) {
		credA := "sk-" + "ant-api03-"
		credB := strings.Repeat("A", 32)
		raw := "https://api.vendor.example/records/detail?a=" + cardA1 + "&b=" + cardA2 + "&k1=" + credA + "&k2=" + credB
		ctx := WithIssuerNumericCardJoinAllowance(context.Background(), allowSet(cardA1, cardA2))
		res := sc.Scan(ctx, raw)
		if res.Allowed {
			t.Fatalf("issued pair + split credential should block, got %+v", res)
		}
	})

	t.Run("short chunks never qualify even if allowance returns true", func(t *testing.T) {
		allowAll := WithIssuerNumericCardJoinAllowance(context.Background(), func([]string) bool { return true })
		cases := []struct {
			name string
			url  string
		}{
			{"4x4", "https://api.vendor.example/records?a=" + "4111" + "&b=" + "1111" + "&c=" + "1111" + "&d=" + "1111"},
			{"6+10", "https://api.vendor.example/records?a=" + "411111" + "&b=" + strings.Repeat("1", 10)},
			{"7+9", "https://api.vendor.example/records?a=" + "4111111" + "&b=" + strings.Repeat("1", 9)},
			{"single 16-digit value", "https://api.vendor.example/records?a=" + cardA1 + cardA2 + "&b=1"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if res := sc.Scan(allowAll, tc.url); res.Allowed {
					t.Fatalf("%s should block even with permissive allowance, got %+v", tc.name, res)
				}
			})
		}
	})

	t.Run("non-raw views and malformed queries never qualify", func(t *testing.T) {
		allowAll := WithIssuerNumericCardJoinAllowance(context.Background(), func([]string) bool { return true })
		fullCard := cardA1 + cardA2
		b64 := base64.StdEncoding.EncodeToString([]byte(fullCard))
		hexCard := hex.EncodeToString([]byte(fullCard))
		cases := []struct {
			name string
			url  string
		}{
			{"percent-encoded digit", "https://api.vendor.example/records?a=%34" + cardA1[1:] + "&b=" + cardA2},
			{"base64 split across values", "https://api.vendor.example/records?a=" + b64[:12] + "&b=" + b64[12:]},
			{"hex split across values", "https://api.vendor.example/records?a=" + hexCard[:16] + "&b=" + hexCard[16:]},
			{"noise-stripped separator", "https://api.vendor.example/records?a=" + cardA1 + "&sep=-&b=" + cardA2},
			{"path seam", "https://api.vendor.example/" + cardA1 + "?site=" + cardA2},
			{"semicolon query rejected by ParseQuery", "https://api.vendor.example/records?a=" + cardA1 + "&b=" + cardA2 + "&c=1;2"},
			{"malformed percent escape rejected by ParseQuery", "https://api.vendor.example/records?a=" + cardA1 + "&b=" + cardA2 + "&bad=%ZZ"},
			{"fullwidth unicode digits", "https://api.vendor.example/records?a=" + url.QueryEscape("４１１１１１１１") + "&b=" + cardA2},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if base := sc.Scan(context.Background(), tc.url); base.Allowed {
					t.Fatalf("%s baseline without allowance should block (vacuous test), got %+v", tc.name, base)
				}
				if res := sc.Scan(allowAll, tc.url); res.Allowed {
					t.Fatalf("%s should block even with permissive allowance, got %+v", tc.name, res)
				}
			})
		}
	})

	t.Run("non-card rules IBAN custom Luhn and keyword card never qualify", func(t *testing.T) {
		allowAll := WithIssuerNumericCardJoinAllowance(context.Background(), func([]string) bool { return true })

		// IBAN split across two params
		ibanA := "GB29" + "NWBK"
		ibanB := "6016" + "1331" + "926819"
		if res := sc.Scan(allowAll, "https://api.vendor.example/records?a="+ibanA+"&b="+ibanB); res.Allowed {
			t.Fatalf("IBAN split should block, got %+v", res)
		}

		// Operator-named Luhn rule using the exact shipped card regex
		customNameScanner := newNumericJoinTestScanner(t, func(cfg *config.Config) {
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
				Name:      "Operator Custom Card",
				Regex:     jsonnumber.ShippedCardPattern,
				Severity:  config.SeverityHigh,
				Validator: config.ValidatorLuhn,
			})
		})
		if res := customNameScanner.Scan(allowAll, "https://api.vendor.example/records?a="+cardA1+"&b="+cardA2); res.Allowed {
			t.Fatalf("operator-named Luhn rule should block, got %+v", res)
		}

		// Operator custom-regex Luhn rule reusing the built-in name
		customRegexScanner := newNumericJoinTestScanner(t, func(cfg *config.Config) {
			cfg.DLP.Patterns = []config.DLPPattern{{
				Name:      "Credit Card Number",
				Regex:     `\b\d{16}\b`,
				Severity:  config.SeverityMedium,
				Validator: config.ValidatorLuhn,
			}}
		})
		if res := customRegexScanner.Scan(allowAll, "https://api.vendor.example/records?a="+cardA1+"&b="+cardA2); res.Allowed {
			t.Fatalf("custom-regex Luhn rule should block, got %+v", res)
		}

		// Operator-configured rule with IDENTICAL name, regex, severity, and validator
		// to the built-in rule (without built-in provenance) must still block.
		identicalFieldsScanner := newNumericJoinTestScanner(t, func(cfg *config.Config) {
			cfg.DLP.Patterns = []config.DLPPattern{{
				Name:      "Credit Card Number",
				Regex:     jsonnumber.ShippedCardPattern,
				Severity:  config.SeverityMedium,
				Validator: config.ValidatorLuhn,
			}}
		})
		if res := identicalFieldsScanner.Scan(allowAll, "https://api.vendor.example/records?a="+cardA1+"&b="+cardA2); res.Allowed {
			t.Fatalf("operator-configured rule with identical fields should block, got %+v", res)
		}

		// YAML-loaded rule with include_defaults: false and identical fields must still block.
		yamlNoDefaults, err := config.LoadBytes([]byte("mode: balanced\ndlp:\n  include_defaults: false\n  patterns:\n    - name: \"Credit Card Number\"\n      regex: '" + jsonnumber.ShippedCardPattern + "'\n      severity: medium\n      validator: luhn\n"))
		if err != nil {
			t.Fatalf("config.LoadBytes(include_defaults: false): %v", err)
		}
		yamlNoDefaults.Internal = nil
		yamlNoDefaultsScanner := MustNew(yamlNoDefaults)
		t.Cleanup(yamlNoDefaultsScanner.Close)
		if res := yamlNoDefaultsScanner.Scan(allowAll, "https://api.vendor.example/records?a="+cardA1+"&b="+cardA2); res.Allowed {
			t.Fatalf("YAML include_defaults:false rule with identical fields should block, got %+v", res)
		}

		// YAML-loaded rule that raises severity on Credit Card Number must still block.
		yamlRaisedSeverity, err := config.LoadBytes([]byte("mode: balanced\ndlp:\n  include_defaults: true\n  patterns:\n    - name: \"Credit Card Number\"\n      regex: '" + jsonnumber.ShippedCardPattern + "'\n      severity: high\n      validator: luhn\n"))
		if err != nil {
			t.Fatalf("config.LoadBytes(raised severity): %v", err)
		}
		yamlRaisedSeverity.Internal = nil
		yamlRaisedScanner := MustNew(yamlRaisedSeverity)
		t.Cleanup(yamlRaisedScanner.Close)
		if res := yamlRaisedScanner.Scan(allowAll, "https://api.vendor.example/records?a="+cardA1+"&b="+cardA2); res.Allowed {
			t.Fatalf("YAML raised-severity Credit Card Number rule should block, got %+v", res)
		}

		// Shipped YAML preset copy (include_defaults: true with exact built-in fields)
		// retains built-in provenance and still qualifies for relief.
		yamlPresetCopy, err := config.LoadBytes([]byte("mode: balanced\ndlp:\n  include_defaults: true\n  patterns:\n    - name: \"Credit Card Number\"\n      regex: '" + jsonnumber.ShippedCardPattern + "'\n      severity: medium\n      validator: luhn\n"))
		if err != nil {
			t.Fatalf("config.LoadBytes(preset copy): %v", err)
		}
		yamlPresetCopy.Internal = nil
		yamlPresetScanner := MustNew(yamlPresetCopy)
		t.Cleanup(yamlPresetScanner.Close)
		if res := yamlPresetScanner.Scan(allowAll, "https://api.vendor.example/records?a="+cardA1+"&b="+cardA2); !res.Allowed {
			t.Fatalf("shipped YAML preset copy of Credit Card Number should retain relief, got %+v", res)
		}

		// Keyword-scoped operator Luhn rule using a custom card regex
		keywordScanner := newNumericJoinTestScanner(t, func(cfg *config.Config) {
			cfg.DLP.Patterns = []config.DLPPattern{{
				Name:      "Payment Card Ref",
				Regex:     `\b\d{16}\b`,
				Severity:  config.SeverityMedium,
				Validator: config.ValidatorLuhn,
				Keywords:  []string{"payment"},
			}}
		})
		if res := keywordScanner.Scan(allowAll, "https://api.vendor.example/payment?a="+cardA1+"&b="+cardA2); res.Allowed {
			t.Fatalf("keyword-scoped Luhn rule should block, got %+v", res)
		}
	})
}

func TestBuildNumericSpanMapAndRelievesGuards(t *testing.T) {
	idA, idB := numericJoinTestCard16A()
	if _, ok := buildNumericSpanMap([]string{idA}, idA); ok {
		t.Fatal("single part should fail buildNumericSpanMap")
	}
	if _, ok := buildNumericSpanMap([]string{idA, idB}, idA+idB+"x"); ok {
		t.Fatal("trailing bytes should fail buildNumericSpanMap")
	}
	spanMap, ok := buildNumericSpanMap([]string{idA, idB}, idA+idB)
	if !ok {
		t.Fatal("expected valid two-part numeric span map")
	}
	if spanMap.relieves(0, len(idA), allowSet(idA, idB)) {
		t.Fatal("single-part span must never relieve")
	}
	if spanMap.relieves(1, len(idA)+len(idB), allowSet(idA, idB)) {
		t.Fatal("partial start offset must never relieve")
	}
	if spanMap.relieves(0, len(idA)+len(idB)-1, allowSet(idA, idB)) {
		t.Fatal("partial end offset must never relieve")
	}
	if !spanMap.relieves(0, len(idA)+len(idB), allowSet(idA, idB)) {
		t.Fatal("exact two-part issued span should relieve")
	}
}
