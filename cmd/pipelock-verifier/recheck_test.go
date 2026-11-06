// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestTransformProfileV1Fixtures(t *testing.T) {
	t.Parallel()
	path := filepath.Clean(filepath.Join("..", "..", "sdk", "conformance", "testdata", "transform-profile", "pipelock-transform-v1.json"))
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var profile struct {
		Profile  string `json:"profile"`
		Fixtures []struct {
			Name           string `json:"name"`
			NormalizedView string `json:"normalized_view"`
			Input          string `json:"input"`
			Output         string `json:"output"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(body, &profile); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if profile.Profile != transformProfileV1 {
		t.Fatalf("profile=%q want %q", profile.Profile, transformProfileV1)
	}
	for _, fixture := range profile.Fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			got, err := reproduceSpanView(fixture.Input, fixture.NormalizedView)
			if err != nil {
				t.Fatalf("reproduceSpanView: %v", err)
			}
			if got != fixture.Output {
				t.Fatalf("output=%q want %q", got, fixture.Output)
			}
		})
	}
}

func TestRecheckEvidenceReceiptSpan(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.txt")
	if err := os.WriteFile(sourcePath, []byte("alpha [redacted-value] omega"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	span := recheckSourceSpanFixture()
	offset := strings.Index("alpha [redacted-value] omega", "[redacted-value]")
	length := len("[redacted-value]")
	span.CharOffset = &offset
	span.CharLength = &length
	receipt := recheckReceiptFixture(t, span)

	result, err := recheckEvidenceReceiptSpan(receipt, sourcePath, 0)
	if err != nil {
		t.Fatalf("recheckEvidenceReceiptSpan: %v", err)
	}
	if result.Location != recheckLocationExact || result.View != contractreceipt.NormalizedViewSanitizedTarget {
		t.Fatalf("result = %+v", result)
	}
}

func TestRecheckEvidenceReceiptSpanRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.txt")
	if err := os.WriteFile(sourcePath, []byte("alpha [redacted-value] omega"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	tests := map[string]struct {
		receipt contractreceipt.EvidenceReceipt
		path    string
		index   int
		want    string
	}{
		"wrong payload kind": {
			receipt: contractreceipt.EvidenceReceipt{PayloadKind: contractreceipt.PayloadProxyDecision},
			path:    sourcePath,
			want:    "requires payload_kind",
		},
		"negative span index": {
			receipt: recheckReceiptFixture(t, recheckSourceSpanFixture()),
			path:    sourcePath,
			index:   -1,
			want:    "non-negative",
		},
		"bad payload json": {
			receipt: contractreceipt.EvidenceReceipt{
				PayloadKind: contractreceipt.PayloadProxyDecisionWithSpans,
				Payload:     []byte(`{`),
			},
			path: sourcePath,
			want: "decode spanned payload",
		},
		"span index outside payload": {
			receipt: recheckReceiptFixture(t, recheckSourceSpanFixture()),
			path:    sourcePath,
			index:   1,
			want:    "outside source_spans length",
		},
		"unsupported transform profile": {
			receipt: func() contractreceipt.EvidenceReceipt {
				span := recheckSourceSpanFixture()
				span.TransformProfile = "pipelock-transform-v2"
				return recheckReceiptFixture(t, span)
			}(),
			path: sourcePath,
			want: "unsupported transform_profile",
		},
		"missing redacted sample": {
			receipt: func() contractreceipt.EvidenceReceipt {
				span := recheckSourceSpanFixture()
				span.RedactedSample = ""
				return recheckReceiptFixture(t, span)
			}(),
			path: sourcePath,
			want: "redacted_sample is required",
		},
		"source read error": {
			receipt: recheckReceiptFixture(t, recheckSourceSpanFixture()),
			path:    filepath.Join(dir, "missing.txt"),
			want:    "read recheck source",
		},
		"unsupported normalized view": {
			receipt: func() contractreceipt.EvidenceReceipt {
				span := recheckSourceSpanFixture()
				span.NormalizedView = "unknown_view"
				return recheckReceiptFixture(t, span)
			}(),
			path: sourcePath,
			want: "unsupported normalized_view",
		},
		"coordinates outside view": {
			receipt: func() contractreceipt.EvidenceReceipt {
				span := recheckSourceSpanFixture()
				offset := 999
				length := 1
				span.CharOffset = &offset
				span.CharLength = &length
				return recheckReceiptFixture(t, span)
			}(),
			path: sourcePath,
			want: "coordinates outside",
		},
		"coordinate mismatch": {
			receipt: func() contractreceipt.EvidenceReceipt {
				span := recheckSourceSpanFixture()
				offset := 0
				length := 5
				span.CharOffset = &offset
				span.CharLength = &length
				return recheckReceiptFixture(t, span)
			}(),
			path: sourcePath,
			want: "redacted_sample mismatch",
		},
		"sample not found without coordinates": {
			receipt: recheckReceiptFixture(t, recheckSourceSpanFixture()),
			path: func() string {
				path := filepath.Join(dir, "no-sample.txt")
				if err := os.WriteFile(path, []byte("alpha beta"), 0o600); err != nil {
					t.Fatalf("write source: %v", err)
				}
				return path
			}(),
			want: "redacted_sample not found",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := recheckEvidenceReceiptSpan(tc.receipt, tc.path, tc.index)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestReproduceSpanViewDecodedInputs(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		source string
		view   string
		want   string
		errSub string
	}{
		"hex decoded": {
			source: "68656c6c6f",
			view:   contractreceipt.NormalizedViewHexDecoded,
			want:   "hello",
		},
		"unicode tags decoded": {
			source: "prefix \U000e0001\U000e0041\u200b\U000e0042\U000e007f suffix",
			view:   contractreceipt.NormalizedViewUnicodeTagsDecoded,
			want:   "prefix AB suffix",
		},
		"unicode tags DLP decoded": {
			source: "prefix \U000e0001\U000e0041\u200b\U000e0042\U000e007f suffix",
			view:   contractreceipt.NormalizedViewDLPNormalized + ":unicode_tags",
			want:   "prefix AB suffix",
		},
		"unicode tags spaced": {
			source: "prefix \U000e0001\U000e0041\u200b\U000e0042\U000e007f suffix",
			view:   "invisible_spaced:" + contractreceipt.NormalizedViewUnicodeTagsDecoded,
			want:   "prefix A B suffix",
		},
		"unicode tags vowel folded": {
			source: "prefix \U000e0001\U000e0041\u200b\U000e0042\U000e007f suffix",
			view:   "vowel_fold:" + contractreceipt.NormalizedViewUnicodeTagsDecoded,
			want:   "prafax AB saffax",
		},
		"hex decoded invalid": {
			source: "not-hex",
			view:   contractreceipt.NormalizedViewHexDecoded,
			errSub: "not valid hex",
		},
		"base64 invalid": {
			source: "%%%",
			view:   contractreceipt.NormalizedViewBase64Decoded,
			errSub: "not valid base64",
		},
		// The scanner's spaced view also spaces invisibles produced by
		// compatibility folding; recheck reproduces the same view.
		"invisible spaced compatibility folded": {
			source: "normalization\uFFA0witness",
			view:   contractreceipt.NormalizedViewInvisibleSpaced,
			want:   "normalization witness",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := reproduceSpanView(tc.source, tc.view)
			if tc.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("err = %v, want substring %q", err, tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("reproduceSpanView: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func recheckSourceSpanFixture() contractreceipt.SourceSpan {
	return contractreceipt.SourceSpan{
		SourceID:             "request-url",
		SourceKind:           contractreceipt.SourceKindHTTPRequestURL,
		NormalizedView:       contractreceipt.NormalizedViewSanitizedTarget,
		PipelockBinaryDigest: "sha256:" + strings.Repeat("1", 64),
		RulesBundleDigest:    "sha256:" + strings.Repeat("2", 64),
		TransformProfile:     transformProfileV1,
		PolicyHash:           "sha256:" + strings.Repeat("3", 64),
		RuleID:               "aws_access_key",
		MatchHash:            "hmac-sha256:" + strings.Repeat("4", 64),
		MatchHashAlg:         contractreceipt.SourceSpanMatchHashAlgHMACSHA256,
		MatchClass:           "secret:aws_access_key",
		RedactedSample:       "[redacted-value]",
	}
}

func recheckReceiptFixture(t *testing.T, span contractreceipt.SourceSpan) contractreceipt.EvidenceReceipt {
	t.Helper()
	payload := contractreceipt.PayloadProxyDecisionWithSpansStruct{
		ActionType:    "block",
		Target:        "https://example.com/[redacted-value]",
		Verdict:       "block",
		Transport:     "forward",
		PolicySources: []string{"dlp"},
		WinningSource: "scanner",
		SourceSpans:   []contractreceipt.SourceSpan{span},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return contractreceipt.EvidenceReceipt{
		PayloadKind: contractreceipt.PayloadProxyDecisionWithSpans,
		Payload:     body,
	}
}

// TestRecheckReport_UnauthenticatedNeverReadsAsVerified is the guard for the
// staged recheck contract: a source recheck run WITHOUT a trusted key must
// never surface a passing result, no matter how strong the positional match.
//
// The defect this replaces: the report carried a bare recheck_valid bool while
// the "this receipt was never authenticated" caveat lived in a separate
// unpinned field. A machine consumer reading recheck_valid alone got a truthy
// source match for a receipt whose producer was never verified.
//
// Non-vacuity: neutralize by deleting the `case !signatureVerified` arm in
// newRecheckReport (so an exact match reports verified regardless of
// authentication). This test must then FAIL.
func TestRecheckReport_UnauthenticatedNeverReadsAsVerified(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		location    string
		wantOverall string
	}{
		{name: "exact", location: recheckLocationExact, wantOverall: recheckOverallIncomplete},
		{name: "occurrence", location: recheckLocationOccurrence, wantOverall: recheckOverallIncomplete},
		{name: "failed", location: recheckLocationFailed, wantOverall: recheckOverallFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := newRecheckReport(recheckResult{Location: tc.location, View: "sanitized_target"}, false)
			if got.Overall != tc.wantOverall {
				t.Fatalf("overall=%q, want %q", got.Overall, tc.wantOverall)
			}
			if got.Signature != recheckSignatureNotChecked {
				t.Fatalf("signature=%q, want %q", got.Signature, recheckSignatureNotChecked)
			}
		})
	}
}

// TestRecheckReport_UnauthenticatedWithholdsAuthoritativeLocation is the guard
// for the strongest form of the contract: for an unauthenticated receipt, the
// positive positional result must not appear in ANY field an automated gate
// would trust.
//
// The defect this closes: an earlier revision reported
// location="exact_coordinates" alongside signature="not_checked". A consumer
// keying off `location != "failed"` would accept an attacker-supplied unpinned
// receipt paired with an attacker-chosen source file. Documenting "also read
// signature" does not prevent that; withholding the field does.
//
// Non-vacuity: neutralize by deleting the `if !signatureVerified` early return
// in newRecheckReport so Location is populated unconditionally. This test must
// then FAIL.
func TestRecheckReport_UnauthenticatedWithholdsAuthoritativeLocation(t *testing.T) {
	t.Parallel()
	for _, loc := range []string{recheckLocationExact, recheckLocationOccurrence} {
		t.Run("unauthenticated/"+loc, func(t *testing.T) {
			t.Parallel()
			got := newRecheckReport(recheckResult{Location: loc, View: "sanitized_target"}, false)
			if got.Location != "" {
				t.Fatalf("unauthenticated recheck exposed authoritative location=%q; a positive positional result must be withheld from the trusted field", got.Location)
			}
			if got.UnauthenticatedDiagnostic == nil || got.UnauthenticatedDiagnostic.Location != loc {
				t.Fatalf("expected non-authoritative diagnostic carrying %q, got %+v", loc, got.UnauthenticatedDiagnostic)
			}
		})
	}
	t.Run("authenticated/reports authoritative location", func(t *testing.T) {
		t.Parallel()
		authenticated := newRecheckReport(recheckResult{Location: recheckLocationExact}, true)
		if authenticated.Location != recheckLocationExact {
			t.Fatalf("authenticated location=%q, want %q", authenticated.Location, recheckLocationExact)
		}
		if authenticated.UnauthenticatedDiagnostic != nil {
			t.Fatalf("authenticated report carried an unauthenticated diagnostic: %+v", authenticated.UnauthenticatedDiagnostic)
		}
	})
}

// TestRecheckReport_StrengthIsDistinguishable guards the second half of the
// contract: a match at the signed coordinates and a bare substring occurrence
// are different facts and must not collapse into one verdict.
//
// Non-vacuity: neutralize by mapping recheckLocationOccurrence to
// recheckOverallVerified in newRecheckReport. This test must then FAIL.
func TestRecheckReport_StrengthIsDistinguishable(t *testing.T) {
	t.Parallel()
	exact := newRecheckReport(recheckResult{Location: recheckLocationExact}, true)
	occurrence := newRecheckReport(recheckResult{Location: recheckLocationOccurrence}, true)
	if exact.Overall != recheckOverallVerified {
		t.Fatalf("authenticated exact match overall=%q, want %q", exact.Overall, recheckOverallVerified)
	}
	if occurrence.Overall == recheckOverallVerified {
		t.Fatalf("occurrence-only match reported overall=%q; a substring hit is not a positional proof", occurrence.Overall)
	}
	if exact.Overall == occurrence.Overall {
		t.Fatalf("exact and occurrence-only collapsed to the same verdict %q", exact.Overall)
	}
}

func TestUnicodeTagsReviewCompositeView(t *testing.T) {
	source := "prefix \U000e0041\U000e0025\U000e0032\U000e0030\U000e0042 suffix"
	got, err := reproduceSpanView(source, "dlp_normalized:unicode_tags:url_userinfo_username_escaped")
	if err != nil || got != "prefix A%20B suffix" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestUnicodeTagsReviewCompositeOrder(t *testing.T) {
	source := "%F3%A0%81%81%F3%A0%80%A5%F3%A0%80%B2%F3%A0%80%B0%F3%A0%81%82"
	got, err := reproduceSpanView(source, "dlp_normalized:unicode_tags_decoded:url_decoded:url_userinfo_username_escaped")
	if err != nil || got != "A%20B" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestUnicodeTagsReviewSharedReceipt(t *testing.T) {
	path := filepath.Join("..", "..", "sdk", "verifiers", "fixtures", "unicode-tags-receipt.json")
	key := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	stdout, stderr, code := runRoot(t, "receipt", "--key", key, "--json", path)
	if code != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestUnicodeTagsReviewUserinfoReplay(t *testing.T) {
	var tags strings.Builder
	for _, r := range "AKIA" + "QWERTYUIOPASDFGH" {
		tags.WriteRune(0xe0000 + r)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	source := "https://" + url.User(tags.String()).String() + "@api.vendor.example/"
	result := sc.ScanTextForDLP(t.Context(), source)
	label := "dlp_normalized:unicode_tags_decoded:url_userinfo_username_escaped"
	for _, m := range result.Matches {
		span := m.Span()
		if span.ViewLabel != label {
			continue
		}
		view, err := reproduceSpanView(source, label)
		if err != nil || span.ByteEnd > len(view) || span.ByteStart < 0 || view[span.ByteStart:span.ByteEnd] != "AKIA"+"QWERTYUIOPASDFGH" {
			t.Fatalf("label=%s span=%+v view=%q err=%v", label, span, view, err)
		}
		return
	}
	t.Fatalf("missing producer label %s: %+v", label, result.Matches)
}

func TestUnicodeTagsReviewUserinfoSources(t *testing.T) {
	for _, tc := range []struct{ name, source, stage, want string }{
		{"escaped username", "https://alpha%20beta@api.vendor.example/path", "url_userinfo_username_escaped", "alpha%20beta"},
		{"password", "https://alpha:beta%20gamma@api.vendor.example/", "url_userinfo_password_escaped", "beta%20gamma"},
		{"joined pair", "https://alpha%20beta:gamma%20delta@api.vendor.example/", "url_userinfo", "alpha beta:gamma delta"},
		{"component", "alpha%20beta", "url_userinfo_username_escaped", "alpha%20beta"},
		{"no userinfo", "https://api.vendor.example/path", "url_userinfo_username_escaped", "https://api.vendor.example/path"},
		{"raw unicode", "https://\U000e0041@api.vendor.example/path?x=y", "url_userinfo_username_escaped", "\U000e0041"},
		{"malformed joined pair", "https://alpha%zz:beta%zz@api.vendor.example/", "url_userinfo", "alpha%zz:beta%zz"},
		{"malformed no userinfo", "https://api.vendor.example/%zz", "url_userinfo_username_escaped", "https://api.vendor.example/%zz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := reproduceTagUserinfoSource(tc.source, tc.stage); got != tc.want {
				t.Fatalf("got=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestUnicodeTagsReviewLeetspeakRecheck(t *testing.T) {
	for _, tc := range []struct{ source, view string }{
		{"\U000e0031\U000e0067\U000e006e\U000e0030\U000e0072\U000e0065", "leetspeak:for_matching:unicode_tags_decoded"},
		{"MWduMHJl", "leetspeak:for_matching:base64_decoded"},
		{"31676e307265", "leetspeak:for_matching:hex_decoded"},
	} {
		got, err := reproduceSpanView(tc.source, tc.view)
		if err != nil || got != "ignore" {
			t.Fatalf("view=%s got=%q err=%v", tc.view, got, err)
		}
	}
	if _, err := reproduceSpanView("source", "leetspeak:unsupported"); err == nil {
		t.Fatal("unsupported nested view accepted")
	}
}

func TestTextEncodingRecheckViews(t *testing.T) {
	for encoding, source := range map[string]string{
		"decimal_character_codes": "104 101 108 108 111 32 119 111 114 108 100",
		"octal_character_codes":   "0o150, 0o145, 0o154, 0o154, 0o157, 0o40, 0o167, 0o157, 0o162, 0o154, 0o144",
		"binary_character_codes":  "0b1101000, 0b1100101, 0b1101100, 0b1101100, 0b1101111, 0b100000, 0b1110111, 0b1101111, 0b1110010, 0b1101100, 0b1100100",
		"quoted_printable":        "=68ello world",
	} {
		got, err := reproduceSpanView(source, "dlp_normalized:"+encoding)
		if err != nil || got != "hello world" {
			t.Fatalf("DLP %s: got %q, %v", encoding, got, err)
		}
		for prefix, want := range map[string]string{"": "hello world", "leetspeak:": "hello world", "invisible_spaced:": "hello world", "vowel_fold:": "halla warld"} {
			view := prefix + "for_matching:" + encoding + "_decoded"
			got, err := reproduceSpanView(source, view)
			if err != nil || got != want {
				t.Fatalf("%s: got %q, %v", view, got, err)
			}
		}
	}
	if _, err := reproduceSpanView("ordinary text", "for_matching:quoted_printable_decoded"); err == nil {
		t.Fatal("admitted an unchanged carrier")
	}
}

func TestDecodedSpacingRecheck(t *testing.T) {
	for _, tc := range []struct{ source, view string }{
		{base64.StdEncoding.EncodeToString([]byte("hello\u200bworld")), "invisible_spaced:for_matching:base64_decoded"},
		{hex.EncodeToString([]byte("hello\u200bworld")), "invisible_spaced:for_matching:hex_decoded"},
	} {
		got, err := reproduceSpanView(tc.source, tc.view)
		if err != nil || got != "hello world" {
			t.Fatalf("%s: got %q, %v", tc.view, got, err)
		}
	}
}
