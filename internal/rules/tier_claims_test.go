// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// These tests pin the tier, signer and freshness behavior that docs/rules.md
// describes. A declared tier is a label inside signed bytes, not an
// entitlement: the signer decides trust, the reserved pipelock- names decide
// standard replacement, and only format_version 2 gets monotonic and expiry
// checks.

const tierClaimsRuleID = "dlp-tier-001"

func writeTierClaimsBundle(t *testing.T, root string, b *Bundle, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	bundleDir := filepath.Join(root, b.Name)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeSignedBundle(t, bundleDir, b, pub, priv)
}

func TestLoadBundles_DeclaredTierIsNotAnEntitlement(t *testing.T) {
	// Non-parallel: mutates keyring globals.
	officialPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating official key: %v", err)
	}
	setupKeyring(t, officialPub)

	vendorPub, vendorPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating vendor key: %v", err)
	}
	trusted := []config.TrustedKey{{Name: "vendor", PublicKey: hex.EncodeToString(vendorPub)}}

	cases := []struct {
		name      string
		bundle    string
		tier      string
		keyID     string
		mapping   map[string]string
		wantRules bool
		wantErr   string
	}{
		{name: "pro tier loads from a trusted third-party signer without a license", bundle: "vendor-rules", tier: TierPro, wantRules: true},
		{name: "community tier loads from a trusted third-party signer", bundle: "vendor-rules", tier: TierCommunity, wantRules: true},
		{name: "standard tier from a third-party signer loads as an additive bundle", bundle: "vendor-rules", tier: TierStandard, wantRules: true},
		{name: "standard tier bound to this signer loads", bundle: "vendor-rules", tier: TierStandard, mapping: map[string]string{TierStandard: KeyFingerprint(vendorPub)}, wantRules: true},
		{name: "standard tier bound to another signer is rejected", bundle: "vendor-rules", tier: TierStandard, mapping: map[string]string{TierStandard: KeyFingerprint(officialPub)}, wantErr: "tier-key binding"},
		{name: "pro tier bound to another signer is rejected", bundle: "vendor-rules", tier: TierPro, mapping: map[string]string{TierPro: KeyFingerprint(officialPub)}, wantErr: "tier-key binding"},
		{name: "declared key id that is not the signer is rejected", bundle: "vendor-rules", tier: TierPro, keyID: KeyFingerprint(officialPub), wantErr: "key_id mismatch"},
		{name: "reserved standard name is refused for a third-party signer", bundle: StandardBundleName, tier: TierStandard, wantErr: "reserved prefix"},
		{name: "reserved standard name is refused even with a standard binding to that signer", bundle: StandardBundleName, tier: TierStandard, mapping: map[string]string{TierStandard: KeyFingerprint(vendorPub)}, wantErr: "reserved prefix"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			b := testBundleV2(tc.bundle, tc.tier, 1, []Rule{testDLPRule(tierClaimsRuleID, confidenceHigh, StatusStable)})
			b.KeyID = KeyFingerprint(vendorPub)
			if tc.keyID != "" {
				b.KeyID = tc.keyID
			}
			writeTierClaimsBundle(t, dir, b, vendorPub, vendorPriv)

			result := LoadBundles(dir, LoadOptions{
				MinConfidence:   confidenceLow,
				PipelockVersion: testPipelockVersion,
				TrustedKeys:     trusted,
				TierKeyMapping:  tc.mapping,
			})

			if !tc.wantRules {
				if len(result.Errors) != 1 || !strings.Contains(result.Errors[0].Reason, tc.wantErr) {
					t.Fatalf("errors = %+v, want one error containing %q", result.Errors, tc.wantErr)
				}
				if len(result.DLP) != 0 || len(result.Injection) != 0 || len(result.ToolPoison) != 0 {
					t.Fatalf("rejected bundle contributed rules: DLP:%d Injection:%d ToolPoison:%d", len(result.DLP), len(result.Injection), len(result.ToolPoison))
				}
				return
			}
			if len(result.Errors) != 0 {
				t.Fatalf("unexpected errors: %+v", result.Errors)
			}
			if len(result.DLP) != 1 {
				t.Fatalf("expected 1 DLP rule, got %d", len(result.DLP))
			}
			if got, want := result.DLP[0].Name, tc.bundle+":"+tierClaimsRuleID; got != want {
				t.Fatalf("DLP pattern name = %q, want namespaced %q", got, want)
			}
		})
	}
}

func TestMergeIntoConfig_ThirdPartyStandardTierDoesNotReplaceCompiledStandard(t *testing.T) {
	// Non-parallel: mutates keyring globals.
	officialPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating official key: %v", err)
	}
	setupKeyring(t, officialPub)
	vendorPub, vendorPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating vendor key: %v", err)
	}

	dir := t.TempDir()
	b := testBundleV2("vendor-rules", TierStandard, 1, []Rule{testDLPRule(tierClaimsRuleID, confidenceHigh, StatusStable)})
	b.KeyID = KeyFingerprint(vendorPub)
	writeTierClaimsBundle(t, dir, b, vendorPub, vendorPriv)

	cfg := config.Defaults()
	cfg.Rules.RulesDir = dir
	cfg.Rules.TrustedKeys = []config.TrustedKey{{Name: "vendor", PublicKey: hex.EncodeToString(vendorPub)}}
	compiledDLP := len(cfg.DLP.Patterns)
	compiledNames := make(map[string]bool, compiledDLP)
	for _, p := range cfg.DLP.Patterns {
		compiledNames[p.Name] = true
	}

	result := MergeIntoConfig(cfg, testPipelockVersion)
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", result.Errors)
	}
	if result.StandardDLP != StandardSourceCompiled {
		t.Fatalf("StandardDLP = %q, want %q", result.StandardDLP, StandardSourceCompiled)
	}
	if got := len(cfg.DLP.Patterns); got != compiledDLP+1 {
		t.Fatalf("DLP patterns = %d, want compiled %d plus 1 additive vendor rule", got, compiledDLP)
	}
	seen := make(map[string]int, len(cfg.DLP.Patterns))
	for _, p := range cfg.DLP.Patterns {
		seen[p.Name]++
	}
	for name := range compiledNames {
		if seen[name] != 1 {
			t.Fatalf("compiled DLP pattern %q appears %d times after merge, want 1", name, seen[name])
		}
	}
	if got := seen["vendor-rules:"+tierClaimsRuleID]; got != 1 {
		t.Fatalf("vendor DLP pattern appears %d times, want 1", got)
	}
}

func TestLoadBundles_IdenticalRegexInTwoBundlesStaysSeparate(t *testing.T) {
	// Non-parallel: mutates keyring globals.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	setupKeyring(t, pub)

	dir := t.TempDir()
	for _, name := range []string{"first-rules", "second-rules"} {
		writeTierClaimsBundle(t, dir, testBundle(name, []Rule{testDLPRule(tierClaimsRuleID, confidenceHigh, StatusStable)}), pub, priv)
	}

	result := LoadBundles(dir, LoadOptions{MinConfidence: confidenceLow, PipelockVersion: testPipelockVersion})
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", result.Errors)
	}
	if len(result.DLP) != 2 {
		t.Fatalf("expected 2 separate DLP patterns, got %d", len(result.DLP))
	}
	if result.DLP[0].Name == result.DLP[1].Name {
		t.Fatalf("identical rules in two bundles share name %q, want namespaced names", result.DLP[0].Name)
	}
}

func TestLoadBundles_V1BundleGetsNoV2FreshnessChecks(t *testing.T) {
	// Non-parallel: mutates keyring globals.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	setupKeyring(t, pub)

	expired := time.Now().UTC().AddDate(-1, 0, 0).Format(time.RFC3339)

	dir := t.TempDir()
	v1 := testBundle("dated-v1", []Rule{testDLPRule(tierClaimsRuleID, confidenceHigh, StatusStable)})
	v1.ExpiresAt = expired
	v1.Tier = TierCommunity
	v1.MonotonicVersion = 1
	writeTierClaimsBundle(t, dir, v1, pub, priv)
	// A saved counter above the bundle's would reject a v2 bundle; v1 ignores it.
	if err := SaveFreshnessState(dir, &FreshnessState{
		HighestSeen: map[string]uint64{TierCommunity + ":" + v1.Name: 5},
		FormatFloor: map[string]int{v1.Name: 1},
	}); err != nil {
		t.Fatalf("SaveFreshnessState: %v", err)
	}

	result := LoadBundles(dir, LoadOptions{MinConfidence: confidenceLow, PipelockVersion: testPipelockVersion})
	if len(result.Errors) != 0 {
		t.Fatalf("v1 bundle with an expired expires_at and a lower-than-saved counter was rejected: %+v", result.Errors)
	}
	if len(result.DLP) != 1 {
		t.Fatalf("expected the v1 bundle to load 1 DLP rule, got %d", len(result.DLP))
	}

	// The same expiry on a v2 bundle is enforced.
	v2Dir := t.TempDir()
	v2 := testBundleV2("dated-v2", TierCommunity, 1, []Rule{testDLPRule(tierClaimsRuleID, confidenceHigh, StatusStable)})
	v2.KeyID = KeyFingerprint(pub)
	v2.ExpiresAt = expired
	writeTierClaimsBundle(t, v2Dir, v2, pub, priv)

	v2Result := LoadBundles(v2Dir, LoadOptions{MinConfidence: confidenceLow, PipelockVersion: testPipelockVersion})
	if len(v2Result.Errors) != 1 || !strings.Contains(v2Result.Errors[0].Reason, "expired") || len(v2Result.DLP) != 0 {
		t.Fatalf("expired v2 bundle: errors=%d DLP=%d, want rejection with no rules", len(v2Result.Errors), len(v2Result.DLP))
	}
}

func TestCheckFreshness_V1IgnoresV2FreshnessFields(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion:    1,
		Name:             "test-bundle",
		Tier:             TierCommunity,
		MonotonicVersion: 1,
		ExpiresAt:        "2020-01-01T00:00:00Z",
	}
	state := &FreshnessState{HighestSeen: map[string]uint64{TierCommunity + ":test-bundle": 5}}
	result := CheckFreshness(b, state, time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC), false)
	if !result.OK {
		t.Fatalf("v1 bundle with lower monotonic version and past expiry should pass freshness, got: %s", result.Message)
	}
}
