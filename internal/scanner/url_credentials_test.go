// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestURLUserinfoComponentInspection(t *testing.T) {
	core := "gh" + "p_" + strings.Repeat("aB3c", 9)
	configured := "gsk_" + strings.Repeat("aB3c", 12)
	random := "Q7mZ9pL4vR2sK8hF6dA0nT5cW3xB1jG" + "uEoYiHkSqVfDtNr"
	for _, empty := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.Internal = nil
		if empty {
			cfg.DLP.Patterns = nil
		}
		s := MustNew(cfg)
		defer s.Close()
		secrets := map[string]string{"core": core, "entropy": random}
		if !empty {
			secrets["configured"] = configured
		}
		for name, secret := range secrets {
			for encoding, value := range map[string]string{
				"raw": secret, "hex": hex.EncodeToString([]byte(secret)),
				"base64":    base64.StdEncoding.EncodeToString([]byte(secret)),
				"base64url": base64.RawURLEncoding.EncodeToString([]byte(secret)),
				"percent":   url.QueryEscape(secret),
			} {
				for _, password := range []bool{false, true} {
					t.Run(name+"/"+encoding+"/"+map[bool]string{false: "username", true: "password"}[password]+"/"+map[bool]string{false: "defaults", true: "floor"}[empty], func(t *testing.T) {
						u := &url.URL{Scheme: "https", Host: "api.vendor.example", Path: "/read"}
						u.User = url.User(value)
						if password {
							u.User = url.UserPassword("reader", value)
						}
						if got := s.Scan(context.Background(), u.String()); got.Allowed {
							t.Fatal("credential-bearing userinfo allowed")
						}
						if got := s.ScanTextForDLP(context.Background(), u.String()); got.Clean {
							t.Fatal("credential-bearing URL in text allowed")
						}
					})
				}
			}
		}
		for _, target := range []string{"https://api.vendor.example/read", "https://reader:ordinary@api.vendor.example/read"} {
			if got := s.Scan(context.Background(), target); !got.Allowed {
				t.Fatalf("benign URL blocked: %s", got.Reason)
			}
			if got := s.ScanTextForDLP(context.Background(), target); !got.Clean {
				t.Fatalf("benign URL text blocked: %+v", got.Matches)
			}
		}
	}
}

func TestWIFOverlappingCandidates(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FetchProxy.Monitoring.EntropyThreshold = 100
	s := MustNew(cfg)
	defer s.Close()
	vectors := []string{
		"5HueCGU8rMjx" + "EXxiPuD5BDku4MkFqe" + "Zyd4dZ1jvhTVqvbTLvyTJ",
		"KwdMAjGmer" + "Yanjeui5SHS7Jkmp" + "ZvVipYvB2LJGU1ZxJwYvP98617",
	}
	for _, vector := range vectors {
		if !validateWIF(vector) {
			t.Fatal("invalid test vector")
		}
		for _, prefix := range []string{"", "K", "L", "5", strings.Repeat("K", 200)} {
			value := prefix + vector
			text := s.ScanTextForDLP(context.Background(), value)
			if !matchRetained(text.Matches, "Bitcoin WIF Private Key") {
				t.Fatalf("WIF not found after %d prefix bytes", len(prefix))
			}
			for _, target := range []string{"https://api.vendor.example/" + value, "https://api.vendor.example/?value=" + value} {
				got := s.Scan(context.Background(), target)
				if got.Allowed || got.Scanner != ScannerDLP {
					t.Fatalf("want DLP block, got %+v", got)
				}
			}
		}
	}
	for _, bad := range []string{"5" + strings.Repeat("H", 50), "K" + strings.Repeat("a", 51)} {
		if got := s.ScanTextForDLP(context.Background(), bad); !got.Clean {
			t.Fatalf("invalid WIF detected: %+v", got.Matches)
		}
	}
}

func TestWIFOverlapWorkBoundAndSpan(t *testing.T) {
	vector := "KwdMAjGmer" + "Yanjeui5SHS7Jkmp" + "ZvVipYvB2LJGU1ZxJwYvP98617"
	calls := 0
	p := compiledPattern{re: regexp.MustCompile(config.BitcoinWIFRegex), wifOverlapRetry: true, validate: func(value string) bool { calls++; return validateWIF(value) }}
	prefix := strings.Repeat("K", 4096)
	input := prefix + vector
	start, end, ok := p.matchSpan(input)
	if !ok || start != len(prefix) || end != len(input) {
		t.Fatalf("span %d:%d ok=%v", start, end, ok)
	}
	if calls > len(input) {
		t.Fatalf("%d checksum calls for %d bytes", calls, len(input))
	}
	if !p.matches(input) {
		t.Fatal("boolean matcher disagrees with span matcher")
	}
}

func TestURLUserinfoWarnPatternEvidence(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Custom URL marker", Regex: `custom-marker-[a-z]+`, Severity: config.SeverityHigh, Action: config.ActionWarn}}
	s := MustNew(cfg)
	defer s.Close()
	value := hex.EncodeToString([]byte("custom-marker-ordinary"))
	got := s.ScanTextForDLP(context.Background(), "https://"+value+"@api.vendor.example/")
	if !got.Clean || len(got.InformationalMatches) == 0 {
		t.Fatalf("warn evidence lost or enforced: %+v", got)
	}
}

func TestURLUserinfoPercentAndEmptyFields(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Custom URL marker", Regex: `literal\+marker`, Severity: config.SeverityHigh}}
	s := MustNew(cfg)
	defer s.Close()
	if got := s.Scan(context.Background(), "https://reader:literal%252Bmarker@api.vendor.example/"); got.Allowed {
		t.Fatal("percent-decoded plus credential allowed")
	}
	for _, value := range []string{"https://:@api.vendor.example/", "https://%zz@api.vendor.example/"} {
		if got := s.ScanTextForDLP(context.Background(), value); !got.Clean {
			t.Fatalf("empty or malformed benign userinfo reported a secret: %+v", got.Matches)
		}
	}
	if ValidatedPatternMatches("ordinary", nil, nil, false, false) {
		t.Fatal("nil pattern matched")
	}
	vector := "K" + "KwdMAjGmer" + "Yanjeui5SHS7Jkmp" + "ZvVipYvB2LJGU1ZxJwYvP98617"
	if !ValidatedPatternMatches(vector, regexp.MustCompile(config.BitcoinWIFRegex), validateWIF, false, true) {
		t.Fatal("shared validated matcher missed overlapping WIF")
	}
}

func TestURLUserinfoFindingViews(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()
	key := "gh" + "p_" + strings.Repeat("aB3c", 9)
	for _, password := range []bool{false, true} {
		u := &url.URL{Scheme: "https", Host: "api.vendor.example", Path: "/read", User: url.User(hex.EncodeToString([]byte(key)))}
		component := "username"
		if password {
			u.User = url.UserPassword("reader", hex.EncodeToString([]byte(key)))
			component = "password"
		}
		got := s.Scan(context.Background(), u.String())
		if got.Allowed || len(got.spans) != 1 {
			t.Fatalf("missing userinfo finding: %+v", got)
		}
		span := got.spans[0]
		if !strings.Contains(span.ViewLabel, "hex_decoded:url_userinfo_"+component) || span.ByteStart != 0 || span.ByteEnd != len(key) {
			t.Fatalf("span does not index the decoded credential field: %+v", span)
		}
	}
}

// TestURLUserinfoColonSplitCredential covers a credential split across the
// username and password: the receiver rejoins the Basic-auth pair, so the
// scanner must see the pair as path and query splits are already seen.
func TestURLUserinfoColonSplitCredential(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	cfg.DLP.ScanEnv = true
	s := MustNew(cfg)
	defer s.Close()
	env := "Envq7MZ9pL4vR2sK8h" + "F6dA0nT5cW3xB1jG"
	s.envSecrets = []string{env}
	for name, secret := range map[string]string{
		"core":       "gh" + "p_" + "R7mZ9pL4vR2sK8hF6dA0nT5cW3xB1jGuEoYi",
		"configured": "gsk_" + "R7mZ9pL4vR2sK8hF6dA0nT5cW3xB1jGuEoYiHkSqVfDtNr12",
		"env":        env,
	} {
		t.Run(name, func(t *testing.T) {
			target := "https://" + secret[:12] + ":" + secret[12:] + "@api.vendor.example/read"
			if got := s.Scan(context.Background(), target); got.Allowed {
				t.Fatal("credential split at the userinfo colon allowed")
			}
			if got := s.ScanTextForDLP(context.Background(), "fetch "+target); got.Clean {
				t.Fatal("credential split at the userinfo colon clean in text")
			}
		})
	}
	if got := s.Scan(context.Background(), "https://reader:ordinary@api.vendor.example/read"); !got.Allowed {
		t.Fatalf("benign userinfo pair blocked: %s", got.Reason)
	}
}

// TestURLUserinfoTextLenientAuthority covers URL tokens that url.Parse refuses
// but other HTTP clients still send as Basic credentials.
func TestURLUserinfoTextLenientAuthority(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()
	encoded := hex.EncodeToString([]byte("gh" + "p_" + "R7mZ9pL4vR2sK8hF6dA0nT5cW3xB1jGuEoYi"))
	random := "Q7mZ9pL4vR2sK8hF6dA0nT5cW3xB1jG" + "uEoYiHkSqVfDtNr"
	for _, text := range []string{
		"fetch https://réader:" + encoded + "@api.vendor.example/read",
		"fetch https://réader:" + random + "@api.vendor.example/read",
		"fetch https://" + encoded + "é@api.vendor.example/read",
	} {
		if _, err := url.Parse(strings.Fields(text)[1]); err == nil {
			t.Fatalf("fixture parses strictly: %q", text)
		}
		if got := s.ScanTextForDLP(context.Background(), text); got.Clean {
			t.Fatalf("credential in leniently parsed userinfo clean: %q", text)
		}
	}
	if got := s.ScanTextForDLP(context.Background(), "fetch https://réader:ordinary@api.vendor.example/read"); !got.Clean {
		t.Fatalf("benign non-ASCII userinfo reported: %+v", got.Matches)
	}
	for token, want := range map[string]string{
		"https://a:b@c@host.example/p@q": "a:b%40c",
		"https://host.example/p@q":       "",
		"https://host.example?x=a@b":     "",
		"https://user@host.example#a@b":  "user",
		"host.example/a@b":               "",
	} {
		got := ""
		if info := lenientURLUserinfo(token); info != nil {
			got = info.String()
		}
		if got != want {
			t.Fatalf("lenientURLUserinfo(%q) = %q, want %q", token, got, want)
		}
	}
}
