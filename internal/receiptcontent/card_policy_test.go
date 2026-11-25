// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCardReceiptPolicyDominatesTraffic(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.CardBareAction = config.ActionWarn
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	pan := cardtest.Issuer("4019", 16)
	for split := 1; split < len(pan); split++ {
		for _, sep := range []string{".", "\t", "\r", "\n", ",", "\u200b"} {
			detail := mustJSON(t, map[string]any{"note": pan[:split] + sep + pan[split:]})
			rep, err := scanDetail(t, sc.ScanTextForReceiptDLP, detail)
			if err != nil || rep.Clean() {
				t.Fatalf("split %d sep %q clean=%v err=%v", split, sep, rep.Clean(), err)
			}
		}
		detail := mustJSON(t, map[string]any{"list": []string{strings.Repeat("4242", 4), pan[:split], pan[split:], strings.Repeat("4242", 4)}})
		rep, err := scanDetail(t, sc.ScanTextForReceiptDLP, detail)
		if err != nil || rep.Clean() {
			t.Fatalf("cross-field split %d: %+v %v", split, rep, err)
		}
	}
	rep, err := scanDetail(t, sc.ScanTextForReceiptDLP, mustJSON(t, map[string]any{"note": strings.Repeat("4242", 4)}))
	if err != nil || !rep.Clean() {
		t.Fatalf("public example: %+v %v", rep, err)
	}
}

func TestCardReceiptPublishedControlsAndKnownValue(t *testing.T) {
	public := strings.Repeat("4242", 4)
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	for _, sep := range []string{"\t", "\r", "\n"} {
		text := "0." + cardtest.Grouped(public, sep)
		uri := "https://api.vendor.example/" + url.QueryEscape(text)
		for _, value := range []string{text, base64.StdEncoding.EncodeToString([]byte(text)), uri, base64.StdEncoding.EncodeToString([]byte(uri))} {
			rep, err := scanDetail(t, sc.ScanTextForReceiptDLP, mustJSON(t, map[string]any{"note": value}))
			if err != nil || !rep.Clean() {
				t.Fatalf("published fixture %q refused: %+v %v", value, rep, err)
			}
		}
	}
	cfg.CanaryTokens = config.CanaryTokens{Enabled: true, Tokens: []config.CanaryToken{{Name: "fixture_secret", Value: public}}}
	known := scanner.MustNew(cfg)
	defer known.Close()
	rep, err := scanDetail(t, known.ScanTextForReceiptDLP, mustJSON(t, map[string]any{"note": public}))
	if err != nil || rep.Clean() {
		t.Fatalf("fixture exemption erased known secret: %+v %v", rep, err)
	}
}

func TestCardReceiptEncodedSeparators(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.CardBareAction = config.ActionWarn
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	pan := cardtest.Issuer("4019", 16)
	for _, text := range []string{pan[:4] + "." + pan[4:], cardtest.Grouped(pan, "\t"), cardtest.Grouped(pan, "\n")} {
		structured, err := json.Marshal(map[string]string{"value": text})
		if err != nil {
			t.Fatal(err)
		}
		for _, payload := range []string{text, string(structured)} {
			for _, encoded := range []string{base64.StdEncoding.EncodeToString([]byte(payload)), hex.EncodeToString([]byte(payload)), url.QueryEscape(payload)} {
				rep, err := scanDetail(t, sc.ScanTextForReceiptDLP, mustJSON(t, map[string]any{"note": encoded}))
				if err != nil || rep.Clean() {
					t.Fatalf("decoded split %q was signed clean: %+v %v", encoded, rep, err)
				}
			}
		}
	}
}

func TestCardReceiptFixtureDoesNotHideEncodedCard(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.CardBareAction = config.ActionWarn
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	pan := cardtest.Issuer("4019", 16)
	text := "0." + cardtest.Grouped(strings.Repeat("4242", 4), "\t") + " " + base64.StdEncoding.EncodeToString([]byte(cardtest.Grouped(pan, "\t")))
	rep, err := scanDetail(t, sc.ScanTextForReceiptDLP, mustJSON(t, map[string]any{"note": text}))
	if err != nil || rep.Clean() {
		t.Fatalf("fixture hid encoded real card: %+v %v", rep, err)
	}
}

func TestCardReceiptTrafficDetectorFloor(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.CardBareAction = config.ActionWarn
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	for _, value := range []string{cardtest.Issuer("4019", 16), strings.Repeat("4242", 4)} {
		if !sc.ScanTextForDLPQuiet(t.Context(), value).Clean {
			t.Fatal("traffic control did not pass")
		}
		rep, err := scanDetail(t, sc.ScanTextForDLPQuiet, mustJSON(t, map[string]string{"note": value}))
		wantClean := value == strings.Repeat("4242", 4)
		if err != nil || rep.Clean() != wantClean {
			t.Fatalf("receipt floor clean=%v want=%v err=%v", rep.Clean(), wantClean, err)
		}
	}
}

func TestCardReceiptIdentifierProjection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	id := "97304a31-7c5d-4f4e-2560-" + "783810564780"
	raw := mustJSON(t, map[string]string{"id": id, "target": "https://api.vendor.example:8443/" + id, "verdict": "allow"})
	proj, err := testProducer.Project(raw)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Scan(t.Context(), sc.ScanTextForReceiptDLP, proj)
	if err != nil || !rep.Clean() {
		t.Fatalf("identity/URL projection refused: %+v %v", rep, err)
	}
}

func TestCardReceiptURLContent(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	pan := cardtest.Issuer("4019", 16)
	for _, value := range []string{
		"https://api.vendor.example:8443/folder/" + pan,
		"https://api.vendor.example:8443/folder/" + cardtest.Grouped(pan, "/"),
		"https://api.vendor.example:8443/folder/?card=" + pan,
	} {
		rep, err := scanDetail(t, sc.ScanTextForReceiptDLP, mustJSON(t, map[string]string{"target": value}))
		if err != nil || rep.Clean() {
			t.Errorf("URL card passed: %s (%v)", value, err)
		}
	}
}
