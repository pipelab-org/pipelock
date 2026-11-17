// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

const decodeRunMarker = "Marker"

func decodeRunScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: decodeRunMarker, Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	return sc
}

// decodeRunCarrier reaches its marker only through the decoded outer view's
// separated run, so reassembly observation of that decode decides the finding.
func decodeRunCarrier() string {
	inner := strings.Repeat("a!", 600) + reassemblyBang(base64.RawStdEncoding.EncodeToString([]byte("MARK1234")))
	return base64.StdEncoding.EncodeToString([]byte(inner))
}

type decodeRunState struct {
	incomplete              bool
	retainedBytes           int
	views, replayPayloads   int
	reassemblyDecoded       int
	reassemblyDecodedBytes  int
	sharedViews, sharedUsed int
	clean                   bool
	names                   []string
}

func observeDecodeRunState(memo *decodingMemo) decodeRunState {
	state := decodeRunState{
		incomplete:             memo.incomplete,
		retainedBytes:          memo.retainedBytes,
		views:                  len(memo.views),
		replayPayloads:         memo.reassemblyReplayPayloadCount,
		reassemblyDecoded:      len(memo.reassemblyDecoded),
		reassemblyDecodedBytes: memo.reassemblyDecodedBytes,
	}
	if memo.shared != nil {
		state.sharedViews, state.sharedUsed = len(memo.shared.store.views), memo.shared.store.retainedBytes
	}
	result := finishAssembled(TextDLPResult{Clean: true}, memo)
	state.clean = result.Clean
	state.names = matchNames(result.Matches)
	return state
}

// decodeAgain must do everything a second decode of the same key does,
// except recompute it: same views, retention, incomplete flag and reassembly
// observation, on the local and shared stores, retained or not.
func TestDecodeAgainMatchesRepeatedDecode(t *testing.T) {
	sc := decodeRunScanner(t)
	text := decodeRunCarrier()
	for _, tc := range []struct {
		name           string
		shared, full   bool
		wantRecomputed bool
	}{
		{name: "local retained"},
		{name: "local unretained", full: true, wantRecomputed: true},
		{name: "shared retained", shared: true},
		{name: "shared unretained", shared: true, full: true, wantRecomputed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newMemo := func() *decodingMemo {
				memo := &decodingMemo{reassemblyPlan: sc.reassemblyPlan, reassemblyDeferred: true}
				if tc.shared {
					memo.shared = &sharedDecodes{}
				}
				if tc.full {
					memo.retainedBytes = maxDecodeTotalBytes
					if memo.shared != nil {
						memo.shared.store.retainedBytes = maxDecodeTotalBytes
					}
				}
				t.Cleanup(memo.releaseProjection)
				return memo
			}
			before := newMemo()
			first := before.decode(text, true)
			again := before.decode(text, true)
			after := newMemo()
			once, run := after.decodeOnce(text)
			replayed := after.decodeAgain(text, run)
			if len(first) == 0 || !reflect.DeepEqual(first, again) || !reflect.DeepEqual(once, replayed) || !reflect.DeepEqual(first, replayed) {
				t.Fatal("replayed views differ from a repeated decode")
			}
			// The repeated decode recomputes an unretained result; the replay
			// reuses the caller's run.
			if recomputed := &again[0] != &first[0]; recomputed != tc.wantRecomputed {
				t.Fatalf("repeated decode recomputed=%v, want %v", recomputed, tc.wantRecomputed)
			}
			if &replayed[0] != &once[0] {
				t.Fatal("decodeAgain recomputed a run the caller held")
			}
			want, got := observeDecodeRunState(before), observeDecodeRunState(after)
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("memo state after replay %+v, after repeated decode %+v", got, want)
			}
			if want.clean || !slices.Contains(want.names, decodeRunMarker) {
				t.Fatalf("reassembled marker was not found: %+v", want)
			}
		})
	}
}

// A run made under another direction or completeness state is not this
// call's decode. It is ignored and the decode is recomputed.
func TestDecodeAgainIgnoresMismatchedRun(t *testing.T) {
	text := decodeRunCarrier()
	for _, tc := range []struct {
		name  string
		flip  func(*decodingMemo)
		other string
	}{
		{name: "direction", flip: func(m *decodingMemo) { m.inbound = true }},
		{name: "text", other: base64.StdEncoding.EncodeToString([]byte("other carrier text"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memo := &decodingMemo{retainedBytes: maxDecodeTotalBytes}
			_, run := memo.decodeOnce(text)
			again := text
			if tc.other != "" {
				again = tc.other
			}
			if tc.flip != nil {
				tc.flip(memo)
			}
			got := memo.decodeAgain(again, run)
			fresh := (&decodingMemo{retainedBytes: maxDecodeTotalBytes, inbound: memo.inbound}).decode(again, true)
			if !reflect.DeepEqual(got, fresh) || len(got) > 0 && len(run.views) > 0 && &got[0] == &run.views[0] {
				t.Fatal("a mismatched run replaced the decode")
			}
		})
	}
	var nilMemo *decodingMemo
	views, run := nilMemo.decodeOnce(text)
	if run.set || !reflect.DeepEqual(nilMemo.decodeAgain(text, run), views) {
		t.Fatal("a memo-less decode recorded a run")
	}
}

// Known-value checks over the cleaned and raw text, with env and file sets,
// report exactly what four separate checks report, in the same order.
func TestCheckSecretLeaksMatchesSeparateChecks(t *testing.T) {
	envValue := "envTok" + "R7qW2zX9pL4mN8vB"
	fileValue := "fileTok" + "Q7mZp2Lx9Vr4Tn8K"
	t.Setenv("PIPELOCK_DECODE_RUN_TOKEN", envValue)
	path := filepath.Join(t.TempDir(), "secrets")
	if err := os.WriteFile(path, []byte(fileValue+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = true
	cfg.DLP.SecretsFile = path
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	if !slices.Contains(sc.envSecrets, envValue) || !slices.Contains(sc.fileSecrets, fileValue) {
		t.Fatal("test values were not loaded")
	}
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	decoy := "decoy " + b64("ordinary decoy text value") + " "
	cases := map[string]string{
		"clean prose":       "status report for api.vendor.example is ready",
		"late file secret":  decoy + strings.Repeat("filler ", 200) + fileValue,
		"encoded env":       decoy + "token=" + b64(envValue),
		"tagged file":       "note " + decodeRunTags(fileValue) + " " + b64("x"),
		"percent file":      "q=" + url.QueryEscape(fileValue+"+"+envValue) + " " + b64("carrier"),
		"partial in base64": decoy + b64("prefix "+fileValue[:18]),
		"malformed carrier": base64.RawStdEncoding.EncodeToString([]byte("key="+envValue+" tail")) + "*~",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			separate := &decodingMemo{}
			cleaned := separate.normalize(text)
			var want []TextDLPMatch
			want = append(want, sc.checkSecretsInTextWithDecodes(sc.envSecrets, cleaned, "Environment Variable Leak", "env", separate)...)
			want = append(want, sc.checkSecretsInTextWithDecodes(sc.fileSecrets, cleaned, "Known Secret Leak", "", separate)...)
			if normalize.ContainsTags(text) || (hasTextEncoding(text) && text != cleaned) {
				want = append(want, sc.checkSecretsInTextWithDecodes(sc.envSecrets, text, "Environment Variable Leak", "env", separate)...)
				want = append(want, sc.checkSecretsInTextWithDecodes(sc.fileSecrets, text, "Known Secret Leak", "", separate)...)
			}
			joined := &decodingMemo{}
			got := sc.checkSecretLeaks(joined.normalize(text), text, joined)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("joined checks %+v, separate checks %+v", got, want)
			}
			if wantFinding := name != "clean prose"; (len(got) > 0) != wantFinding {
				t.Fatalf("finding presence %v, want %v: %+v", len(got) > 0, wantFinding, got)
			}
			if joined.incomplete != separate.incomplete {
				t.Fatal("joined checks changed the completeness result")
			}
		})
	}
}

// decodeRunTags writes ASCII as Unicode tag characters (U+E0000 + byte).
func decodeRunTags(s string) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteRune(0xE0000 + r)
	}
	return b.String()
}

// The synthetic pause isolates continuation ordering. This doesn't construct
// an input whose production decode graph exceeds the candidate limit.
func TestResumedKnownTailContainsCredential(t *testing.T) {
	cred := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	malformed := base64.RawStdEncoding.EncodeToString([]byte("key="+cred+" ok")) + "*~"
	// The walk recovers the prefix only after a candidate pause.
	prefix := make([]decodedResult, maxDecodeCandidates)
	seen := newDecodeSeen(malformed)
	for i := range prefix {
		prefix[i] = decodedResult{text: "prior view " + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + strings.Repeat("y", i/26), encoding: encodingURL}
		seen.add(prefix[i].text)
	}
	state := newOutboundDecodeState(prefix, []string{malformed}, seen, outboundDecodeOptions{includeURL: true, minPrefix: minKnownSecretSubstringLen})
	out, _, paused := state.run()
	if !paused || slices.ContainsFunc(out, func(d decodedResult) bool { return strings.Contains(d.text, cred) }) {
		t.Fatal("credential prefix was reachable before the pause")
	}
	resumed, _ := state.resume(out, maxDecodeCandidates)
	if !slices.ContainsFunc(resumed[len(out):], func(d decodedResult) bool { return strings.Contains(d.text, cred) }) {
		t.Fatal("credential prefix is not in the resumed tail")
	}
}

// These ordinary scanner inputs exercise malformed prefix recovery with an
// unrelated configured value; they don't force the known-value continuation.
func TestKnownPrefixCredentialPathsStillBlock(t *testing.T) {
	cred := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	malformed := base64.RawStdEncoding.EncodeToString([]byte("key="+cred+" ok")) + "*~"
	path := filepath.Join(t.TempDir(), "secrets")
	if err := os.WriteFile(path, []byte("unrelated"+"Q7mZp2Lx9Vr4Tn8K\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.SecretsFile = path
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	nested := base64.StdEncoding.EncodeToString([]byte(malformed))
	for name, text := range map[string]string{
		"direct":            "note " + malformed + " end",
		"nested":            "note " + nested + " end",
		"early decoy, late": "decoy " + base64.StdEncoding.EncodeToString([]byte("ordinary decoy")) + " " + strings.Repeat("filler ", 300) + nested,
	} {
		t.Run(name, func(t *testing.T) {
			result := sc.ScanTextForDLP(t.Context(), text)
			if result.Clean || HasInspectionLimit(result.Matches) || len(result.Matches) == 0 {
				t.Fatalf("known-prefix credential was not blocked: %+v", result)
			}
			if !strings.Contains(result.Matches[0].PatternName, "AWS") {
				t.Fatalf("unexpected finding %q", result.Matches[0].PatternName)
			}
		})
	}
	// A scan that starts canceled still produces its findings.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result := sc.ScanTextForDLP(ctx, "note "+nested+" end"); result.Clean {
		t.Fatal("canceled scan of the credential returned clean")
	}
}
