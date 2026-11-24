// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestCardPresentationProperties(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	for seed := range 8 {
		pan := cardtest.Issuer(fmt.Sprintf("4019%011d", seed), 16)
		groups := []string{pan[:4], pan[4:8], pan[8:12], pan[12:]}
		presentations := []string{pan, `{"x":"` + pan + `"}`, pan[:4] + "\u200b" + pan[4:], base64.StdEncoding.EncodeToString([]byte(pan)), hex.EncodeToString([]byte(pan))}
		var escaped, fullwidth strings.Builder
		for _, r := range pan {
			fmt.Fprintf(&escaped, "%%%02X", r)
			fullwidth.WriteRune(r - '0' + '０')
		}
		presentations = append(presentations, escaped.String(), fullwidth.String())
		for _, sep := range []string{" ", "-", ".", "/", "_", "--", ".-"} {
			presentations = append(presentations, strings.Join(groups, sep))
			presentations = append(presentations, reassemblyBang(base64.StdEncoding.EncodeToString([]byte(strings.Join(groups, sep)))))
		}
		for _, value := range presentations {
			for _, wrap := range [][2]string{{"", ""}, {"0.", "."}, {"\"(", ")\""}, {strings.Repeat("padding ", 1300), ""}, {strings.Repeat("4242", 4) + " ", ""}, {"1234.", " 12/28"}} {
				text := wrap[0] + value + wrap[1]
				for _, scan := range []func(string) TextDLPResult{func(v string) TextDLPResult { return s.ScanTextForDLP(t.Context(), v) }, func(v string) TextDLPResult { return s.ScanTextForDLPInbound(t.Context(), v) }} {
					got := scan(text)
					if got.Clean || !HasEnforcingMatch(got.Matches) {
						t.Fatalf("seed=%d value=%q wrap=%q: expected block, got %+v", seed, value, wrap, got)
					}
					for _, m := range got.Matches {
						if m.IsInformational() {
							t.Fatal("informational evidence in Matches")
						}
					}
				}
			}
		}
		for _, scheme := range []string{"http", "HTTPS", "ws", "wss", "ftp", "ftps", "sftp", "file"} {
			for _, tail := range []string{"api.vendor.example/" + pan, "api.vendor.example/?a=" + pan[:8] + "&b=" + pan[8:], "a." + strings.Join(groups, ".") + ".vendor.example/", "a." + pan[:4] + "-" + pan[4:8] + "." + pan[8:12] + "-" + pan[12:] + ".vendor.example/", "api.vendor.example/path/" + pan[:4] + "." + pan[4:], "api.vendor.example/path/" + pan[:4] + "///" + pan[4:], "api.vendor.example/path/" + pan[:4] + "!!!" + pan[4:], "api.vendor.example/" + strings.Repeat("p", 8200) + "/" + pan[:4] + "." + pan[4:]} {
				url := scheme + "://" + tail
				if got := s.ScanTextForDLP(t.Context(), "see ("+url+")."); got.Clean {
					t.Fatalf("embedded URL %s: %+v", url, got)
				}
				// Destination protocol policy rejects non-HTTP schemes before DLP.
				if scheme == "http" || scheme == "HTTPS" {
					if got := s.Scan(t.Context(), url); got.Allowed {
						t.Fatalf("URL allowed: %s", url)
					}
				}
			}
		}
		for _, text := range []string{"F27=" + pan[:4] + "." + pan[4:], pan[:8] + "\t" + pan[8:], pan[:8] + "\n" + pan[8:], strings.Join(groups, ","), pan[:8] + " " + pan[8:]} {
			for _, value := range []string{text, base64.StdEncoding.EncodeToString([]byte(text)), reassemblyBang(base64.StdEncoding.EncodeToString([]byte(text)))} {
				got := s.ScanTextForDLP(t.Context(), value)
				if !got.Clean || len(got.Findings()) != 0 {
					t.Fatalf("noncanonical input %q: %+v", value, got)
				}
			}
		}
	}
}
