// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestURLUserinfoRecoveredPercentLimit(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = nil
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	s := MustNew(cfg)
	defer s.Close()
	for name, value := range map[string]string{"benign": "ordinary", "credential": inspectionLimitAWSKey()} {
		for _, rounds := range []int{1, maxDecodeRounds, maxDecodeRounds + 20} {
			percent := percentEncodeN(value[:1], rounds) + value[1:]
			for encoding, encoded := range map[string]string{
				"base64": base64.StdEncoding.EncodeToString([]byte(percent)),
				"hex":    hex.EncodeToString([]byte(percent)),
			} {
				for field, user := range map[string]*url.Userinfo{"username": url.User(encoded), "password": url.UserPassword("reader", encoded)} {
					u := &url.URL{Scheme: "https", Host: "api.vendor.example", Path: "/read", User: user}
					for parse, target := range map[string]string{"parsed": u.String(), "unparsed": u.String() + "%zz"} {
						t.Run(fmt.Sprintf("%s/%d/%s/%s/%s", name, rounds, encoding, field, parse), func(t *testing.T) {
							got := s.ScanURLCoreFloor(target)
							wantLimit := rounds > maxDecodeRounds
							wantAllowed := name == "benign" && !wantLimit
							if got.Allowed != wantAllowed || IsURLInspectionLimitResult(got) != wantLimit {
								t.Fatalf("Allowed=%v limit=%v, want allowed=%v limit=%v: %s", got.Allowed, IsURLInspectionLimitResult(got), wantAllowed, wantLimit, got.Reason)
							}
						})
					}
				}
			}
		}
	}
}
