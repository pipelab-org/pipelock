// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package carddlp

import "strings"

// Stripe publishes these PANs for simulating successful payments by card brand:
// https://docs.stripe.com/testing#cards
var publicTestPANs = func() map[string]struct{} {
	groups := [][]string{
		{"4242", "4242", "4242", "4242"},
		{"4000", "0566", "5566", "5556"},
		{"5555", "5555", "5555", "4444"},
		{"2223", "0031", "2200", "3222"},
		{"5200", "8282", "8282", "8210"},
		{"5105", "1051", "0510", "5100"},
		{"3782", "822463", "10005"},
		{"3714", "496353", "98431"},
		{"6011", "1111", "1111", "1117"},
		{"6011", "0009", "9013", "9424"},
		{"6011", "9811", "1111", "1113"},
		{"3056", "9300", "0902", "0004"},
		{"3622", "7206", "2716", "67"},
		{"6555", "9000", "0060", "4105"},
		{"3566", "0020", "2036", "0505"},
		{"6200", "0000", "0000", "0005"},
		{"6200", "0000", "0000", "0047"},
		{"6205", "5000", "0000", "0000", "004"},
	}
	pans := make(map[string]struct{}, len(groups))
	for _, groups := range groups {
		pans[strings.Join(groups, "")] = struct{}{}
	}
	return pans
}()

// IsPublicTestPAN reports whether candidate is one of the exact published
// test PANs, regardless of its supported presentation.
func IsPublicTestPAN(candidate string) bool {
	var digits [19]byte
	n := 0
	for i := range len(candidate) {
		switch b := candidate[i]; {
		case digit(b):
			if n == len(digits) {
				return false
			}
			digits[n] = b
			n++
		case !urlSeparator(b):
			return false
		}
	}
	_, ok := publicTestPANs[string(digits[:n])]
	return ok
}
