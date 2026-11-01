// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import "regexp"

// A DEA token has a two-character prefix and seven decimal digits. The
// configured regex selects registrant classes; this extracts that token from
// matches that also include a label, as the numeric validators already do.
var deaTokenRE = regexp.MustCompile(`(?i)\b[A-Z][A-Z9][0-9]{7}\b`)

// validateDEA checks every DEA token in the regex match. An invalid decoy
// cannot hide a later valid token in the same labeled match. The rule regex
// remains responsible for registrant prefixes; letter case is not safety.
// Source: HL7 USDEANumber NamingSystem, structural validation algorithm.
// https://terminology.hl7.org/NamingSystem-USDEANumber.html
func validateDEA(s string) bool {
	for _, loc := range deaTokenRE.FindAllStringIndex(s, -1) {
		token := s[loc[0]:loc[1]]
		// Go's case folding can match non-ASCII letters such as long s.
		// Byte arithmetic below accepts only the nine-byte ASCII shape;
		// the scanner normalizes supported Unicode forms before matching.
		if len(token) != 9 {
			continue
		}
		// Positions 1,3,5 plus twice positions 2,4,6; position 7 is the
		// decimal units digit of that sum.
		sum := int(token[2]-'0') + int(token[4]-'0') + int(token[6]-'0') +
			2*(int(token[3]-'0')+int(token[5]-'0')+int(token[7]-'0'))
		if sum%10 == int(token[8]-'0') {
			return true
		}
	}
	return false
}

// validateNPI checks the CMS NPI check digit with its implied 80840 prefix.
// Like the ABA validator, it extracts digits from the regex match so labeled
// rules can opt in. Shape and labels remain the rule regex's responsibility.
// Source: CMS Requirements for NPI and NPI Check Digit, January 23, 2004.
// https://www.cms.gov/Regulations-and-Guidance/Administrative-Simplification/NationalProvIdentStand/Downloads/NPIcheckdigit.pdf
func validateNPI(s string) bool {
	var digits [10]byte
	n := 0
	for i := range len(s) {
		if !isASCIIDigit(s[i]) {
			continue
		}
		if n == len(digits) {
			return false
		}
		digits[n] = s[i] - '0'
		n++
	}
	if n != len(digits) {
		return false
	}
	// CMS specifies 24 as the Luhn contribution of the implied prefix.
	sum := 24
	for i, digit := range digits {
		d := int(digit)
		if i%2 == 0 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}
