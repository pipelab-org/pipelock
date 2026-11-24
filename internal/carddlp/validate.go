// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package carddlp

const (
	MinDigits = 14
	MaxDigits = 19
)

func ValidCardNumber(s string) bool {
	var digits [MaxDigits]byte
	n := 0
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			continue
		}
		if n >= len(digits) {
			return false
		}
		digits[n] = s[i] - '0'
		n++
	}
	if n < MinDigits || !ValidCardIssuer(digits[:n], n) {
		return false
	}
	sum := 0
	for i := n - 1; i >= 0; i-- {
		d := int(digits[i])
		if (n-i)%2 == 0 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// ValidCardIssuer checks the established card network prefixes and lengths.
func ValidCardIssuer(digits []byte, n int) bool {
	// Every issuer length below is at least MinDigits, so shorter
	// input is never a card; the guard also keeps the prefix reads in bounds.
	if n < MinDigits || len(digits) < n {
		return false
	}
	prefix4 := int(digits[0])*1000 + int(digits[1])*100 + int(digits[2])*10 + int(digits[3])
	prefix6 := prefix4*100 + int(digits[4])*10 + int(digits[5])
	// Published ranges: Cybersource's card-type identification reference for
	// Diners (14 digits), and the publisher's Eduction grammar for narrow Maestro
	// and UnionPay. Deliberately exclude broad 12/13-digit Maestro allocations.
	// https://developer.cybersource.com/docs/cybs/en-us/test-data/developer/all/so/test-data/best_practices_intro/card_type_id.html
	// https://www.microfocus.com/documentation/file-analysis-suite/23.4/Fusion_23.4.0_ManageHelpCenter/Content/mng_entites_builtIn.htm
	// https://www.microfocus.com/documentation/idol/IDOL_24_3/EductionSDK_24.3_Documentation/Guides/html/Content/Reference/StandardGrammars/StandardGrammarCompiled_N.htm
	if n >= 16 && n <= 19 {
		switch prefix4 {
		case 5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763:
			return true
		}
	}
	// JCB's merchant guide documents 16-digit UnionPay cards starting 62/81.
	// https://www.jcb.co.jp/merchant/services/payment/unionpay.html
	// Mir's published processor implementation lists 2200-2204 and 16 digits.
	// https://github.com/braintree/credit-card-type/blob/main/src/lib/card-types.ts
	if n == 16 && prefix4 >= 2200 && prefix4 <= 2204 {
		return true
	}
	if digits[0] == 8 && digits[1] == 1 {
		return n == 16
	}
	if digits[0] == 6 && digits[1] == 2 {
		return n >= 16 && n <= 19
	}
	switch digits[0] {
	case 4:
		return n == 16 || n == 19
	case 5:
		return digits[1] >= 1 && digits[1] <= 5 && n == 16
	case 3:
		if n == 16 && (digits[1] == 6 || digits[1] >= 8) {
			return true
		}
		if n == 14 && (prefix4 >= 3000 && prefix4 <= 3059 || prefix4 == 3095 || digits[1] == 6 || digits[1] >= 8) {
			return true
		}
		if digits[1] == 4 || digits[1] == 7 {
			return n == 15
		}
		return prefix4 >= 3528 && prefix4 <= 3589 && n >= 16 && n <= 19
	case 6:
		if prefix4 == 6011 || (prefix4 >= 6440 && prefix4 <= 6499) ||
			(prefix6 >= 622126 && prefix6 <= 622925) || digits[1] == 5 {
			return n == 16 || n == 19
		}
	case 2:
		return prefix4 >= 2221 && prefix4 <= 2720 && n == 16
	}
	return false
}
