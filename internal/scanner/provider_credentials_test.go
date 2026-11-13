// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strconv"
	"strings"
)

type providerCredentialFixture struct {
	name    string
	pattern string
	value   string
}

func documentedProviderCredentials() []providerCredentialFixture {
	fixtures := []providerCredentialFixture{
		{name: "1Password Secret Key", pattern: "1Password Secret Key", value: "A3-" + strings.Repeat("B", 6) + "-" + strings.Repeat("C", 11) + strings.Repeat("-D7EF8", 3)},
		{name: "1Password Emergency Kit grouping", pattern: "1Password Secret Key", value: "A3-" + strings.Repeat("B", 6) + "-" + strings.Repeat("C", 6) + strings.Repeat("-D7EF8", 4)},
		{name: "age X25519 identity", pattern: "age Secret Key", value: "AGE-SECRET-KEY-1" + strings.Repeat("GFPYYSJZ", 6) + "GFPQ4EGAEX"},
		{name: "PyPI minimum payload", pattern: "PyPI Token", value: "pypi-" + strings.Repeat("B", 85)},
		{name: "PyPI previous payload", pattern: "PyPI Token", value: "pypi-AgE" + strings.Repeat("C", 90)},
		{name: "PyPI URL alphabet", pattern: "PyPI Token", value: "pypi-" + strings.Repeat("D_", 43) + "-"},
		{name: "Sentry organization payload", pattern: "Sentry Auth Token", value: "sntrys_" + strings.Repeat("QUJD", 12) + "+/==_" + strings.Repeat("A", 42) + "/"},
		{name: "Sentry previous payload", pattern: "Sentry Auth Token", value: "sntrys_" + strings.Repeat("E", 40)},
		{name: "Sentry personal token", pattern: "Sentry Auth Token", value: "sntryu_" + strings.Repeat("ab", 32)},
		{name: "Vault batch token", pattern: "HashiCorp Vault Token", value: "hvb." + strings.Repeat("Ab", 12)},
		{name: "Vault batch base64url token", pattern: "HashiCorp Vault Token", value: "hvb." + "A-b_" + strings.Repeat("Cd", 10) + "-"},
		{name: "Heroku OAuth token", pattern: "Heroku OAuth Token", value: "HRKU-" + strings.Repeat("Ab3_", 15)},
		{name: "Heroku OAuth token with hyphens", pattern: "Heroku OAuth Token", value: "HRKU-" + "-" + strings.Repeat("Ab3_", 7) + "-" + strings.Repeat("Cd4_", 7) + "A-"},
		{name: "Heroku UUID token", pattern: "Heroku OAuth Token", value: "HRKU-" + "01234567-89ab-cdef-0123-" + "456789abcdef"},
		{name: "Bedrock long-term key", pattern: "Amazon Bedrock Long-Term API Key", value: "ABSK" + "QmVkcm9j" + "a0FQSU" + "tleS" + strings.Repeat("Ab", 4) + "+/="},
		{name: "Bedrock short-term key", pattern: "Amazon Bedrock Short-Term API Key", value: "bedrock-" + "api-key-" + bedrockShortPreamble() + "Ab9"},
		{name: "Slack rotating bot token", pattern: "Slack Token", value: "xoxe." + "xoxb-" + strings.Repeat("1a-", 5)},
		{name: "Slack rotating user token", pattern: "Slack Token", value: "xoxe." + "xoxp-" + strings.Repeat("2b-", 5)},
		{name: "Slack rotating app token", pattern: "Slack App Token", value: "xoxe." + "xapp-1-" + strings.Repeat("A", 12) + "-2-" + strings.Repeat("b", 16)},
	}
	for _, kind := range []string{"ct", "pt", "st", "sa", "said", "scim", "audit"} {
		for _, length := range []int{40, 44} {
			fixtures = append(fixtures, providerCredentialFixture{
				name: "Doppler " + kind + " " + strconv.Itoa(length), pattern: "Doppler Token",
				value: "dp." + kind + "." + strings.Repeat("aB3x", length/4),
			})
		}
	}
	for _, environment := range []string{"ab", strings.Repeat("dev-", 8) + "_01"} {
		fixtures = append(fixtures, providerCredentialFixture{
			name: "Doppler service environment " + environment, pattern: "Doppler Token",
			value: "dp.st." + environment + "." + strings.Repeat("cD4y", 10),
		})
	}
	return fixtures
}

// bedrockShortPreamble is the fixed base64 prefix AWS publishes after
// bedrock-api-key-. It is split so the fixture is not one credential-shaped literal.
func bedrockShortPreamble() string {
	return strings.Join([]string{
		"YmVkcm9j",
		"ay5hbWF6",
		"b25hd3Mu",
		"Y29tLz9B",
		"Y3Rpb249",
		"Q2FsbFdp",
		"dGhCZWFy",
		"ZXJUb2tl",
		"biZYLUFt",
		"ei1BbGdv",
		"cml0aG09",
		"QVdTNC1I",
		"TUFDLVNI",
		"QTI1NiZY",
		"LUFtei1D",
		"cmVkZW50",
		"aWFsP",
	}, "")
}
