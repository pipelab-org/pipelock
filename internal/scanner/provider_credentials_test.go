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
		{name: "age X25519 identity", pattern: "age Secret Key", value: "AGE-SECRET-KEY-1" + strings.Repeat("GFPYYSJZ", 6) + "GFPQ4EGAEX"},
		{name: "PyPI minimum payload", pattern: "PyPI Token", value: "pypi-" + strings.Repeat("B", 85)},
		{name: "PyPI previous payload", pattern: "PyPI Token", value: "pypi-AgE" + strings.Repeat("C", 90)},
		{name: "PyPI URL alphabet", pattern: "PyPI Token", value: "pypi-" + strings.Repeat("D_", 43) + "-"},
		{name: "Sentry organization payload", pattern: "Sentry Auth Token", value: "sntrys_" + strings.Repeat("QUJD", 12) + "+/==_" + strings.Repeat("A", 42) + "/"},
		{name: "Sentry previous payload", pattern: "Sentry Auth Token", value: "sntrys_" + strings.Repeat("E", 40)},
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
