// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import "testing"

// TestCurlShortFlagsAreCaseSensitive checks the Network Exfiltration rule's
// short flags. Upload flags -d, -F and -T stay denied, including a combined
// flag that ends in one of them. The same letters in the other case are
// curl's fail, header-dump and telnet options and stay allowed. Long options
// and the tool name stay case-insensitive.
func TestCurlShortFlagsAreCaseSensitive(t *testing.T) {
	runVerdictRows(t, []verdictRow{
		{"data", "curl -d x", ruleNetwork, ""},
		{"form", "curl -F a=@f", ruleNetwork, ""},
		{"upload", "curl -T file", ruleNetwork, ""},
		{"combined form", "curl -sF a=b", ruleNetwork, ""},
		{"long data", "curl --data x", ruleNetwork, ""},
		{"upper tool", "CURL -d x", ruleNetwork, ""},
		{"long form", "curl --form a=b", ruleNetwork, ""},
		{"wget post", "wget --post-data=x", ruleNetwork, ""},
		{"request method", "curl -X POST", ruleNetwork, ""},
		{"lower method", "curl -X post", ruleNetwork, ""},
		{"json", "curl --json {}", ruleNetwork, ""},
		{"upper long data", "curl --DATA x", ruleNetwork, ""},
		{"fail", "curl -f https://api.vendor.example/", "", ""},
		{"fail silent", "curl -fsSL https://api.vendor.example/install.sh", "", ""},
		{"combined fail", "curl -sSf https://api.vendor.example/", "", ""},
		{"header dump", "curl -D headers.txt https://api.vendor.example/", "", ""},
		{"telnet", "curl -t opt=val https://api.vendor.example/", "", ""},
		{"upper fail", "CURL -f https://api.vendor.example/", "", ""},
	})
}
