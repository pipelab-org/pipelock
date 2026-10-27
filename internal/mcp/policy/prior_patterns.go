// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"regexp"
	"sync"
)

// priorArgPatterns maps a built-in or preset argument pattern to the
// pattern it replaced. A rule with one of these patterns also matches
// whatever the replaced pattern matched, read the way it was read before
// (see priorMatch), so revising a pattern or splitting a command string
// never lets through a call the earlier pattern caught.
var priorArgPatterns = map[string][]string{
	// Destructive File Delete
	`(?i)\brm(?:\s+[^\s;|&]+)*?\s+(-[a-z]*[rf][a-z]*\b|--(?:recursive|force)\b)`: {
		`(?i)\brm\s+(--\s+)?(-[a-z]*[rf]\b|--(?:recursive|force)\b)`,
	},
	// Destructive Git Operation
	`(?i)(\bgit\s+)?(push(?:\s+[^\s;|&]+)*?\s+(--force(?:[\s;&|()<>]|$)|-[a-z]*f[a-z]*\b|\+[^\s;|&]+)|reset(?:\s+[^\s;|&]+)*?\s+--hard\b|clean(?:\s+[^\s;|&]+)*?\s+(-[a-z]*(f[a-z]*d|d[a-z]*f)[a-z]*\b|-[a-z]*f[a-z]*(?:\s+[^\s;|&]+)*?\s+-[a-z]*d[a-z]*\b|-[a-z]*d[a-z]*(?:\s+[^\s;|&]+)*?\s+-[a-z]*f[a-z]*\b))`: {
		`(?i)(\bgit\s+)?(push\s+(--force(\s|$)|-f\b)|reset\s+--hard\b|clean\s+-fd\b)`,
	},
	// Detached Process Spawning
	`(?i)(\bnohup\s+|\bdisown\b|\bsetsid\s+|\bscreen\s+(-\S+\s+)*-[dDm]|\btmux(?:\s+[^\s;|&]+)*?\s+(new-session|new)(?:\s+[^\s;|&]+)*?\s+-[a-z]*d)`: {
		`(?i)(\bnohup\s+|\bdisown\b|\bsetsid\s+|\bscreen\s+(-\S+\s+)*-[dDm]|\btmux\s+(new-session|new)\s+-d)`,
	},
	// Disk Wipe Command
	`(?i)\b(dd\b.*of=/dev/|mkfs\.|fdisk|sfdisk|mke2fs|blkdiscard|mkfs(?:\s+[^\s;|&]+)*?\s+(?:-t|/dev/)|wipefs(?:\s+[^\s;|&]+)*?\s+(?:-[a-z]*[ao][a-z]*|--all|--offset)|sgdisk(?:\s+[^\s;|&]+)*?\s+(?:-[a-z]*z[a-z]*|--zap(?:-all)?))\b`: {
		`(?i)\b(dd\s+if=.*of=/dev/|mkfs\.|fdisk)\b`,
	},
	// Encoded Command Execution
	`(?i)(\beval\b.*\bbase64\b|\bbase64(?:\s+[^\s;|&]+)*?\s+(-[a-z]*d[a-z]*|--decode)\b.*\|\s*(?:(?:sudo|env|exec|command)(?:\s+[^\s;|&]+)*?\s+)?(?:[^\s;|&]*/)?((ba)?sh|zsh|dash|ksh|mksh)\b)`: {
		`(?i)(\beval\b.*\bbase64\b|\bbase64\s+(-d|--decode)\b.*\|\s*(ba)?sh\b)`,
	},
	// Network Exfiltration
	`(?i)\b(curl|wget)\b.*(-d\s|-F\s|-T\s|--data(?:-binary|-raw|-urlencode)?\b|--form\b|--upload-file\b|--post-data\b|--post-file\b|--body-data\b|--body-file\b|-X\s+POST|--json\b|--form-string\b)|\bcurl\b.*\s(?-i:-[a-zA-Z0-9]+[dFT])`: {
		`(?i)\b(curl|wget)\b.*(-d\s|--data|--upload-file|-T\s|-X\s+POST|--post-data)`,
	},
	// Package Install
	`(?i)\b(pip3?|npm|gem|cargo|go)(?:\s+-[^\s;|&]*(?:\s+[^-\s;|&][^\s;|&]*)?)*\s+install\b|\b(npm|pnpm|yarn|bun)(?:\s+-[^\s;|&]*(?:\s+[^-\s;|&][^\s;|&]*)?)*\s+(i|in|ins|inst|insta|instal|isnt|isnta|isntal|isntall|add)\b|\b(uv|poetry|cargo)(?:\s+-[^\s;|&]*(?:\s+[^-\s;|&][^\s;|&]*)?)*\s+add\b`: {
		`(?i)\b(pip|npm|gem|cargo|go)\s+install\b`,
	},
	// Recursive Permission Change
	`(?i)\b(chmod(?:\s+[^\s;|&]+)*?\s+(-[a-z]*r[a-z]*|--recursive)(?:\s+[^\s;|&]+)*?\s+(0?(?:777|666)|(?:[ugoa]*[+=-][rwxXst]*,)*[ugo]*[ao][ugoa]*[+=][rwxXst]*w[rwxXst]*(?:,[ugoa]*[+=-][rwxXst]*)*)|chmod(?:\s+[^\s;|&]+)*?\s+(0?(?:777|666)|(?:[ugoa]*[+=-][rwxXst]*,)*[ugo]*[ao][ugoa]*[+=][rwxXst]*w[rwxXst]*(?:,[ugoa]*[+=-][rwxXst]*)*)(?:\s+[^\s;|&]+)*?\s+(-[a-z]*r[a-z]*|--recursive)|chown(?:\s+[^\s;|&]+)*?\s+(-[a-z]*r[a-z]*|--recursive))\b`: {
		`(?i)\b(chmod\s+(-R|--recursive)\s+(777|666)|chmod\s+(777|666)\s+(-R|--recursive)|chown\s+(-R|--recursive))\b`,
	},
	// Reverse Shell
	`(?i)(bash\s+-i\s+>&|/dev/tcp/|mkfifo\s+|nc\s+-e|ncat\s+-e|\b(?:nc|ncat|netcat)(?:\s+[^\s;|&]+)*?\s+-[a-z0-9]*e\b|\b(?:nc|ncat|netcat)(?:\s+[^\s;|&]+)*?\s+((?-i:-[a-z0-9]*c)\b|--(?:sh-|lua-)?exec\b)|\bbash(?:\s+-[a-z]+)*?\s+-[a-z]*i[a-z]*(?:\s+-[a-z]+)*?\s+>&|/dev/udp/)`: {
		`(?i)(bash\s+-i\s+>&|/dev/tcp/|mkfifo\s+|nc\s+-e|ncat\s+-e)`,
	},
}

var (
	priorCompiled     map[string][]*regexp.Regexp
	priorCompiledOnce sync.Once
)

// priorPatterns returns the patterns pat replaced, or nil when it is not a
// revised pattern.
func priorPatterns(pat *regexp.Regexp) []*regexp.Regexp {
	priorCompiledOnce.Do(func() {
		priorCompiled = make(map[string][]*regexp.Regexp, len(priorArgPatterns))
		for p, prev := range priorArgPatterns {
			for _, s := range prev {
				priorCompiled[p] = append(priorCompiled[p], regexp.MustCompile(s))
			}
		}
	})
	return priorCompiled[pat.String()]
}

// priorMatch reports whether pat matches tokens as the argument check read
// them before commands in one string were told apart: the joined list, each
// token, and, up to maxPairwiseTokens tokens, every ordered pair.
func priorMatch(pat *regexp.Regexp, tokens []string, joined string, folds map[string]string) bool {
	if matchPatternWithFold(pat, joined, folds) {
		return true
	}
	for _, t := range tokens {
		if matchPatternWithFold(pat, t, folds) {
			return true
		}
	}
	if len(tokens) <= maxPairwiseTokens {
		for i, a := range tokens {
			for j, b := range tokens {
				if i != j && matchPatternWithFold(pat, a+" "+b, folds) {
					return true
				}
			}
		}
	}
	return false
}
