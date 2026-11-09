// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
)

// Only the shipped dd-aware rules may use the literal trailing-comment proof.
// Custom rules retain whole-input matching, even when they reuse a rule name.
var ddCommentRules = func() map[string]config.ToolPolicyRule {
	patterns := make(map[string]config.ToolPolicyRule)
	for _, rule := range DefaultToolPolicyRules() {
		switch rule.Name {
		case "Persistence Path Write via Command", "Shell Profile Write via Command", "Audit Log Tampering":
			patterns[rule.Name] = rule
		}
	}
	return patterns
}()

func ddCommentRule(rule *CompiledRule) bool {
	shipped, ok := ddCommentRules[rule.Name]
	return ok && rule.ArgPattern != nil && rule.ToolPattern != nil && rule.ArgKey == nil && rule.ArgSource == "" &&
		rule.ArgPattern.String() == shipped.ArgPattern &&
		(rule.ToolPattern.String() == shipped.ToolPattern || rule.ToolPattern.String() == presetToolPattern(shipped.ToolPattern))
}

// ddTrailingCommentViews prevents pairwise matching from promoting a comment's
// of= text into an output operand. POSIX Shell Command Language 2.3 discards a
// word-starting, unquoted # through the end of the line. Only a literal dd
// command without operators can use this reading; expansions, wrappers,
// additional JSON fields and multiple lines retain whole-input matching.
func ddTrailingCommentViews(args []string, raw json.RawMessage) []argView {
	if len(args) != 1 || strings.ContainsAny(args[0], "\r\n") || !strings.Contains(args[0], "#") {
		return nil
	}
	if len(raw) != 0 {
		var object map[string]any
		if extract.DecodeJSON(raw, &object) != nil || len(object) != 1 || object["command"] != args[0] {
			return nil
		}
	}
	source := args[0]
	for _, word := range shellPathWords(source) {
		if source[word.start] != '#' {
			continue
		}
		prefix := source[:word.start]
		words, ok := shellProofWords(prefix)
		if !ok || len(words) == 0 || words[0].value != "dd" {
			return nil
		}
		for _, w := range words {
			if !w.literal || w.operator {
				return nil
			}
		}
		return buildArgViews([]string{prefix}, false, nil, true)
	}
	return nil
}
