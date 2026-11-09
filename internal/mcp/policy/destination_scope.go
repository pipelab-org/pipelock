// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
)

var fileWriteValueToolName = regexp.MustCompile(`(?i)^(?:` + builtinToolNameAliasPrefix + `)?(?:` + fileWriteToolPattern + `)$`)

// fileWriteDestinationArgs uses the shipped file-tool pathname contract, not a
// global content-key exemption. Only a flat object with a scalar pathname can
// prove scalar document/edit text is data. Unknown fields remain candidates;
// nested objects, arrays, absent shapes and mismatched values retain every
// submitted value. Executable tools never enter this proof.
func fileWriteDestinationArgs(tool string, values []string, raw json.RawMessage) ([]string, json.RawMessage, bool) {
	if !fileWriteValueToolName.MatchString(tool) {
		return nil, nil, false
	}
	extracted, truncated := ArgValues(raw)
	if truncated || !slices.Equal(values, extracted) {
		return nil, nil, false
	}
	var object map[string]any
	if extract.DecodeJSON(raw, &object) != nil || object == nil {
		return nil, nil, false
	}
	hasPath := false
	for key, value := range object {
		switch value.(type) {
		case map[string]any, []any:
			return nil, nil, false
		}
		if path, ok := value.(string); ok && path != "" && fileDestinationArgumentKey.MatchString(key) {
			hasPath = true
		}
	}
	if !hasPath {
		return nil, nil, false
	}
	for key, value := range object {
		if _, ok := value.(string); !ok || filePathArgumentKey.MatchString(key) {
			continue
		}
		// Scalar data carriers in the file-write/edit contract. A tool with
		// unknown keys does not acquire an exemption merely by having a path.
		switch key {
		case "content", "document", "body", "text", "old_text", "new_text", "old_string", "new_string", "oldText", "newText":
			delete(object, key)
		}
	}
	filtered, err := json.Marshal(object)
	if err != nil {
		return nil, nil, false
	}
	selected, _ := ArgValues(filtered)
	return selected, filtered, true
}

// Only the shipped unscoped persistence/profile write rules use the proof.
// Custom patterns (even with the same name), credential/read rules, shell
// command rules and patch target extraction retain their own matching semantics.
func destinationScopedWriteRule(rule *CompiledRule) bool {
	if rule.ArgPattern == nil || rule.ArgKey != nil || rule.ArgSource != "" || rule.ToolPattern == nil {
		return false
	}
	for _, shipped := range shippedDestinationWriteRules {
		// Presets spell some alternations as capturing groups. MatchString
		// does not read captures, so these spellings have the same contract.
		if rule.Name == shipped.Name && strings.ReplaceAll(rule.ArgPattern.String(), "(?:", "(") == strings.ReplaceAll(shipped.ArgPattern, "(?:", "(") &&
			(rule.ToolPattern.String() == shipped.ToolPattern || rule.ToolPattern.String() == presetToolPattern(shipped.ToolPattern)) {
			return true
		}
	}
	return false
}

var shippedDestinationWriteRules = func() []config.ToolPolicyRule {
	var rules []config.ToolPolicyRule
	for _, rule := range DefaultToolPolicyRules() {
		if (rule.Name == "Persistence Path Write" || rule.Name == "Shell Profile Modification") && rule.ArgSource == "" {
			rules = append(rules, rule)
		}
	}
	return rules
}()

func presetToolPattern(pattern string) string {
	body := strings.TrimPrefix(pattern, `(?i)^(?:`+builtinToolNameAliasPrefix+`)?`)
	return `(?i)^` + builtinToolNameAliasPrefix + `?` + body
}
