// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDDTrailingCommentProof(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		raw  string
		want bool
	}{
		{"no args", nil, "", false},
		{"split args", []string{"dd", "of=/tmp/safe # of=/etc/cron.d/job"}, "", false},
		{"no comment", []string{"dd of=/tmp/safe"}, "", false},
		{"trailing comment", []string{"dd of=/tmp/safe # of=/etc/cron.d/job"}, "", true},
		{"JSON command", []string{"dd # comment"}, `{"command":"dd # comment"}`, true},
		{"invalid JSON", []string{"dd # comment"}, `{`, false},
		{"JSON array", []string{"dd # comment"}, `["dd # comment"]`, false},
		{"unknown JSON key", []string{"dd # comment"}, `{"content":"dd # comment"}`, false},
		{"extra JSON key", []string{"dd # comment"}, `{"command":"dd # comment","other":"notes"}`, false},
		{"different JSON value", []string{"dd # comment"}, `{"command":"dd of=.bashrc"}`, false},
		{"next command", []string{"dd # comment\ndd of=/etc/cron.d/job"}, "", false},
		{"carriage return", []string{"dd # comment\rdd of=/etc/cron.d/job"}, "", false},
		{"quoted hash", []string{`dd of='/tmp/#notes'`}, "", false},
		{"escaped hash", []string{`dd of=/tmp/safe \# of=/etc/cron.d/job`}, "", false},
		{"quoted path", []string{`dd of='/home/user space/.bashrc' # comment`}, "", true},
		{"unfinished quote", []string{`dd of='/tmp/safe # of=/etc/cron.d/job`}, "", false},
		{"wrapper", []string{"sudo dd # comment"}, "", false},
		{"different utility", []string{"echo dd # comment"}, "", false},
		{"expansion", []string{"dd of=$OUTPUT # comment"}, "", false},
		{"operator", []string{"dd; dd # comment"}, "", false},
		{"redirect", []string{"dd > /etc/cron.d/job # comment"}, "", false},
		{"comment only", []string{"# dd of=/etc/cron.d/job"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ddTrailingCommentViews(tc.args, json.RawMessage(tc.raw)); (got != nil) != tc.want {
				t.Errorf("proof=%v, want %v", got != nil, tc.want)
			}
		})
	}
}

func TestDDCommentCustomRuleRetainsInput(t *testing.T) {
	for _, change := range []func(*config.ToolPolicyRule){
		func(rule *config.ToolPolicyRule) { rule.Name = "Operator Command Rule" },
		func(rule *config.ToolPolicyRule) { rule.ArgPattern += "|operator-match" },
		func(rule *config.ToolPolicyRule) { rule.ToolPattern = "^bash$" },
	} {
		for _, name := range []string{"Persistence Path Write via Command", "Shell Profile Write via Command", "Audit Log Tampering"} {
			rule := ddCommentRules[name]
			change(&rule)
			pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: []config.ToolPolicyRule{rule}})
			assertPolicyCall(t, pc, "bash", map[string]any{"command": "dd of=/tmp/safe # of=/etc/cron.d/job of=.bashrc of=/var/log/auth.log"}, rule.Name, config.ActionBlock)
		}
	}
}
