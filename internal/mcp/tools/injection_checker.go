// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ResourceLimitInjectionChecker refuses a tools/list whose descriptions the
// selected external checker could not assess in block mode.
const ResourceLimitInjectionChecker = "injection_checker_unavailable"

// CheckerPatternPrefix prefixes an external checker finding's pattern name.
const CheckerPatternPrefix = "checker:"

// descriptionCheck is the external checker's result for one tools/list.
type descriptionCheck struct {
	ext     scanner.ExternalAssessment
	flagged map[int]bool // tool indexes a finding cites; nil means every tool
}

// assessToolDescriptions sends every tool's scanned text to the checker that
// owns the description surface, as one item with independently attributed views. ok is
// false when the built-in checker decides descriptions or the mode is off.
func assessToolDescriptions(ctx context.Context, sc *scanner.Scanner, prescans []toolPrescan) (descriptionCheck, bool) {
	set := sc.InjectionCheckers()
	surface := config.InjectionSurfaceMCPToolDescription
	if !set.External(surface) && !set.Watches(surface) {
		return descriptionCheck{}, false
	}
	texts := make([]string, len(prescans))
	for i, pre := range prescans {
		texts[i] = pre.text
	}
	item := sc.BuildToolDescriptionInjectionItem(ctx, texts)
	if len(item.Parts) == 0 && item.Completeness.Status == checker.Complete {
		return descriptionCheck{}, false
	}
	ext, ok := sc.AssessInjection(ctx, surface, item)
	if !ok {
		return descriptionCheck{}, false
	}
	out := descriptionCheck{ext: ext}
	if ext.Finding() && ext.Assessment.Response != nil {
		for _, f := range ext.Assessment.Response.Findings {
			for _, id := range f.PartIDs {
				rest, found := strings.CutPrefix(id, scanner.ToolDescriptionPartPrefix)
				if !found {
					continue
				}
				idx, err := strconv.Atoi(strings.SplitN(rest, ":", 2)[0])
				if err != nil {
					continue
				}
				if out.flagged == nil {
					out.flagged = map[int]bool{}
				}
				out.flagged[idx] = true
			}
			if len(f.PartIDs) == 0 {
				// A finding that cites nothing applies to every tool.
				out.flagged = nil
				break
			}
		}
	}
	return out, true
}

// flags reports whether a finding applies to the tool at index.
func (d descriptionCheck) flags(index int) bool {
	return d.ext.Finding() && (d.flagged == nil || d.flagged[index])
}

// descriptionsWithheld reports whether the description surface is decided by
// an external checker in block mode that did not return a complete benign
// assessment or a finding.
func descriptionsWithheld(sc *scanner.Scanner, a scanner.InjectionAssessment) bool {
	b, ok := sc.InjectionCheckers().Decider(config.InjectionSurfaceMCPToolDescription)
	if !ok || b.Policy.Mode != checker.ModeBlock {
		return false
	}
	return a.Checker != b.Name || (a.Status != scanner.AssessmentBenign && a.Status != scanner.AssessmentFinding)
}

// CheckerBlocked reports whether an external checker in block mode found
// injection in this list's descriptions. Such a list is refused whatever
// mcp_tool_scanning.action says: the checker's mode decides.
func (r ToolScanResult) CheckerBlocked() bool {
	for _, m := range r.Matches {
		for _, inj := range m.Injection {
			if strings.HasPrefix(inj.PatternName, CheckerPatternPrefix) {
				return true
			}
		}
	}
	return false
}
