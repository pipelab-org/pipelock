// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ResourceLimitInjectionChecker refuses a tools/list whose descriptions the
// selected external checker could not assess in block mode.
const ResourceLimitInjectionChecker = "injection_checker_unavailable"

// CheckerPatternPrefix prefixes an external checker finding's pattern name.
const CheckerPatternPrefix = "checker:"

const toolPartPrefix = "tool:"

// descriptionCheck is the external checker's result for one tools/list.
type descriptionCheck struct {
	ext     scanner.ExternalAssessment
	flagged map[int]bool // tool indexes a finding cites; nil means every tool
}

// assessToolDescriptions sends every tool's scanned text to the checker that
// owns the description surface, as one item with one part per tool. ok is
// false when the built-in checker decides descriptions or the mode is off.
func assessToolDescriptions(ctx context.Context, sc *scanner.Scanner, prescans []toolPrescan) (descriptionCheck, bool) {
	set := sc.InjectionCheckers()
	surface := config.InjectionSurfaceMCPToolDescription
	if !set.External(surface) && !set.Watches(surface) {
		return descriptionCheck{}, false
	}
	var parts []checker.Part
	for i, pre := range prescans {
		if pre.text == "" {
			continue
		}
		id := toolPartPrefix + strconv.Itoa(i)
		parts = append(parts, checker.Part{ID: id, Role: "tool_description", Representation: "original", Text: pre.text})
		if tags := normalize.DecodeTags(pre.text); tags != pre.text {
			parts = append(parts, checker.Part{ID: id + ":tags", Role: "decoded_view", Representation: "unicode_tags/v1", Text: tags})
		}
	}
	if len(parts) == 0 {
		return descriptionCheck{}, false
	}
	var submitted, original int64
	for _, p := range parts {
		submitted += int64(len(p.Text))
		if p.Representation == "original" {
			original += int64(len(p.Text))
		}
	}
	item := checker.Item{
		ID: "mcp-tools-list", Kind: checker.KindText, Surface: surface, Transport: "mcp",
		Direction: "response", ExtractionVersion: "mcp-tool-text/v1", Parts: parts,
		OriginalBytes: original, SubmittedBytes: submitted,
		Completeness: &checker.Completeness{Status: checker.Complete},
	}
	ext, ok := sc.AssessInjection(ctx, surface, item)
	if !ok {
		return descriptionCheck{}, false
	}
	out := descriptionCheck{ext: ext}
	if ext.Finding() && ext.Assessment.Response != nil {
		for _, f := range ext.Assessment.Response.Findings {
			for _, id := range f.PartIDs {
				rest, found := strings.CutPrefix(id, toolPartPrefix)
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
