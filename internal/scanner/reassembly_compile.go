// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"slices"
	"sync"
)

type assembledSyntaxKey struct{ name, expression string }

// Keep only the most recently compiled syntax, rather than a registry of past
// configurations. Regex syntax and rule order completely determine the raw
// automata and shape masks. No scanner, validator, keyword context, finding or
// inspection budget is retained here.
var assembledSyntaxCache struct {
	sync.Mutex
	key  []assembledSyntaxKey
	plan *assembledPlan
}

func newAssembledPlan(p *reassemblyPlan) (*assembledPlan, error) {
	key := make([]assembledSyntaxKey, len(p.patterns))
	for id, pattern := range p.patterns {
		key[id] = assembledSyntaxKey{pattern.name, pattern.re.String()}
	}
	assembledSyntaxCache.Lock()
	defer assembledSyntaxCache.Unlock()
	if assembledSyntaxCache.plan == nil || !slices.Equal(key, assembledSyntaxCache.key) {
		plan, err := compileAssembledPlan(p)
		if err != nil {
			return nil, err
		}
		assembledSyntaxCache.key, assembledSyntaxCache.plan = key, plan
	}
	// Share immutable tables, but bind shape validation and card partitions to
	// this scanner. Identical regexes can have different validators or policy.
	a := *assembledSyntaxCache.plan
	a.shapes = make([]*assembledShape, 0, len(a.shapes))
	for _, template := range assembledSyntaxCache.plan.shapes {
		shape := *template
		pattern := p.patterns[shape.id]
		if shape.validateRule {
			validation := *pattern
			validation.keywords = nil
			validation.keywordContext = nil
			shape.validate = &validation
		}
		if pattern.relaxSingleGluedBoundary {
			glued := *pattern
			glued.keywords = nil
			glued.keywordContext = nil
			shape.glued = &glued
		}
		a.shapes = append(a.shapes, &shape)
	}
	a.buildShapeGroups(p)
	return &a, nil
}
