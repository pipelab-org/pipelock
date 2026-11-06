// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0
package scanner

// Grouping transposes the existing independent byte lanes. A lane retains its
// original bias, mask and reset rule; its shape and phase identify cue delivery.
// No class, minimum run or correlated pair condition changes.
type assembledShapeLane struct {
	shape *assembledShape
	phase int
}
type assembledShapeGroup struct {
	lanes [8]assembledShapeLane
	masks [8][64]uint64
	bias  uint64
}

func (a *assembledPlan) buildShapeGroups(p *reassemblyPlan) {
	for set := textDLPAllPatterns; set <= textDLPCardPatterns; set++ {
		for codec, c := range reassemblyCodecs {
			var groups []assembledShapeGroup
			count := 0
			for _, shape := range a.shapes {
				if !set.includes(p.patterns[shape.id].genericCard) {
					continue
				}
				for phase := range c.quantum {
					index, lane := count/8, count%8
					if index == len(groups) {
						groups = append(groups, assembledShapeGroup{})
					}
					g := &groups[index]
					g.lanes[lane] = assembledShapeLane{shape: shape, phase: phase}
					g.bias |= (shape.bias[codec] >> uint(phase*8) & 255) << uint(lane*8)
					for position := range c.quantum {
						for value := range 1 << c.width {
							g.masks[position][value] |= (shape.masks[codec][position][value] >> uint(phase*8) & 255) << uint(lane*8)
						}
					}
					count++
				}
			}
			a.shapeGroups[set][codec] = groups
		}
	}
}

func (g *assembledShapeGroup) step(position, value int, state *uint64) uint64 {
	keep := g.masks[position&7][value&63]
	*state = ((*state + shapeOnes) & keep) | (g.bias &^ keep)
	hit := *state & shapeHigh
	if hit != 0 {
		reset := (hit >> 7) * 255
		*state = (*state &^ reset) | (g.bias & reset)
	}
	return hit
}
