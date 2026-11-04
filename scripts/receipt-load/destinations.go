// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
)

const (
	destinationsSingle               = "single"
	destinationsPerRequest           = "per-request"
	attributionPerRequestDestination = "per_request_destination"
)

func destinationMode(mode string) string {
	if mode == "" {
		return destinationsSingle
	}
	return mode
}

// destinationPoolSize balances listeners and DNS aliases. Their Cartesian
// product covers every slot, using ceil(sqrt(total)) ports instead of one
// listener or one DNS override per request.
func destinationPoolSize(total int) int {
	n := max(1, int(math.Sqrt(float64(total))))
	if (total-1)/n+1 > n {
		n++
	}
	return n
}

// destinationPlan records the actual bound ports and ordered aliases. The
// slot-to-authority mapping is derived from the plan, never from receipts.
// Lookup tables take O(sqrt(total)) space; no million-entry target map is needed.
type destinationPlan struct {
	Aliases    []string `json:"aliases"`
	Ports      []string `json:"ports"`
	aliasIndex map[string]int
	portIndex  map[string]int
}

func newDestinationPlan(total int, ports []string) *destinationPlan {
	d := &destinationPlan{Ports: ports, aliasIndex: make(map[string]int), portIndex: make(map[string]int)}
	for i, port := range ports {
		d.portIndex[port] = i
	}
	for i := range (total-1)/len(ports) + 1 {
		alias := fmt.Sprintf("r%06d.load.example", i)
		d.Aliases = append(d.Aliases, alias)
		d.aliasIndex[alias] = i
	}
	return d
}

func (d *destinationPlan) authority(slot int) string {
	return net.JoinHostPort(d.Aliases[slot/len(d.Ports)], d.Ports[slot%len(d.Ports)])
}

func (d *destinationPlan) overrides() map[string][]string {
	out := make(map[string][]string, len(d.Aliases))
	for _, alias := range d.Aliases {
		out[alias] = []string{"127.0.0.1"}
	}
	return out
}

// targetSlot accepts only the exact destination-only spelling signed by the
// producer. Extra URL fields, unknown aliases/ports and unused pairs fail.
func (d *destinationPlan) targetSlot(target string, total int) (int, bool) {
	authority, ok := strings.CutPrefix(target, "http://")
	if !ok {
		return 0, false
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return 0, false
	}
	a, hostOK := d.aliasIndex[host]
	p, portOK := d.portIndex[port]
	if !hostOK || !portOK {
		return 0, false
	}
	slot := a*len(d.Ports) + p
	return slot, slot < total && target == "http://"+d.authority(slot)
}

func (s *recorderScanner) targetSlot(target string) (int, bool) {
	if s.plan.destinations != nil {
		return s.plan.destinations.targetSlot(target, s.plan.total())
	}
	key, ok := keyFromTarget(target)
	if !ok {
		return 0, false
	}
	return s.plan.parseKey(key)
}

func (s *recorderScanner) matchesReceiptTarget(target string, slot int) bool {
	if s.plan.destinations != nil {
		return target == "http://"+s.plan.destinations.authority(slot)
	}
	return s.plan.matchesTargetQuery(target, slot, true)
}

func listenerPort(addr net.Addr) string {
	return strconv.Itoa(addr.(*net.TCPAddr).Port)
}
