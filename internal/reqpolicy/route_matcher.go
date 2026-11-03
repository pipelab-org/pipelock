// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import "github.com/luckyPipewrench/pipelock/internal/config"

// RouteMatcher evaluates one request_policy route grammar (hosts, methods, path
// prefixes and RE2 path patterns) outside a rule set, for features that name a
// route without attaching an action to it. It is the compiled form the rules
// themselves use, so a route matches the same requests in both places.
type RouteMatcher struct {
	route compiledRoute
}

// NewRouteMatcher compiles a route. The only failure is a path pattern that
// does not compile.
func NewRouteMatcher(route config.RequestPolicyRoute) (*RouteMatcher, error) {
	compiled, err := compileRoute(route)
	if err != nil {
		return nil, err
	}
	return &RouteMatcher{route: compiled}, nil
}

// Matches reports whether a request satisfies every constraint the route sets.
// path is the request's escaped path; matching normalizes it the way rule
// matching does. Content type is not consulted.
func (m *RouteMatcher) Matches(host, method, path string) bool {
	if m == nil {
		return false
	}
	return m.route.routeMatches(RequestMeta{Host: host, Method: method, Path: path})
}
