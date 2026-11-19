// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"encoding/json"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

type nestedBody struct {
	kind string
	body v3Common
}

func v3NestedBodyRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	registry, err := os.ReadFile("../receipt-v3/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Objects map[string]map[string]struct {
			Required bool
			Type     string
		}
	}
	if err := json.Unmarshal(registry, &spec); err != nil {
		t.Fatal(err)
	}
	type site struct {
		name, shape string
		base        func(*v3Stream) nestedBody
		path        []string
	}
	var sites []site
	for _, kind := range []string{"stream_open", "stream_close", "action"} {
		shape := map[string]string{"stream_open": "StreamOpen", "stream_close": "StreamClose", "action": "Action"}[kind]
		var visit func(string, []string)
		visit = func(shape string, path []string) {
			for _, name := range slices.Sorted(maps.Keys(spec.Objects[shape])) {
				field := spec.Objects[shape][name]
				nested := strings.TrimPrefix(field.Type, "[]")
				if _, exists := spec.Objects[nested]; !exists {
					continue
				}
				child := append(slices.Clone(path), name)
				sites = append(sites, site{
					name: kind + "-" + strings.Join(child, "-"), shape: nested, path: child,
					base: func(s *v3Stream) nestedBody { return v3NestedSample(s, kind, child[0]) },
				})
				visit(nested, child)
			}
		}
		visit(shape, nil)
	}
	var recipes []v3Recipe
	for _, site := range sites {
		for _, name := range slices.Sorted(maps.Keys(spec.Objects[site.shape])) {
			if !spec.Objects[site.shape][name].Required {
				continue
			}
			s := v3New(t)
			sample := site.base(s)
			obj, ok := v3NestedObject(sample.body, site.path)
			if !ok {
				t.Fatalf("nested sample lacks object %s", site.name)
			}
			if _, ok := obj[name]; !ok {
				t.Fatalf("nested sample %s lacks required field %s", site.name, name)
			}
			delete(obj, name)
			recipes = append(recipes, v3NestedInvalid(t, s, sample, site.name+"-missing-"+name))
		}
		s := v3New(t)
		sample := site.base(s)
		obj, ok := v3NestedObject(sample.body, site.path)
		if !ok {
			t.Fatalf("nested sample lacks object %s", site.name)
		}
		obj["runtime_label"] = "value"
		recipes = append(recipes, v3NestedInvalid(t, s, sample, site.name+"-data-derived"))
	}
	for _, row := range []struct {
		name, field string
		change      func(v3Common)
	}{
		{"caller-verified-missing-issuer", "caller", func(o v3Common) { delete(o, "issuer") }},
		{"caller-verified-missing-client", "caller", func(o v3Common) { delete(o, "client_id") }},
		{"caller-verified-missing-resource", "caller", func(o v3Common) { delete(o, "resource") }},
		{"caller-verified-missing-subject", "caller", func(o v3Common) { delete(o, "subject") }},
		{"caller-verified-partial-identity", "caller", func(o v3Common) {
			delete(o, "client_id")
			delete(o, "resource")
		}},
		{"caller-none-with-issuer", "caller", func(o v3Common) {
			o["authn"] = "none"
			delete(o, "subject")
			delete(o, "client_id")
			delete(o, "resource")
		}},
		{"caller-none-with-resource", "caller", func(o v3Common) {
			o["authn"] = "none"
			delete(o, "subject")
			delete(o, "client_id")
			delete(o, "issuer")
		}},
		{"caller-none-with-subject", "caller", func(o v3Common) {
			o["authn"] = "none"
			delete(o, "client_id")
			delete(o, "issuer")
			delete(o, "resource")
		}},
		{"fallback-checker-no-hash", "checker", func(o v3Common) { o["selection"] = "fallback"; delete(o, "config_hash") }},
		{"unavailable-checker-with-hash", "checker", func(o v3Common) { o["selection"], o["disposition"] = "unavailable", "not_run" }},
		{"approval-ask-unobserved", "ask", func(o v3Common) { o["channel"] = "approval_api" }},
		{"hold-no-policy", "hold", func(o v3Common) { delete(o, "policy") }},
		{"hold-with-correction", "hold", func(o v3Common) { o["correction"] = true }},
		{"hold-with-resolution-policy", "hold", func(o v3Common) { o["resolution_policy"] = "example" }},
		{"hold-with-resolution-source", "hold", func(o v3Common) { o["resolution_source"] = "example" }},
		{"resolution-with-policy", "resolution", func(o v3Common) { o["policy"] = "example" }},
		{"resolution-with-parent", "resolution", func(o v3Common) { o["parent"] = "example" }},
		{"resolution-no-policy", "resolution", func(o v3Common) { delete(o, "resolution_policy") }},
		{"resolution-no-source", "resolution", func(o v3Common) { delete(o, "resolution_source") }},
		{"redaction-classes-unsorted", "redaction", func(o v3Common) {
			o["classes"] = []v3Common{{"class": "z", "count": 2}, {"class": "a", "count": 1}}
		}},
		{"redaction-classes-repeated", "redaction", func(o v3Common) {
			o["classes"] = []v3Common{{"class": "a", "count": 2}, {"class": "a", "count": 1}}
		}},
	} {
		s := v3New(t)
		sample := v3NestedSample(s, "action", row.field)
		field := row.field
		if field == "resolution" {
			field = "hold"
		}
		row.change(sample.body[field].(v3Common))
		recipes = append(recipes, v3NestedInvalid(t, s, sample, row.name))
	}
	for _, row := range []struct {
		name, kind, field string
		change            func(v3Common)
	}{
		{"coverage-unsorted", "stream_open", "coverage", func(o v3Common) {
			o["coverage"].(v3Common)["surfaces"] = []string{"response", "request"}
		}},
		{"wrong-embedded-signer", "stream_open", "signer_key", func(o v3Common) {
			o["signer_key"] = v3DefaultOpen(v3Key("other"), "")["signer_key"]
		}},
		{"previous-and-cutover", "stream_open", "previous", func(o v3Common) {
			o["legacy_cutover"] = v3Common{"chains": 0, "inventory": v3.EmptyInventoryDigest()}
		}},
		{"incorrect-close-count", "stream_close", "durability", func(o v3Common) { o["records"] = 3 }},
		{"empty-optional-contract", "action", "contract", func(o v3Common) { o["contract"] = v3Common{} }},
		{"boolean-coverage-type", "stream_open", "coverage", func(o v3Common) {
			o["coverage"].(v3Common)["content_scan"] = "true"
		}},
	} {
		s := v3New(t)
		sample := v3NestedSample(s, row.kind, row.field)
		row.change(sample.body)
		recipes = append(recipes, v3NestedInvalid(t, s, sample, row.name))
	}

	return recipes
}

func v3NestedSample(s *v3Stream, kind, field string) nestedBody {
	digest := v3.Digest(nil)
	switch kind {
	case "stream_open":
		body := v3DefaultOpen(s.key, s.lineage)
		body["posture"] = v3Common{
			"capsule_sha256": digest, "contained_uid": "1000", "containment_nonce": "example", "signer_key_id": "example",
		}
		if field == "previous" {
			delete(body, "legacy_cutover")
			body["previous"] = v3Common{"stream": strings.Repeat("3", 32), "record": digest, "seq": 2, "ended": "unsealed"}
		}
		return nestedBody{kind, body}
	case "stream_close":
		body := v3Close(1)
		body["recorder"] = v3Common{"entries": 1, "session": "example", "transcript_root": digest}
		return nestedBody{kind, body}
	}
	body := v3DefaultAction()
	switch field {
	case "ask":
		body["verdict"], body["effect_boundary"], body["effect_relation"] = "ask", "hook_execution", "before"
		body[field] = v3Common{"channel": "host_prompt", "observed": false}
	case "caller":
		body[field] = v3Common{
			"authn": "mcp_door_verified", "client_id": "example", "issuer": "https://issuer.vendor.example",
			"resource": "https://api.vendor.example", "subject": "example",
		}
	case "checker":
		body[field] = v3Common{"surface": "scan_api", "mode": "block", "selection": "configured", "disposition": "passed", "config_hash": digest}
	case "contract":
		body[field] = v3Common{"rule_id": "example"}
	case "hold":
		body["phase"], body["verdict"], body["effect_boundary"], body["effect_relation"] = "hold", "defer", "approval_prompt", "before"
		body[field] = v3Common{"id": "example", "policy": "example"}
	case "resolution":
		body["phase"], body["effect_boundary"], body["effect_relation"] = "resolution", "approval_prompt", "after"
		body["hold"] = v3Common{"id": "example", "resolution_policy": "example", "resolution_source": "example"}
	case "normalization":
		body[field] = v3Common{"id": "example", "digest": digest}
	case "redaction":
		body[field] = v3Common{"classes": []v3Common{{"class": "example", "count": 1}}}
	case "session":
		body[field] = v3Common{"id": "example", "taint_sources": []v3Common{{
			"kind": "example", "level": 1, "timestamp": "2026-01-01T00:00:00.000Z", "url": "https://api.vendor.example",
		}}}
	case "shield":
		body[field] = v3Common{"partial": false}
	case "taint":
		body[field] = v3Common{"decision": "example"}
	}
	return nestedBody{kind, body}
}

func v3NestedObject(body v3Common, path []string) (v3Common, bool) {
	for _, part := range path {
		switch value := body[part].(type) {
		case v3Common:
			body = value
		case []v3Common:
			if len(value) == 0 {
				return nil, false
			}
			body = value[0]
		default:
			return nil, false
		}
	}
	return body, body != nil
}

func TestReceiptV3NestedObjectRequiresPath(t *testing.T) {
	for _, child := range []any{nil, "example", []v3Common{}, []v3Common{nil}} {
		if object, ok := v3NestedObject(v3Common{"parent": v3Common{"child": child}}, []string{"parent", "child"}); ok {
			t.Fatalf("found nested object %v through %v", object, child)
		}
	}
}

func v3NestedInvalid(t *testing.T, s *v3Stream, sample nestedBody, name string) v3Recipe {
	t.Helper()
	if sample.kind == "stream_open" {
		s.records = nil
	}
	s.add(t, sample.kind, sample.body, nil)
	if sample.kind != "stream_close" {
		s.close(t)
	}
	return v3Invalid(6, "nested-"+name, "BODY_SCHEMA", s.file(0, len(s.records)))
}
