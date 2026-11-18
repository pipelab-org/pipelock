// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestMCPClassifyHostileBrowserOperations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		tool, args string
		want       session.ActionClass
	}{
		{"mcp__playwright__browser_navigate", `{"url":"https://docs.vendor.example/guide"}`, session.ActionClassBrowse},
		{"browser_navigate_back", `{}`, session.ActionClassBrowse},
		{"browser_wait_for", `{"text":"Details"}`, session.ActionClassBrowse},
		{"browser_snapshot", "", session.ActionClassBrowse},
		{"browser_take_screenshot", `{"type":"png"}`, session.ActionClassBrowse},
		{"browser_take_screenshot", `{"filename":""}`, session.ActionClassUnknown},
		{"browser_find", `{"query":"Details"}`, session.ActionClassBrowse},
		{"browser_console_messages", `{"level":"info","outputPath":"console.txt"}`, session.ActionClassUnknown},
		{"browser_snapshot", `{"file_path":"capture.txt"}`, session.ActionClassUnknown},
		{"browser_snapshot", `[]`, session.ActionClassUnknown},
		{"browser_snapshot", `{"filename":`, session.ActionClassUnknown},
		{"browser_tabs", `{"action":"new"}`, session.ActionClassBrowse},
		{"browser_tabs", `{"action":"new","url":"https://docs.vendor.example/start"}`, session.ActionClassBrowse},
		{"browser_tabs", `{"action":"new","url":""}`, session.ActionClassUnknown},
		{"browser_tabs", `{"action":"new","url":7}`, session.ActionClassUnknown},
		{"browser_tabs", `{"action":"new","url":"https://docs.vendor.example/","index":0}`, session.ActionClassUnknown},
		{"browser_tabs", `{"action":"select","index":1.0}`, session.ActionClassBrowse},
		{"browser_tabs", `{"action":"list","isolatedContext":false}`, session.ActionClassUnknown},
		{"browser_tabs", `{"action":"new","isolatedContext":null}`, session.ActionClassUnknown},
		{"browser_tabs", `{"action":"list","index":0}`, session.ActionClassUnknown},
		{"browser_tabs", `{"action":"list","action":"list"}`, session.ActionClassUnknown},
		{"browser_tabs", `{"action":{"name":"list"}}`, session.ActionClassUnknown},
		{"browser_tabs", `{"action":"select"}`, session.ActionClassUnknown},
		{"browser_tabs", `{"action":"select","index":"1"}`, session.ActionClassUnknown},
		{"browser_tabs", `{"action":"select","index":-1}`, session.ActionClassUnknown},
		{"browser_tabs", `{"action":"select","index":1.5}`, session.ActionClassUnknown},
		{"browser_tabs", `{"action":"select","index":1e999}`, session.ActionClassUnknown},
		{"browser_tabs", `{"action":"close","index":0}`, session.ActionClassUnknown},
		{"browser_tabs", `{}`, session.ActionClassUnknown},
		{"browser_tabs", "", session.ActionClassUnknown},
		{"browser_route_list", `{}`, session.ActionClassBrowse},
		{"browser_get_config", `{}`, session.ActionClassBrowse},
		{"browser_cookie_get", `{"name":"display-mode"}`, session.ActionClassBrowse},
		{"browser_cookie_list", `{}`, session.ActionClassBrowse},
		{"browser_localstorage_get", `{"key":"display-mode"}`, session.ActionClassBrowse},
		{"browser_localstorage_list", `{}`, session.ActionClassBrowse},
		{"browser_sessionstorage_get", `{"key":"display-mode"}`, session.ActionClassBrowse},
		{"browser_sessionstorage_list", `{}`, session.ActionClassBrowse},
		{"browser_generate_locator", `{}`, session.ActionClassBrowse},
		{"browser_verify_element_visible", `{}`, session.ActionClassBrowse},
		{"browser_verify_list_visible", `{}`, session.ActionClassBrowse},
		{"browser_verify_text_visible", `{}`, session.ActionClassBrowse},
		{"browser_verify_value", `{}`, session.ActionClassBrowse},
		{"browser_verify_custom", `{}`, session.ActionClassUnknown},
		{"browser_screenshot", `{}`, session.ActionClassBrowse},
		{"browser_go_back", `{}`, session.ActionClassBrowse},
		{"browser_switch_tab", `{}`, session.ActionClassBrowse},
		{"browser_get_state", `{}`, session.ActionClassBrowse},
		{"browser_get_html", `{}`, session.ActionClassBrowse},
		{"browser_extract_content", `{}`, session.ActionClassBrowse},
		{"browser_list_tabs", `{}`, session.ActionClassBrowse},
		{"browser_list_sessions", `{}`, session.ActionClassBrowse},
		{"browser_cookie_set", `{"name":"display-mode","value":"compact"}`, session.ActionClassUnknown},
		{"browser_storage_state", `{}`, session.ActionClassUnknown},
		{"browser_login", `{}`, session.ActionClassUnknown},
		{"browser_feedback", `{}`, session.ActionClassUnknown},
		{"browser_click", `{}`, session.ActionClassUnknown},
		{"browserGetUnknown", `{}`, session.ActionClassUnknown},
		{"browser_get_html_extra", `{}`, session.ActionClassUnknown},
		{"browser_file_upload", `{"paths":["/workspace/photo.png"]}`, session.ActionClassPublish},
		{"browser_mouse_move_xy", `{}`, session.ActionClassWrite},
		{"browser_run_code_unsafe", `{}`, session.ActionClassExec},
		{"browser_snapshot", `{"command":"echo test"}`, session.ActionClassExec},
		{"browser_snapshot", `{"filename":"/workspace/.env"}`, session.ActionClassSecret},
		{"mcp__browser__frobnicate", `{}`, session.ActionClassUnknown},
		{"mcp__browser__list_items", `{}`, session.ActionClassRead},
		{"browserless_get", `{}`, session.ActionClassBrowse},
		// Irregular capitalization must not split the leading word apart.
		{"bRoWsEr_click", `{}`, session.ActionClassUnknown},
		{"BROWSER_CLICK", `{}`, session.ActionClassUnknown},
		{"mcp__playwright__bRoWsEr_click", `{}`, session.ActionClassUnknown},
		{"BrOwSeR_navigate", `{"url":"https://docs.vendor.example/guide"}`, session.ActionClassUnknown},
	} {
		t.Run(tc.tool+"/"+tc.args, func(t *testing.T) {
			classified := session.ClassifyMCPToolCallWithOptions(tc.tool, tc.args, nil, nil, session.ClassificationOptions{HostileMCP: true})
			if classified.Class != tc.want {
				t.Errorf("class=%s, want %s", classified.Class, tc.want)
			}
		})
	}
}

func TestMCPClassifyHostileDelegationOperations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		tool string
		want session.ActionClass
	}{
		{"open_subtask", session.ActionClassUnknown},
		{"open_sub_task", session.ActionClassUnknown},
		{"openSubAgent", session.ActionClassUnknown},
		{"open-sub-agent", session.ActionClassUnknown},
		{"mcp__agents__open_subagent", session.ActionClassUnknown},
		// The existing conservative write classifier finds "patch" in "dispatch".
		{"dispatch_fetch", session.ActionClassWrite},
		{"delegate_get_task", session.ActionClassUnknown},
		{"spawn_subagent", session.ActionClassExec},
		{"delegate_run", session.ActionClassExec},
		{"retry_with_browser_use_agent", session.ActionClassUnknown},
		{"Retry_With_Browser_Use_Agent", session.ActionClassUnknown},
		{"retry-with-browser-use-agent", session.ActionClassUnknown},
		{"RetryWithBrowserUseAgent", session.ActionClassUnknown},
		{"mcp__agents__RetryWithBrowserUseAgent", session.ActionClassUnknown},
		{"retry_with_browser_use_agent_status", session.ActionClassBrowse},
		{"list_subagents", session.ActionClassRead},
		{"get_subagent", session.ActionClassRead},
		{"open_file", session.ActionClassRead},
		{"open_subtasker", session.ActionClassRead},
		{"delegated_get", session.ActionClassRead},
		{"prefetch_cache", session.ActionClassBrowse},
		{"DeLeGaTe_get_task", session.ActionClassUnknown},
		{"oPeN_SuBtAsK", session.ActionClassUnknown},
		{"SpAwN_fetch", session.ActionClassExec},
		{"rEtRy_WiTh_BrOwSeR_uSe_AgEnT", session.ActionClassUnknown},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			classified := session.ClassifyMCPToolCallWithOptions(tc.tool, `{}`, nil, nil, session.ClassificationOptions{HostileMCP: true})
			if classified.Class != tc.want {
				t.Errorf("class=%s, want %s", classified.Class, tc.want)
			}
		})
	}
}

func TestMCPClassifyOperationEvidence(t *testing.T) {
	for _, tc := range []struct {
		tool string
		want session.ActionClass
	}{
		{"mcp__read__frobnicate", session.ActionClassUnknown},
		{"mcp__fetch__frobnicate", session.ActionClassUnknown},
		{"mcp__browse__x", session.ActionClassUnknown},
		{"mcp__download__frobnicate", session.ActionClassUnknown},
		{"service.area.frobnicate", session.ActionClassUnknown},
		{"mcp__fs__read_text_file", session.ActionClassRead},
		{"mcp__service__read_file", session.ActionClassRead},
		{"mcp__service__fetch_page", session.ActionClassBrowse},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			if got := session.ClassifyMCPToolCallWithOptions(tc.tool, `{}`, nil, nil, session.ClassificationOptions{}).Class; got != tc.want {
				t.Fatalf("class = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestMCPClassifyExecArgumentKeys(t *testing.T) {
	for _, tc := range []struct {
		name, tool, args string
		want             session.ActionClass
	}{
		{"search_value", "search_files", `{"query":"command","path":"/repo"}`, session.ActionClassRead},
		{"command_key", "search_files", `{"command":"echo test"}`, session.ActionClassExec},
		{"cmd_key", "search_files", `{"nested":[{"cmd":"echo test"}]}`, session.ActionClassExec},
		{"script_key", "search_files", `{"script":"echo test"}`, session.ActionClassExec},
		{"read_with_command", "read_file", `{"path":"/repo","command":"echo test"}`, session.ActionClassExec},
		{"malformed", "search_files", `{"command":`, session.ActionClassExec},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := session.ClassifyMCPToolCallWithOptions(tc.tool, tc.args, nil, nil, session.ClassificationOptions{}).Class; got != tc.want {
				t.Fatalf("class = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestMCPBoundedOperationEvidence(t *testing.T) {
	for _, prefix := range []string{"", "mcp__service__", "service.", "service:"} {
		for _, tool := range []string{"list_thread_pull_requests", "list_posts", "get_input", "listPosts", "getInput", "listThreadPullRequests"} {
			for _, failSafe := range []bool{false, true} {
				t.Run(prefix+tool+map[bool]string{false: "/off", true: "/on"}[failSafe], func(t *testing.T) {
					got := session.ClassifyMCPToolCallWithOptions(prefix+tool, `{}`, nil, nil, session.ClassificationOptions{FailSafe: failSafe})
					if got.Class != session.ActionClassRead || got.Confident {
						t.Fatalf("got %+v, want low-confidence read", got)
					}
					want := session.SensitivityNormal
					if failSafe {
						want = session.SensitivityProtected
					}
					if got.Sensitivity != want {
						t.Fatalf("got %+v, want sensitivity %v", got, want)
					}
					decision := (session.PolicyMatrix{}).EvaluateWithOptions(session.TaintExternalUntrusted, got.Class, got.Sensitivity, session.AuthorityUserBroad, session.PolicyEvaluateOptions{FailSafeClassification: failSafe, ClassificationConfident: got.Confident})
					expected := session.PolicyAllow
					if failSafe {
						expected = session.PolicyAsk
					}
					if decision.Decision != expected {
						t.Fatalf("got %+v, want %v", decision, expected)
					}
				})
			}
		}
	}
}

func TestMCPMutationEvidencePrecedesReads(t *testing.T) {
	tests := []struct{ tool, args string }{
		{"post_message", `{}`},
		{"read_post", `{}`},
		{"get_put", `{}`},
		{"request", `{}`},
		{"mcp__service__request", `{}`},
		{"service.request", `{}`},
		{"http_get", `{}`},
		{"mcp__publish__list_posts", `{}`},
		{"publishList", `{}`},
		{"mcp__post__nested__list_posts", `{}`},
		{"list_posts", `{"nested":{"payload":"x"}}`},
		{"list_posts", `{ "nested": { "request_body": "x" }`},
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "QUERY"} {
		tests = append(tests, struct{ tool, args string }{"list_thread_pull_requests", `{"nested":[{"method":" ` + method + ` "}]}`}, struct{ tool, args string }{"get_input", `{ "nested": { "method" : "` + method + `" }`})
	}
	for _, tt := range tests {
		t.Run(tt.tool+tt.args, func(t *testing.T) {
			got := session.ClassifyMCPToolCallWithOptions(tt.tool, tt.args, nil, nil, session.ClassificationOptions{})
			wantClass := session.ActionClassPublish
			if tt.tool == "get_put" {
				wantClass = session.ActionClassWrite
			}
			if got.Class != wantClass {
				t.Fatalf("mutation lost: %+v", got)
			}
			decision := (session.PolicyMatrix{Profile: "strict"}).EvaluateWithOptions(session.TaintExternalUntrusted, got.Class, got.Sensitivity, session.AuthorityUserBroad, session.PolicyEvaluateOptions{ClassificationConfident: got.Confident})
			wantDecision := session.PolicyAsk
			if tt.tool == "get_put" {
				wantDecision = session.PolicyAllow
			}
			if decision.Decision != wantDecision {
				t.Fatalf("publication allowed: %+v", decision)
			}
		})
	}
}

func TestMCPConservativeMutationEvidence(t *testing.T) {
	for _, name := range []string{"listposts", "getpullrequest", "link_pull_request", "watch_pull_request", "linkPullRequest", "watchPullRequest", "mcp__service__watch_pull_request", "linkpullrequest", "watchpullrequest", "get_pull_post", "get_pull_put", "list_pull_send", "get_or_open_pull_request", "get_and_open_pull_request", "link_and_open_pull_request", "get_and_forward_posts", "get_and_share_posts", "get_and_set_input", "get_and_deploy_input", "mcp__posts__list_items", "mcp__input__get_status", "mcp__pull_request__list_things", "getReQuest", "listPoSt", "readSeNd", "getPuT", "getHtTp", "getWebHook", "listPubLish", "postcomment", "postmessage", "submitpost", "putobject", "repost", "webpost", "xpostx", "post1", "post2_message", "merge_pull_request", "approve_pull_request", "make_request", "payment_request", "api_request", "mcp__service__nested__request", "service.nested.request", "service::request", "service. request"} {
		for _, failSafe := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/off", true: "/on"}[failSafe], func(t *testing.T) {
				got := session.ClassifyMCPToolCallWithOptions(name, `{}`, nil, nil, session.ClassificationOptions{FailSafe: failSafe})
				wantClass := session.ActionClassPublish
				if name == "get_pull_put" {
					wantClass = session.ActionClassWrite
				}
				if got.Class != wantClass {
					t.Fatalf("mutation lost: %+v", got)
				}
				decision := (session.PolicyMatrix{Profile: "strict"}).EvaluateWithOptions(session.TaintExternalUntrusted, got.Class, got.Sensitivity, session.AuthorityUserBroad, session.PolicyEvaluateOptions{FailSafeClassification: failSafe, ClassificationConfident: got.Confident})
				wantDecision := session.PolicyAsk
				if name == "get_pull_put" && !failSafe {
					wantDecision = session.PolicyAllow
				}
				if decision.Decision != wantDecision {
					t.Fatalf("publication allowed after taint: %+v", decision)
				}
			})
		}
	}
}

func TestMCPReadOperationObjects(t *testing.T) {
	for _, tt := range []struct {
		name string
		want session.ActionClass
	}{
		{"get_comment", session.ActionClassRead},
		{"get_merge_status", session.ActionClassRead},
		{"get_merge_base", session.ActionClassRead},
		{"get_reply", session.ActionClassRead},
		{"check_push_status", session.ActionClassUnknown},
		{"show_posts", session.ActionClassUnknown},
		{"query_posts", session.ActionClassUnknown},
		{"describe_pull_request", session.ActionClassUnknown},
		{"check_pull_request", session.ActionClassUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := session.ClassifyMCPToolCallWithOptions(tt.name, `{}`, nil, nil, session.ClassificationOptions{})
			if got.Class != tt.want {
				t.Fatalf("got %+v, want %v", got, tt.want)
			}
		})
	}
}

// Complete read-only names whose words merely contain a publish or network
// needle ("put" in input/output, "post" in postgres, "request" as a noun).
// Spelling variants that produce the same word sequence also qualify; any extra
// word, a namespace mutation, or a concatenated spelling keeps the conservative
// classification asserted in TestMCPEmbeddedNeedleNamesStayConservative.
func TestMCPReadOnlyNamesWithEmbeddedNeedles(t *testing.T) {
	for _, name := range []string{
		"get_input_schema", "getInputSchema", "read_output", "ReadOutput", "read-output", "get_output",
		"get_request_log", "list_feature_requests", "list_postgres_tables", "listPostgresTables",
		"list_pending_requests", "mcp__service__list_pending_requests",
	} {
		for _, failSafe := range []bool{false, true} {
			got := session.ClassifyMCPToolCallWithOptions(name, `{}`, nil, nil, session.ClassificationOptions{FailSafe: failSafe})
			if got.Class != session.ActionClassRead {
				t.Fatalf("%s (failSafe=%v): read-only name classified as %+v", name, failSafe, got)
			}
		}
	}
}

func TestMCPEmbeddedNeedleNamesStayConservative(t *testing.T) {
	for _, name := range []string{
		"readoutput", "getinputschema", "read_output_and_send", "get_input_schema_and_post",
		"list_pending_requests_extra", "send_list_pending_requests", "list_feature_requests_webhook",
		"mcp__post__get_request_log", "get_request_log2", "list_postgres_tables_put",
	} {
		got := session.ClassifyMCPToolCallWithOptions(name, `{}`, nil, nil, session.ClassificationOptions{})
		// An exact trailing "put" word selects write before publish detection.
		wantClass := session.ActionClassPublish
		if name == "list_postgres_tables_put" {
			wantClass = session.ActionClassWrite
		}
		if got.Class != wantClass {
			t.Fatalf("%s: want %v, got %+v", name, wantClass, got)
		}
	}
}

func TestMCPWatchMutationWithIdentifierArguments(t *testing.T) {
	for _, name := range []string{"watch_pull_request", "link_pull_request", "mcp__service__watch_pull_request"} {
		for _, failSafe := range []bool{false, true} {
			got := session.ClassifyMCPToolCallWithOptions(name, `{"project_key":"example","repo_slug":"example","pr_id":1}`, nil, nil, session.ClassificationOptions{FailSafe: failSafe})
			if got.Class != session.ActionClassPublish {
				t.Fatalf("%s: mutation lost: %+v", name, got)
			}
			decision := (session.PolicyMatrix{}).EvaluateWithOptions(session.TaintExternalUntrusted, got.Class, got.Sensitivity, session.AuthorityUserBroad, session.PolicyEvaluateOptions{FailSafeClassification: failSafe, ClassificationConfident: got.Confident})
			if decision.Decision != session.PolicyAsk {
				t.Fatalf("%s: mutation allowed: %+v", name, decision)
			}
		}
	}
}

func TestUploadVerbIsNotASafeBrowse(t *testing.T) {
	pm := session.PolicyMatrix{Profile: "balanced"}
	for _, name := range []string{
		"upload_data", "upload_file", "file_upload", "uploadFile", "Upload_File",
		"mcp__storage__upload_file", "browser_file_upload", "api_upload",
	} {
		t.Run(name, func(t *testing.T) {
			got := session.ClassifyMCPToolCallWithOptions(name, `{}`, nil, nil, session.ClassificationOptions{})
			if got.Class != session.ActionClassPublish {
				t.Fatalf("got %+v, want publish", got)
			}
			hostile := pm.EvaluateWithOptions(session.TaintExternalHostile, got.Class, got.Sensitivity, session.AuthorityUserBroad, session.PolicyEvaluateOptions{
				CheckTaskPermission:     true,
				ClassificationConfident: got.Confident,
			})
			if hostile.Decision != session.PolicyAsk || hostile.Reason != session.TaskPermissionRequired {
				t.Fatalf("hostile decision %+v, want task permission", hostile)
			}
			clean := pm.EvaluateWithOptions(session.TaintTrusted, got.Class, got.Sensitivity, session.AuthorityUserBroad, session.PolicyEvaluateOptions{
				CheckTaskPermission:     true,
				ClassificationConfident: got.Confident,
			})
			if clean.Decision != session.PolicyAllow || clean.Reason != "trusted_or_allowlisted_context" {
				t.Fatalf("clean decision %+v, want allow", clean)
			}
		})
	}

	// The noun "uploads" and a server id are not the upload verb. A list stays a
	// read. An unrelated tool on a server named upload stays unknown.
	reads := []string{"list_uploads", "mcp__upload__list_files"}
	for _, name := range reads {
		got := session.ClassifyMCPToolCallWithOptions(name, `{}`, nil, nil, session.ClassificationOptions{})
		if got.Class != session.ActionClassRead {
			t.Fatalf("%s: got %+v, want read", name, got)
		}
	}
	unknown := session.ClassifyMCPToolCallWithOptions("mcp__upload__frobnicate", `{}`, nil, nil, session.ClassificationOptions{})
	if unknown.Class != session.ActionClassUnknown {
		t.Fatalf("namespace upload: got %+v, want unknown", unknown)
	}
	ask := pm.EvaluateWithOptions(session.TaintExternalHostile, unknown.Class, unknown.Sensitivity, session.AuthorityUserBroad, session.PolicyEvaluateOptions{
		CheckTaskPermission:     true,
		ClassificationConfident: unknown.Confident,
	})
	if ask.Reason != session.TaskPermissionRequired {
		t.Fatalf("namespace upload hostile: %+v", ask)
	}

	// Browse restoration stays for a navigation name and a delete still wins
	// over a fetch substring.
	nav := session.ClassifyMCPToolCallWithOptions("browser_navigate", `{"url":"https://docs.vendor.example/guide"}`, nil, nil, session.ClassificationOptions{})
	if nav.Class != session.ActionClassBrowse {
		t.Fatalf("browser_navigate: got %+v, want browse", nav)
	}
	deleted := session.ClassifyMCPToolCallWithOptions("fetcher_admin_delete", `{}`, nil, nil, session.ClassificationOptions{})
	if deleted.Class != session.ActionClassWrite {
		t.Fatalf("fetcher_admin_delete: got %+v, want write", deleted)
	}
}

func TestMCPExplicitMutationMethodPrecedesWrite(t *testing.T) {
	for _, name := range []string{"get_put", "get_pull_put", "write_file", "update_item"} {
		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "QUERY"} {
			for _, failSafe := range []bool{false, true} {
				args := `{"url":"https://api.vendor.example/resource","nested":{"method":" ` + method + ` "}}`
				got := session.ClassifyMCPToolCallWithOptions(name, args, nil, nil, session.ClassificationOptions{FailSafe: failSafe})
				if got.Class != session.ActionClassPublish {
					t.Fatalf("%s/%s: want publish, got %+v", name, method, got)
				}
				decision := (session.PolicyMatrix{Profile: "strict"}).EvaluateWithOptions(session.TaintExternalUntrusted, got.Class, got.Sensitivity, session.AuthorityUserBroad, session.PolicyEvaluateOptions{FailSafeClassification: failSafe, ClassificationConfident: got.Confident})
				if decision.Decision != session.PolicyAsk {
					t.Fatalf("%s/%s: mutation allowed: %+v", name, method, decision)
				}
			}
		}
	}
}
