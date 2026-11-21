// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestClassifyURLSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		rawURL string
		want   session.TaintLevel
	}{
		{name: "localhost is trusted", rawURL: "http://localhost:3000/docs", want: session.TaintTrusted},
		{name: "loopback is trusted", rawURL: "http://127.0.0.1:8080/health", want: session.TaintTrusted},
		{name: "allowlisted docs are references", rawURL: testGitHubCopilotDocs, want: session.TaintAllowlistedReference},
		{name: "allowlisted single-label gateway is reference", rawURL: "http://litellm:4000/v1/chat/completions", want: session.TaintAllowlistedReference},
		{name: "random site is untrusted", rawURL: "https://evil.example/backdoor", want: session.TaintExternalUntrusted},
		{name: "bad url is untrusted", rawURL: "://not-a-url", want: session.TaintExternalUntrusted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := session.ClassifyURLSource(tt.rawURL, []string{"docs.github.com", "litellm"})
			if got != tt.want {
				t.Fatalf("ClassifyURLSource(%q) = %v, want %v", tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestClassifyHTTPResponseObservation_MediaSeen(t *testing.T) {
	t.Parallel()

	observation := session.ClassifyHTTPResponseObservation(
		"https://evil.example/image.png",
		"image/png",
		nil,
		false,
	)
	if !observation.MediaSeen {
		t.Fatal("expected external image content to set media_seen")
	}
	if observation.Source.Level != session.TaintExternalUntrusted {
		t.Fatalf("level = %v, want external_untrusted", observation.Source.Level)
	}
}

func TestClassifyMCPToolCall(t *testing.T) {
	t.Parallel()

	protected := []string{"*/auth/*", "*/security/*", "*/.env*"}
	elevated := []string{"*/config/*", "*/middleware*"}

	tests := []struct {
		name       string
		toolName   string
		argsJSON   string
		wantClass  session.ActionClass
		wantLevel  session.ActionSensitivity
		wantAction string
	}{
		{
			name:       "protected write tool",
			toolName:   "write_file",
			argsJSON:   `{"path":"/repo/auth/middleware.go","content":"x"}`,
			wantClass:  session.ActionClassWrite,
			wantLevel:  session.SensitivityProtected,
			wantAction: "/repo/auth/middleware.go",
		},
		{
			name:       "shell mutation is exec",
			toolName:   "shell",
			argsJSON:   `{"command":"git push origin main"}`,
			wantClass:  session.ActionClassExec,
			wantLevel:  session.SensitivityElevated,
			wantAction: "",
		},
		{
			name:       "secret path is secret use",
			toolName:   "read_file",
			argsJSON:   `{"path":"/home/developer/.ssh/id_rsa"}`,
			wantClass:  session.ActionClassSecret,
			wantLevel:  session.SensitivityProtected,
			wantAction: "/home/developer/.ssh/id_rsa",
		},
		{
			name:       "browse tool",
			toolName:   "browse_url",
			argsJSON:   `{"url":"https://example.com/docs"}`,
			wantClass:  session.ActionClassBrowse,
			wantLevel:  session.SensitivityNormal,
			wantAction: "https://example.com/docs",
		},
		{
			name:       "non mutating shell stays exec",
			toolName:   "shell",
			argsJSON:   `{"command":"git status"}`,
			wantClass:  session.ActionClassExec,
			wantLevel:  session.SensitivityProtected,
			wantAction: "",
		},
		{
			name:       "unknown tool with edit intent becomes write",
			toolName:   "apply_changes",
			argsJSON:   `{"path":"/repo/security/policy.go","changes":[{"text":"deny all"}]}`,
			wantClass:  session.ActionClassWrite,
			wantLevel:  session.SensitivityProtected,
			wantAction: "/repo/security/policy.go",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotClass, gotLevel, gotAction := session.ClassifyMCPToolCall(tt.toolName, tt.argsJSON, protected, elevated)
			if gotClass != tt.wantClass {
				t.Fatalf("action class = %v, want %v", gotClass, tt.wantClass)
			}
			if gotLevel != tt.wantLevel {
				t.Fatalf("sensitivity = %v, want %v", gotLevel, tt.wantLevel)
			}
			if gotAction != tt.wantAction {
				t.Fatalf("action ref = %q, want %q", gotAction, tt.wantAction)
			}
		})
	}
}

func TestClassifyPathSensitivity_RootRelativePatterns(t *testing.T) {
	t.Parallel()

	protected := []string{"*/.env*", "*/auth/*"}
	if got := session.ClassifyPathSensitivity(".env.production", protected, nil); got != session.SensitivityProtected {
		t.Fatalf("sensitivity = %v, want protected", got)
	}
	if got := session.ClassifyPathSensitivity("auth/middleware.go", protected, nil); got != session.SensitivityProtected {
		t.Fatalf("sensitivity = %v, want protected", got)
	}
}

func TestClassifyHTTPActionWithOptions_FailSafeReadNeedsConfidence(t *testing.T) {
	t.Parallel()

	off := session.ClassifyHTTPActionWithOptions("GET", "", nil, nil, session.ClassificationOptions{})
	if off.Class != session.ActionClassRead || off.Sensitivity != session.SensitivityNormal || off.Confident {
		t.Fatalf("fail-safe off classification = %+v, want read normal low-confidence", off)
	}

	on := session.ClassifyHTTPActionWithOptions("GET", "", nil, nil, session.ClassificationOptions{FailSafe: true})
	if on.Class != session.ActionClassRead || on.Sensitivity != session.SensitivityProtected || on.Confident {
		t.Fatalf("fail-safe on classification = %+v, want read protected low-confidence", on)
	}
}

func TestClassifyMCPToolCallWithOptions_FailSafeUnknownTool(t *testing.T) {
	t.Parallel()

	off := session.ClassifyMCPToolCallWithOptions("mystery_tool", `{}`, nil, nil, session.ClassificationOptions{})
	if off.Class != session.ActionClassUnknown || off.Sensitivity != session.SensitivityNormal || off.Confident {
		t.Fatalf("fail-safe off classification = %+v, want unknown normal low-confidence", off)
	}

	on := session.ClassifyMCPToolCallWithOptions("mystery_tool", `{}`, nil, nil, session.ClassificationOptions{FailSafe: true})
	if on.Class != session.ActionClassUnknown || on.Sensitivity != session.SensitivityProtected || on.Confident {
		t.Fatalf("fail-safe on classification = %+v, want unknown protected low-confidence", on)
	}
}

func TestClassifyHTTPAction_QueryIsPublish(t *testing.T) {
	t.Parallel()

	// The HTTP QUERY method carries a request body; it is classified with the
	// body-bearing write methods (Publish), not the bodyless read methods, so an
	// agent cannot move a body to an upstream at lower taint risk than POST.
	class, _ := session.ClassifyHTTPAction("QUERY", "/search", nil, nil)
	if class != session.ActionClassPublish {
		t.Fatalf("ClassifyHTTPAction(QUERY) class = %v, want publish", class)
	}
}

func TestClassifyMCPToolCall_QueryMethodIsMutatingNetworkIntent(t *testing.T) {
	t.Parallel()

	// An MCP tool call that tunnels a QUERY request (a body-bearing method)
	// must classify as publish, exactly like POST — otherwise an agent could
	// move a body to an upstream at lower taint risk by choosing QUERY. The
	// neutral tool name "invoke" isolates the method-based classification: it
	// matches no name heuristic, so only the QUERY method drives the verdict.
	class, _, target := session.ClassifyMCPToolCall(
		"invoke",
		`{"method":"QUERY","url":"https://api.example.com/search"}`,
		nil,
		nil,
	)
	if class != session.ActionClassPublish {
		t.Fatalf("ClassifyMCPToolCall(invoke, method=QUERY) class = %v, want publish", class)
	}
	if target != "https://api.example.com/search" {
		t.Fatalf("target = %q, want the request URL", target)
	}
}

func TestClassifyMCPToolCall_MutatingNetworkIntentWithSpacedJSON(t *testing.T) {
	t.Parallel()

	class, sensitivity, target := session.ClassifyMCPToolCall(
		"http_request",
		"{\n  \"method\": \"POST\",\n  \"url\": \"https://api.example.com/publish\"\n}",
		nil,
		nil,
	)
	if class != session.ActionClassPublish {
		t.Fatalf("action class = %v, want publish", class)
	}
	if sensitivity != session.SensitivityElevated {
		t.Fatalf("sensitivity = %v, want elevated", sensitivity)
	}
	if target != "https://api.example.com/publish" {
		t.Fatalf("target = %q, want publish URL", target)
	}
}

func TestClassifyResponseFindingsMatchesBooleanClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		kinds []session.HostileFindingKind
		want  []session.HostileFindingKind
	}{
		{name: "no findings", kinds: nil, want: nil},
		{name: "wording", kinds: []session.HostileFindingKind{session.FindingWording}, want: []session.HostileFindingKind{session.FindingWording}},
		{name: "mixed with duplicate", kinds: []session.HostileFindingKind{session.FindingDLP, session.FindingWording, session.FindingDLP}, want: []session.HostileFindingKind{session.FindingDLP, session.FindingWording}},
		{name: "unknown label", kinds: []session.HostileFindingKind{"not-a-kind"}, want: []session.HostileFindingKind{session.FindingUnattributed}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			hit := len(tt.kinds) > 0 && tt.name != "wording"
			want := tt.want

			httpGot := session.ClassifyHTTPResponseFindings("https://evil.example/page", "text/html", nil, tt.kinds)
			httpWant := session.ClassifyHTTPResponseObservation("https://evil.example/page", "text/html", nil, hit)
			assertFindingsObservation(t, "http", httpGot, httpWant, want)

			mcpGot := session.ClassifyMCPResponseFindings("tool_result", true, tt.kinds)
			mcpWant := session.ClassifyMCPResponseObservation("tool_result", true, hit)
			assertFindingsObservation(t, "mcp", mcpGot, mcpWant, want)
		})
	}
}

func assertFindingsObservation(t *testing.T, surface string, got, boolean session.RiskObservation, kinds []session.HostileFindingKind) {
	t.Helper()
	if !reflect.DeepEqual(got.FindingKinds, kinds) {
		t.Fatalf("%s finding kinds = %v, want %v", surface, got.FindingKinds, kinds)
	}
	got.FindingKinds = nil
	if !reflect.DeepEqual(got, boolean) {
		t.Fatalf("%s observation = %+v, want boolean classification %+v", surface, got, boolean)
	}
}

func TestClassifyMCPToolCallWithOptions_CredentialPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		path   string
		secret bool
	}{
		{"bare env", ".env", true},
		{"dot relative env", "./.env", true},
		{"env variant", ".env.local", true},
		{"relative aws", ".aws/credentials", true},
		{"bare rsa", "id_rsa", true},
		{"relative ssh config", ".ssh/config", true},
		{"bare ssh directory", ".ssh", true},
		{"relative ssh key", ".ssh/id_ed25519", true},
		{"bare ed25519", "id_ed25519", true},
		{"rsa variant", "id_rsa.pub", true},
		{"ed25519 variant", "id_ed25519.pub", true},
		{"relative kube config", ".kube/config", true},
		{"relative docker config", ".docker/config.json", true},
		{"bare netrc", ".netrc", true},
		{"bare npmrc", ".npmrc", true},
		{"bare pypirc", ".pypirc", true},
		{"git credentials", ".git-credentials", true},
		{"absolute netrc with space", "/home/my user/.netrc", true},
		{"bare secrets directory", "secrets", true},
		{"bare kubeconfig", "kubeconfig", true},
		{"relative shadow", "etc/shadow", true},
		{"relative passwd", "etc/passwd", true},
		{"windows aws", `C:\Users\u\.aws\credentials`, true},
		{"home npmrc", "~/.npmrc", true},
		{"surrounding spaces", " id_rsa ", true},
		{"parent traversal", "x/../.env", true},
		{"absolute netrc", "/home/u/.netrc", true},
		{"absolute pypirc", "/home/u/.pypirc", true},
		{"absolute git credentials", "/home/u/.git-credentials", true},
		{"absolute kube config", "/home/u/.kube/config", true},
		{"absolute docker config", "/home/u/.docker/config.json", true},
		{"uppercase credential", ".NETRC", true},
		{"readme", "README.md", false},
		{"source file", "src/env.go", false},
		{"environment yaml", "environment.yaml", false},
		// Preserve the existing /secrets substring match, including longer names.
		{"secrets management retains legacy substring match", "docs/secrets-management.md", true},
		{"free text env", "rotate the .env file please", false},
		{"free text relative credential", "rotate .netrc please", false},
		{"free text absolute env retains legacy match", "rotate /home/u/.env please", true},
		{"kube source", "kube/config.go", false},
		{"kube other file", ".kube/config.go", false},
		{"docker other file", ".docker/config", false},
		{"etc other file", "etc/hosts", false},
		{"bare kube directory", ".kube", false},
		{"url", "https://example.com/docs", false},
		{"tab separated prose", "rotate\t.netrc", false},
		{"unicode space prose", "rotate\u00a0.netrc", false},
		// Normalization bypasses on two-segment credential paths.
		{"double slash kube config", ".kube//config", true},
		{"dot segment kube config", ".kube/./config", true},
		{"absolute double slash kube config", "/home/u/.kube//config", true},
		{"absolute dot segment kube config", "/home/u/.kube/./config", true},
		{"parent collapse kube config", ".kube/sub/../config", true},
		{"double slash docker config", ".docker//config.json", true},
		{"dot segment docker config", ".docker/./config.json", true},
		{"absolute double slash docker config", "/home/u/.docker//config.json", true},
		{"double slash etc shadow", "etc//shadow", true},
		{"dot segment etc shadow", "etc/./shadow", true},
		{"absolute double slash etc shadow", "/etc//shadow", true},
		{"absolute dot segment etc shadow", "/etc/./shadow", true},
		{"parent collapse etc shadow", "/etc/sub/../shadow", true},
		{"double slash etc passwd", "etc//passwd", true},
		{"absolute dot segment etc passwd", "/etc/./passwd", true},
		{"mixed separator kube config", `.kube\/config`, true},
		{"mixed separator etc shadow", `etc/\shadow`, true},
		// Whitespace in paths without a trailing or leading slash match.
		{"absolute ssh dir with space", "/home/my user/.ssh", true},
		{"absolute aws dir with space", "/home/my user/.aws", true},
		{"windows ssh dir with space", `C:\Users\My User\.ssh`, true},
		{"unc aws dir with space", `\\server\my share\.aws`, true},
		{"relative aws child with space", ".aws/my credentials", true},
		{"relative ssh child with space", ".ssh/my key", true},
		{"spaced double slash kube config", "/home/my user/.kube//config", true},
		{"spaced dot segment kube config", "/home/my user/.kube/./config", true},
		{"spaced dot segment etc shadow", "my dir/etc/./shadow", true},
		// file:// URIs with percent-encoding, query, or fragment.
		{"file uri percent encoded env", "file:///home/u/%2eenv", true},
		{"file uri fully percent encoded env", "file:///%2e%65%6e%76", true},
		{"file uri percent encoded ssh config", "file:///home/u/%2essh/config", true},
		{"file uri percent encoded aws", "file:///home/u/%2eaws/credentials", true},
		{"file uri percent encoded shadow", "file:///etc/%73hadow", true},
		{"file uri percent encoded passwd", "file:///etc/%70asswd", true},
		{"file uri percent encoded kube config", "file:///home/u/.kube/%63onfig", true},
		{"file uri percent encoded docker config", "file:///home/u/.docker/%63onfig.json", true},
		{"file uri percent encoded netrc", "file:///home/u/%2enetrc", true},
		{"file uri localhost percent encoded shadow", "file://localhost/etc/%73hadow", true},
		{"file uri percent encoded space ssh dir", "file:///home/my%20user/.ssh", true},
		{"file uri ssh with query", "file:///home/u/.ssh?v=1", true},
		{"file uri ssh with fragment", "file:///home/u/.ssh#frag", true},
		{"file uri trailing percent space netrc", "file:///home/u/.netrc%20", true},
		{"uppercase file uri percent encoded env", "FILE:///home/u/%2eenv", true},
		// Windows drive-relative paths.
		{"windows drive relative env", "C:.env", true},
		{"windows drive relative aws", `C:.aws\credentials`, true},
		{"windows drive relative ssh config", `C:.ssh\config`, true},
		{"windows drive relative rsa", "C:id_rsa", true},
		{"windows drive relative netrc", "C:.netrc", true},
		{"windows drive relative kube config", `C:.kube\config`, true},
		{"windows drive relative docker config", `C:.docker\config.json`, true},
		{"windows drive relative shadow", `C:etc\shadow`, true},
		// NUL truncation, Windows trailing dots, quotes, env/kubeconfig variants.
		{"nul suffixed env", ".env\x00", true},
		{"nul truncated env", ".env\x00.txt", true},
		{"nul suffixed netrc", ".netrc\x00", true},
		{"nul suffixed shadow", "etc/shadow\x00", true},
		{"trailing dot netrc", ".netrc.", true},
		{"trailing dot kube config", ".kube/config.", true},
		{"trailing dot docker config", ".docker/config.json.", true},
		{"trailing dot ssh dir", ".ssh.", true},
		{"trailing dot shadow", "etc/shadow.", true},
		{"trailing space and dot kube config", ".kube\\config .", true},
		{"ntfs default stream kube config", ".kube\\config::$DATA", true},
		{"ntfs named stream env", ".env:hidden", true},
		{"ntfs default stream ordinary file", "notes.txt::$DATA", false},
		{"rejected file uri keeps raw candidate", "file:///%zz/.kube/./config", true},
		{"double quoted env", `".env"`, true},
		{"single quoted aws", "'.aws/credentials'", true},
		{"hyphen env variant", ".env-local", true},
		{"underscore env variant", ".env_prod", true},
		{"kubeconfig yaml", "kubeconfig.yaml", true},
		{"kubeconfig yml", "kubeconfig.yml", true},
		// False-positive guardrails on common repo files and prose.
		{"root env go source", "env.go", false},
		{"root secrets test source", "secrets_test.go", false},
		{"root secrets markdown", "secrets.md", false},
		{"bare envrc direnv file", ".envrc", false},
		{"kubeconfig go source", "kubeconfig.go", false},
		{"prose starting with id_rsa", "id_rsa is my key", false},
		{"prose starting with env variant", ".env.local is missing", false},
		{"prose mentioning relative aws", "check .aws/credentials before deploy", false},
		{"prose starting with etc passwd", "etc/passwd is a file", false},
		{"prose with spaced slashes around ssh", "use / .ssh / keys", false},
		{"benign file uri", "file:///home/u/README.md", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			args, err := json.Marshal(map[string]string{"path": tt.path})
			if err != nil {
				t.Fatal(err)
			}
			got := session.ClassifyMCPToolCallWithOptions("read_file", string(args), nil, nil, session.ClassificationOptions{})
			if secret := got.Class == session.ActionClassSecret; secret != tt.secret {
				t.Fatalf("class = %v for %q, want secret = %v", got.Class, tt.path, tt.secret)
			}
			if tt.secret && got.Sensitivity != session.SensitivityProtected {
				t.Fatalf("sensitivity = %v, want protected", got.Sensitivity)
			}
		})
	}
}

func TestPolicyMatrixEvaluate_CredentialPathReads(t *testing.T) {
	t.Parallel()
	const hostileReason = "sensitive_action_after_hostile_external_exposure"
	tests := []struct {
		name   string
		path   string
		taint  session.TaintLevel
		want   session.PolicyDecision
		reason string
	}{
		{"relative after hostile exposure", ".env", session.TaintExternalHostile, session.PolicyBlock, hostileReason},
		{"absolute after hostile exposure", "/home/u/proj/.env", session.TaintExternalHostile, session.PolicyBlock, hostileReason},
		{"relative without exposure", ".env", session.TaintTrusted, session.PolicyAllow, "trusted_or_allowlisted_context"},
		{"absolute without exposure", "/home/u/proj/.env", session.TaintTrusted, session.PolicyAllow, "trusted_or_allowlisted_context"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			args, err := json.Marshal(map[string]string{"path": tt.path})
			if err != nil {
				t.Fatal(err)
			}
			classified := session.ClassifyMCPToolCallWithOptions("read_file", string(args), nil, nil, session.ClassificationOptions{})
			pm := session.PolicyMatrix{Profile: "balanced"}
			got := pm.Evaluate(tt.taint, classified.Class, classified.Sensitivity, session.AuthorityUnknown)
			if got.Decision != tt.want || got.Reason != tt.reason {
				t.Fatalf("decision = %v, reason = %q; want %v, %q", got.Decision, got.Reason, tt.want, tt.reason)
			}
		})
	}
}

func TestClassifyMCPToolCallWithOptions_CredentialArgumentShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		tool      string
		args      string
		wantClass session.ActionClass
	}{
		// Non-target queries carrying the plain English word "secrets" must not false-positive.
		{"search query bare secrets", "search_code", `{"query":"secrets"}`, session.ActionClassRead},
		{"search files bare secrets with repo path", "search_files", `{"pattern":"secrets","path":"internal/"}`, session.ActionClassRead},
		{"issue label bare secrets", "list_issues", `{"label":"secrets"}`, session.ActionClassRead},
		{"read file with section secrets", "read_file", `{"path":"README.md","section":"secrets"}`, session.ActionClassRead},
		{"write file with tag secrets", "write_file", `{"path":"README.md","tag":"secrets","content":"hi"}`, session.ActionClassWrite},
		{"commit message mentioning id_rsa", "create_commit", `{"message":"fix id_rsa handling"}`, session.ActionClassWrite},
		// Target keys and path-shaped or unambiguous secret targets still classify as secret.
		{"directory key bare secrets", "list_directory", `{"directory":"secrets"}`, session.ActionClassSecret},
		{"dir key spaced aws child", "list_files", `{"dir":".aws/my creds"}`, session.ActionClassSecret},
		{"unknown key path under secrets", "read_file", `{"arg":"secrets/api.key"}`, session.ActionClassSecret},
		{"unknown key dot relative secrets", "read_file", `{"arg":"./secrets"}`, session.ActionClassSecret},
		{"unknown key trailing slash secrets", "read_file", `{"arg":"secrets/"}`, session.ActionClassSecret},
		{"unknown key bare env", "read_file", `{"arg":".env"}`, session.ActionClassSecret},
		{"unknown key padded rsa", "read_file", `{"arg":" id_rsa "}`, session.ActionClassSecret},
		{"unknown key drive relative env", "read_file", `{"arg":"C:.env"}`, session.ActionClassSecret},
		{"unknown key encoded file uri", "read_file", `{"arg":"file:///home/u/%2eenv"}`, session.ActionClassSecret},
		{"unknown key spaced file uri", "read_file", `{"arg":"file:///home/my user/.ssh"}`, session.ActionClassSecret},
		{"nested object env", "read_file", `{"request":{"file":".env"}}`, session.ActionClassSecret},
		{"target array containing env", "read_file", `{"paths":["README.md",".env"]}`, session.ActionClassSecret},
		{"unknown array containing netrc", "read_file", `{"items":["README.md",".netrc"]}`, session.ActionClassSecret},
		{"malformed bare env argument", "read_file", `.env`, session.ActionClassSecret},
		{"write relative env matches absolute secret class", "write_file", `{"path":".env","content":"KEY=val"}`, session.ActionClassSecret},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := session.ClassifyMCPToolCallWithOptions(tt.tool, tt.args, nil, nil, session.ClassificationOptions{})
			if got.Class != tt.wantClass {
				t.Fatalf("class = %v for %s(%s), want %v", got.Class, tt.tool, tt.args, tt.wantClass)
			}
			if tt.wantClass == session.ActionClassSecret && got.Sensitivity != session.SensitivityProtected {
				t.Fatalf("sensitivity = %v, want protected", got.Sensitivity)
			}
		})
	}
}
