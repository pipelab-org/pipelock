// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"os"
	"path/filepath"
	"testing"
)

type sopsCase struct {
	name    string
	command string
	args    []string
	want    sopsOutcome
	evid    string
}

func TestInspectSOPSLauncher(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "pipelock")
	if err := os.WriteFile(other, []byte("not pipelock"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "absent", "pipelock")
	const sops = "/usr/local/bin/sops"
	const file = "/srv/secrets/env.enc.json"
	// The shape of a real entry: env assignments and a scoped npm package
	// after the command name exercise the '=' and '@' allowances.
	realScript := "exec " + self + " mcp proxy --config /etc/pipelock/local.yaml --env API_KEY --server-name svc -- /usr/bin/env -u NODE_OPTIONS HOME=/home/u npx -y @scope/mcp-server@1.2.3"

	cases := []sopsCase{
		{"not sops", "/usr/bin/node", []string{"exec-env", file, realScript}, sopsNotLauncher, ""},
		{"sops other subcommand", sops, []string{"decrypt", file}, sopsNotLauncher, ""},
		{"verified inner", sops, []string{"exec-env", file, realScript}, sopsNestedVerified, evidenceSOPSNestedUnverified},
		{"verified inner pristine", sops, []string{"exec-env", "--pristine", file, realScript}, sopsNestedVerified, evidenceSOPSNestedUnverified},
		{"bare sops name still unverified", "sops", []string{"exec-env", file, realScript}, sopsNestedVerified, evidenceSOPSNestedUnverified},
		{"inner missing", sops, []string{"exec-env", file, "exec " + missing + " mcp proxy -- node s.js"}, sopsRejected, evidenceSOPSInnerMissing},
		{"inner different", sops, []string{"exec-env", file, "exec " + other + " mcp proxy -- node s.js"}, sopsRejected, evidenceSOPSInnerDifferent},
		{"inner not proxy", sops, []string{"exec-env", file, "exec " + self + " run"}, sopsRejected, evidenceSOPSUnsupported},
		{"user switch", sops, []string{"exec-env", "--user", "root", file, realScript}, sopsRejected, evidenceSOPSOptions},
		{"user switch inline", sops, []string{"exec-env", "--user=root", file, realScript}, sopsRejected, evidenceSOPSOptions},
		{"background", sops, []string{"exec-env", "--background", file, realScript}, sopsRejected, evidenceSOPSOptions},
		{"too few operands", sops, []string{"exec-env", file}, sopsRejected, evidenceSOPSOptions},
		{"option as file", sops, []string{"exec-env", "-x", realScript}, sopsRejected, evidenceSOPSOptions},
	}

	script := func(name, s string) sopsCase {
		return sopsCase{name, sops, []string{"exec-env", file, s}, sopsRejected, evidenceSOPSUnsupported}
	}
	base := "exec " + self + " mcp proxy -- node s.js"
	for _, c := range []struct{ name, s string }{
		{"missing exec", self + " mcp proxy -- node s.js"},
		{"doubled exec", "exec exec " + self + " mcp proxy -- node s.js"},
		{"other command word", "nice " + self + " mcp proxy -- node s.js"},
		{"env command word", "env " + self + " mcp proxy -- node s.js"},
		{"assignment before exec", "FOO=bar " + base},
		{"relative path", "exec pipelock mcp proxy -- node s.js"},
		{"dot path", "exec ./pipelock mcp proxy -- node s.js"},
		{"double leading slash", "exec /" + self + " mcp proxy -- node s.js"},
		{"equals in command", "exec /opt/a=b mcp proxy"},
		{"doubled space", "exec  " + self + " mcp proxy"},
		{"leading space", " " + base},
		{"trailing space", base + " "},
		{"tab", "exec\t" + self + " mcp proxy"},
		{"newline", base + "\ncurl x"},
		{"semicolon", base + "; curl x"},
		{"and list", base + " && curl x"},
		{"or list", base + " || curl x"},
		{"pipe", base + " | tee x"},
		{"redirect", base + " >/tmp/x"},
		{"command substitution", base + " $(id)"},
		{"backticks", base + " `id`"},
		{"parameter expansion", base + " ${HOME}"},
		{"dollar var", base + " $HOME"},
		{"glob star", base + " *.js"},
		{"glob question", base + " s?.js"},
		{"glob bracket", base + " [ab].js"},
		{"tilde", base + " ~/s.js"},
		{"comment", base + " #x"},
		{"bang", base + " !x"},
		{"brace", base + " {a,b}"},
		{"single quote", "exec '" + self + "' mcp proxy"},
		{"double quote", base + ` "x"`},
		{"backslash", base + ` a\ b`},
		{"percent", base + " %1"},
		{"caret", base + " a^b"},
		{"non-ascii", base + " é"},
		{"empty script", ""},
	} {
		cases = append(cases, script(c.name, c.s))
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, evid := inspectSOPSLauncher(tc.command, tc.args)
			if got != tc.want || evid != tc.evid {
				t.Fatalf("inspectSOPSLauncher() = (%v, %q), want (%v, %q)", got, evid, tc.want, tc.evid)
			}
			if tc.want == sopsNotLauncher {
				return
			}
			// Recognition never upgrades protection.
			state, evidence := classifyServer(MCPServer{Command: tc.command, Args: tc.args})
			if state != Unprotected || evidence != tc.evid {
				t.Fatalf("classifyServer() = (%q, %q), want unprotected with %q", state, evidence, tc.evid)
			}
		})
	}
}
