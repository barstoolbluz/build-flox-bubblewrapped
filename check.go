package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type probeRecord struct {
	Name   string
	Status string // "pass", "fail", "opt_supported", "opt_missing"
}

type checkState struct {
	format      string // "text" or "json"
	passed      int
	failed      int
	optPresent  int
	optMissing  int
	probes      []probeRecord
}

func (cs *checkState) passMsg(name string) {
	cs.probes = append(cs.probes, probeRecord{name, "pass"})
	cs.passed++
	if cs.format == "text" {
		fmt.Printf("  PASS  %s\n", name)
	}
}

func (cs *checkState) failMsg(name, detail string) {
	fullName := name
	if detail != "" {
		fullName = name + " — " + detail
	}
	cs.probes = append(cs.probes, probeRecord{fullName, "fail"})
	cs.failed++
	if cs.format == "text" {
		if detail != "" {
			fmt.Printf("  FAIL  %s — %s\n", name, detail)
		} else {
			fmt.Printf("  FAIL  %s\n", name)
		}
	}
}

func (cs *checkState) optMsg(flag, status string) {
	if status == "present" {
		cs.probes = append(cs.probes, probeRecord{"bwrap supports " + flag, "opt_supported"})
		cs.optPresent++
		if cs.format == "text" {
			fmt.Printf("  OPT   bwrap supports %s  (optional: only needed if %s is passed at runtime)\n", flag, flag)
		}
	} else {
		cs.probes = append(cs.probes, probeRecord{"bwrap supports " + flag, "opt_missing"})
		cs.optMissing++
		if cs.format == "text" {
			fmt.Printf("  OPT   bwrap missing  %s  (optional: %s will fail if used)\n", flag, flag)
		}
	}
}

func (cs *checkState) optExternal(name, status, detail string) {
	if status == "present" {
		cs.probes = append(cs.probes, probeRecord{name, "opt_supported"})
		cs.optPresent++
		if cs.format == "text" {
			if detail != "" {
				fmt.Printf("  OPT   %s  (%s)\n", name, detail)
			} else {
				fmt.Printf("  OPT   %s\n", name)
			}
		}
	} else {
		cs.probes = append(cs.probes, probeRecord{name, "opt_missing"})
		cs.optMissing++
		if cs.format == "text" {
			if detail != "" {
				fmt.Printf("  OPT   %s  (missing — %s)\n", name, detail)
			} else {
				fmt.Printf("  OPT   %s  (missing)\n", name)
			}
		}
	}
}

func (cs *checkState) emitJSON() {
	ok := "false"
	if cs.failed == 0 {
		ok = "true"
	}
	fmt.Println("{")
	fmt.Printf("  \"schema\": \"bubblewrap-jail-check/1\",\n")
	fmt.Printf("  \"wrapper_version\": %s,\n", jsonStr(version))
	if len(cs.probes) == 0 {
		fmt.Println("  \"probes\": [],")
	} else {
		fmt.Println("  \"probes\": [")
		for i, p := range cs.probes {
			comma := ","
			if i == len(cs.probes)-1 {
				comma = ""
			}
			fmt.Printf("    {\"name\": %s, \"status\": %s}%s\n",
				jsonStr(p.Name), jsonStr(p.Status), comma)
		}
		fmt.Println("  ],")
	}
	fmt.Println("  \"summary\": {")
	fmt.Printf("    \"passed\": %d,\n", cs.passed)
	fmt.Printf("    \"failed\": %d,\n", cs.failed)
	fmt.Printf("    \"opt_supported\": %d,\n", cs.optPresent)
	fmt.Printf("    \"opt_missing\": %d,\n", cs.optMissing)
	fmt.Printf("    \"ok\": %s\n", ok)
	fmt.Println("  }")
	fmt.Println("}")
}

func (cs *checkState) printSummary() {
	if cs.format == "text" {
		fmt.Printf("=== result: %d passed, %d failed; optional: %d supported / %d missing ===\n",
			cs.passed, cs.failed, cs.optPresent, cs.optMissing)
	} else {
		cs.emitJSON()
	}
}

// jsonStr returns a JSON-escaped quoted string.
func jsonStr(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\t", "\\t")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return "\"" + s + "\""
}

// runCheck implements the check/doctor subcommand.  Returns the exit code.
func runCheck(args []string) int {
	cs := &checkState{format: "text"}

	// Parse check-specific flags.
	for _, a := range args {
		switch a {
		case "--json":
			cs.format = "json"
		case "-h", "--help":
			usage(os.Stdout)
			return 0
		default:
			fatalf("unknown option: %s", a)
		}
	}

	if cs.format == "text" {
		fmt.Println("=== bubblewrap-jail compat probe ===")
	}

	// bwrap present?
	bwrapBin, err := exec.LookPath("bwrap")
	if err != nil {
		cs.failMsg("bwrap not found in PATH", "")
		cs.printSummary()
		return 1
	}
	cs.passMsg(fmt.Sprintf("bwrap in PATH (%s)", bwrapBin))

	// bwrap version.
	verOut, err := exec.Command(bwrapBin, "--version").Output()
	if err == nil {
		parts := strings.Fields(string(verOut))
		if len(parts) > 0 {
			cs.passMsg("bwrap version: " + parts[len(parts)-1])
		} else {
			cs.failMsg("bwrap --version returned nothing parseable", "")
		}
	} else {
		cs.failMsg("bwrap --version returned nothing parseable", "")
	}

	// Required bwrap flags.
	helpOut, _ := exec.Command(bwrapBin, "--help").CombinedOutput()
	helpStr := string(helpOut)

	requiredFlags := []string{
		"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts",
		"--unshare-cgroup-try", "--unshare-net",
		"--disable-userns", "--assert-userns-disabled",
		"--die-with-parent", "--hostname", "--new-session",
		"--bind", "--ro-bind", "--ro-bind-try",
		"--tmpfs", "--proc", "--dev", "--remount-ro",
		"--clearenv", "--setenv", "--chdir", "--seccomp",
	}
	for _, flag := range requiredFlags {
		if bwrapHasFlag(helpStr, flag) {
			cs.passMsg("bwrap supports " + flag)
		} else {
			cs.failMsg("bwrap missing feature", flag)
		}
	}

	// Optional bwrap flags.
	for _, flag := range []string{"--lock-file", "--sync-fd", "--info-fd"} {
		if bwrapHasFlag(helpStr, flag) {
			cs.optMsg(flag, "present")
		} else {
			cs.optMsg(flag, "missing")
		}
	}

	// flox-env runtime deps (OPT).
	if nixStore, err := exec.LookPath("nix-store"); err == nil {
		cs.optExternal("flox-env: nix-store available", "present", nixStore)
	} else {
		cs.optExternal("flox-env: nix-store available", "missing",
			"required for closure computation in flox-env immutable mode")
	}
	if floxBin, err := exec.LookPath("flox"); err == nil {
		floxVer := ""
		if out, err := exec.Command(floxBin, "--version").Output(); err == nil {
			parts := strings.Fields(string(out))
			if len(parts) > 0 {
				floxVer = parts[len(parts)-1]
			}
		}
		if floxVer == "" {
			floxVer = "unknown version"
		}
		cs.optExternal("flox-env: flox CLI available", "present", floxVer)
	} else {
		cs.optExternal("flox-env: flox CLI available", "missing",
			"required by the flox-env subcommand")
	}
	if _, err := os.Stat("/etc/nix"); err == nil {
		cs.optExternal("flox-env: /etc/nix present", "present", "")
	} else {
		cs.optExternal("flox-env: /etc/nix present", "missing",
			"activation inside flox-env sandbox will fail without /etc/nix")
	}

	// Kernel user namespaces.
	if data, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		val := strings.TrimSpace(string(data))
		n := 0
		fmt.Sscanf(val, "%d", &n)
		if n > 0 {
			cs.passMsg(fmt.Sprintf("kernel user namespaces enabled (max_user_namespaces=%d)", n))
		} else {
			cs.failMsg("user namespaces disabled", "user.max_user_namespaces=0")
		}
	} else {
		cs.failMsg("cannot read /proc/sys/user/max_user_namespaces", "")
	}

	// Minimal bwrap launch.
	minCmd := exec.Command(bwrapBin,
		"--ro-bind", "/", "/",
		"--disable-userns", "--assert-userns-disabled",
		"--unshare-user", "--unshare-pid", "--die-with-parent",
		"true",
	)
	if err := minCmd.Run(); err == nil {
		cs.passMsg("minimal bwrap launch works")
	} else {
		cs.failMsg("minimal bwrap launch failed", "")
	}

	// /nix/store presence.
	if _, err := os.Stat("/nix/store"); err == nil {
		cs.passMsg("/nix/store present")
	} else {
		cs.failMsg("/nix/store absent (non-Nix host)", "many flox-packaged tools won't resolve")
	}

	// Seccomp BPF.
	if len(tiocstiBPF) > 0 {
		cs.passMsg(fmt.Sprintf("seccomp BPF readable (%d bytes at embedded)", len(tiocstiBPF)))

		// Load test: write blob to a temp file, pass to a throwaway bwrap.
		if err := preflightSeccomp(bwrapBin); err == nil {
			cs.passMsg("seccomp BPF loads into bwrap")
		} else {
			cs.failMsg("seccomp BPF present but bwrap rejected it", "")
		}
	} else {
		cs.failMsg("seccomp BPF path not substituted (running from unbuilt source?)", "")
	}

	cs.printSummary()
	if cs.failed > 0 {
		return 1
	}
	return 0
}

// bwrapHasFlag checks if a flag appears as a whole word in bwrap --help output.
func bwrapHasFlag(helpStr, flag string) bool {
	// Word-boundary match: the flag must be preceded by whitespace/SOL and
	// followed by whitespace/EOL.  This prevents --bind matching --bind-try.
	for _, line := range strings.Split(helpStr, "\n") {
		for _, word := range strings.Fields(line) {
			if word == flag {
				return true
			}
		}
	}
	return false
}
