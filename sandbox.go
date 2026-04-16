package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// run builds the bwrap argument list and execs into bwrap.
func run(cfg *Config) error {
	// Resolve flox-env state (closure, bash path, flox binary) before
	// building the argv — the flox-env filesystem layout depends on it.
	var fes *floxEnvState
	if cfg.Mode == "flox-env" {
		var err error
		fes, err = resolveFloxEnv(cfg)
		if err != nil {
			return err
		}
	}

	args := buildBwrapArgs(cfg, fes)

	// Find bwrap.
	bwrap := bwrapPath
	if bwrap == "" {
		var err error
		bwrap, err = exec.LookPath("bwrap")
		if err != nil {
			return fmt.Errorf("bwrap not found in PATH")
		}
	}

	// Attach seccomp filter (unless --no-seccomp).
	if !cfg.NoSeccomp {
		secArgs, err := loadSeccompFd(bwrap, cfg.DryRun)
		if err != nil {
			return err
		}
		args = append(args, secArgs...)
	}

	// Build the final command line inside the sandbox.
	finalCmd := cfg.Command
	if cfg.Mode == "flox-env" && !cfg.NoActivate {
		finalCmd = buildFloxEnvCommand(cfg)
	}

	// Dry-run: print argv and exit.
	if cfg.DryRun {
		printDryRun(bwrap, args, finalCmd)
		return nil
	}

	// Exec bwrap (replaces this process).
	argv := []string{"bwrap"}
	argv = append(argv, args...)
	argv = append(argv, "--")
	argv = append(argv, finalCmd...)
	return syscall.Exec(bwrap, argv, os.Environ())
}

// buildBwrapArgs composes the full bwrap argument list.
func buildBwrapArgs(cfg *Config, fes *floxEnvState) []string {
	var args []string

	// 1. Hardening core (always, all modes).
	args = append(args,
		"--unshare-user",
		"--unshare-ipc",
		"--unshare-pid",
		"--unshare-uts",
		"--unshare-cgroup-try",
		"--disable-userns",
		"--assert-userns-disabled",
		"--die-with-parent",
		"--hostname", cfg.Hostname,
	)

	// 2. Mode-specific filesystem layout.
	switch cfg.Mode {
	case "run":
		args = append(args, buildRunFS()...)
	case "agent":
		args = append(args, buildAgentFS()...)
	case "flox-env":
		args = append(args, buildFloxEnvFS(cfg, fes)...)
	}

	// 3. Network policy.
	if cfg.ResolvedNet {
		args = append(args, roBindTry("/etc/resolv.conf")...)
		args = append(args, roBindTry("/etc/hosts")...)
		args = append(args, roBindTry("/etc/ssl")...)
		args = append(args, roBindTry("/etc/ca-certificates")...)
		args = append(args, roBindTry("/etc/pki")...)
	} else {
		args = append(args, "--unshare-net")
	}

	// 4. Env scrub + baseline setenvs.
	args = append(args,
		"--clearenv",
		"--setenv", "PATH", "/usr/bin:/bin:/usr/sbin:/sbin",
		"--setenv", "TERM", envOr("TERM", "dumb"),
		"--setenv", "LANG", envOr("LANG", "C.UTF-8"),
	)

	// 5. Mode-specific env/bindings.
	switch cfg.Mode {
	case "run":
		args = append(args, buildRunEnv()...)
	case "agent":
		args = append(args, buildAgentEnv(cfg)...)
	case "flox-env":
		args = append(args, buildFloxEnvEnv(cfg, fes)...)
	}

	// 6. User extras.
	for _, b := range cfg.Binds {
		args = append(args, "--bind", b[0], b[1])
	}
	for _, b := range cfg.RoBinds {
		args = append(args, "--ro-bind", b[0], b[1])
	}
	for _, kv := range cfg.SetEnvs {
		args = append(args, "--setenv", kv[0], kv[1])
	}

	// 7. Lifecycle fds.
	if cfg.LockFile != "" {
		// Auto-bind the lock file into the jail unless the user already
		// bound the same jail-side path.
		if !userBoundDst(cfg, cfg.LockFile) {
			args = append(args, "--bind", cfg.LockFile, cfg.LockFile)
		}
		args = append(args, "--lock-file", cfg.LockFile)
	}
	if cfg.SyncFd != "" {
		args = append(args, "--sync-fd", cfg.SyncFd)
	}
	if cfg.InfoFd != "" {
		args = append(args, "--info-fd", cfg.InfoFd)
	}

	// 8. /etc seal.
	args = append(args, "--remount-ro", "/etc")

	return args
}

// printDryRun prints the bwrap command line in a re-runnable shell format.
func printDryRun(bwrap string, args []string, cmd []string) {
	fmt.Print("bwrap")
	for _, a := range args {
		if strings.ContainsAny(a, " \t\n\"'\\") {
			fmt.Printf(" %q", a)
		} else {
			fmt.Printf(" %s", a)
		}
	}
	fmt.Print(" --")
	for _, a := range cmd {
		if strings.ContainsAny(a, " \t\n\"'\\") {
			fmt.Printf(" %q", a)
		} else {
			fmt.Printf(" %s", a)
		}
	}
	fmt.Println()
}

// --- helpers ---

// roBindTry returns --ro-bind-try SRC SRC if SRC exists, else nil.
func roBindTry(path string) []string {
	if _, err := os.Stat(path); err == nil {
		return []string{"--ro-bind-try", path, path}
	}
	return nil
}

// etcAllowlistBase returns the /etc tmpfs + surgical allowlist shared by
// run/agent modes.
func etcAllowlistBase() []string {
	return []string{
		"--tmpfs", "/etc",
		"--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
		"--ro-bind-try", "/etc/ld.so.conf", "/etc/ld.so.conf",
		"--ro-bind-try", "/etc/ld.so.conf.d", "/etc/ld.so.conf.d",
		"--ro-bind-try", "/etc/nsswitch.conf", "/etc/nsswitch.conf",
		"--ro-bind-try", "/etc/alternatives", "/etc/alternatives",
		"--ro-bind-try", "/etc/passwd", "/etc/passwd",
		"--ro-bind-try", "/etc/group", "/etc/group",
		"--ro-bind-try", "/etc/host.conf", "/etc/host.conf",
		"--ro-bind-try", "/etc/localtime", "/etc/localtime",
	}
}

// procDevTmpfs returns the shared --proc, --dev, --tmpfs args.
func procDevTmpfs() []string {
	return []string{
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--tmpfs", "/var/tmp",
		"--tmpfs", "/run",
	}
}

// envOr returns the value of an env var, or a fallback if unset.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// userBoundDst checks whether the user already bound a specific jail-side
// destination via --bind or --ro-bind.
func userBoundDst(cfg *Config, dst string) bool {
	for _, b := range cfg.Binds {
		if b[1] == dst {
			return true
		}
	}
	for _, b := range cfg.RoBinds {
		if b[1] == dst {
			return true
		}
	}
	return false
}

// resolveRealpath resolves a path to its canonical absolute form,
// following symlinks.  Equivalent to `readlink -f` in bash.
func resolveRealpath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return abs
	}
	return resolved
}
