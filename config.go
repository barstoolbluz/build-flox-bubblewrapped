package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config holds the parsed CLI configuration for run/agent/flox-env modes.
type Config struct {
	Mode string // "run", "agent", "flox-env"

	// Common flags (valid across multiple modes)
	Net             *bool      // nil = use mode default
	Binds           [][2]string // --bind SRC DST (repeatable)
	RoBinds         [][2]string // --ro-bind SRC DST (repeatable)
	SetEnvs         [][2]string // --setenv K V (repeatable)
	Hostname        string
	NoSeccomp       bool
	LockFile        string
	SyncFd          string
	InfoFd          string
	BindForce       bool
	PassthroughEnvs []string // --passthrough-env VAR (repeatable)
	PassthroughSet  bool     // true if --passthrough-env was explicitly passed

	// Agent-only flags
	Project   string
	ProjectAs string
	ProjectRo bool
	AgentHome string

	// Flox-env-only flags
	LocalEnv   string // -d DIR
	RemoteEnv  string // -r OWNER/NAME
	Mutable    bool
	X11        bool
	GPU        bool
	DevShm     bool
	DryRun     bool
	NoActivate bool

	// Resolved at applyDefaults time
	ResolvedNet     bool
	ResolvedProject string
	ResolvedProjAs  string
	ResolvedHome    string // agent home (resolved + mkdir'd)

	// The user's command after --
	Command []string
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `Usage: %s <subcommand> [options] -- CMD [ARGS...]

Subcommands:
  run       Jail a command.  Minimal filesystem view, no project binding.
  agent     Jail an agent.   Project dir rw, persistent agent home.
  flox-env  Jail a Flox environment as a hardened container.  The sandbox
            sees only the Flox env's closure (immutable mode) or the full
            /nix/store rw (mutable mode, --mutable).  The env is activated
            via `+"`"+`flox activate`+"`"+` inside the sandbox.  Requires nix-store
            and flox on PATH at invocation time (not inside the sandbox).
            Pass `+"`"+`-d DIR`+"`"+` for a local env or `+"`"+`-r OWNER/NAME`+"`"+` for a remote
            Flox catalog env.  See "flox-env options" below.
  check     Probe the host for required bwrap/kernel features.  Reports
            PASS/FAIL/OPT per check and exits 0 (all required green) or
            1 (anything required red).  Optional features report on OPT
            lines and don't affect the exit code.  Pass `+"`"+`--json`+"`"+` for a
            machine-readable document (schema bubblewrap-jail-check/1)
            instead of the human-readable text output.
  doctor    Alias for `+"`"+`check`+"`"+`.  Same output, same exit code.

Common options:
  --net             Enable network (adds TLS certs, DNS, hosts).
  --no-net          Disable network.
  --bind SRC DST    Additional rw bind (may repeat).
  --ro-bind SRC DST Additional ro bind (may repeat).
  --bind-force      Disable essential-dir shadowing guard.
  --setenv K V      Additional environment variable (may repeat).
  --hostname NAME   Sandbox hostname (default: bubblewrap-jail).
  --no-seccomp      Disable TIOCSTI-blocking seccomp filter.
  --lock-file PATH  bwrap lock-file pass-through.
  --sync-fd FD      bwrap sync-fd pass-through.
  --info-fd FD      bwrap info-fd pass-through.
  -h, --help        This help.

Agent-only options:
  --project DIR         Project dir to bind rw.
  --project-as DIR      Map project to synthetic path inside jail.
  --project-ro          Bind project read-only.
  --agent-home DIR      Persistent agent HOME.
  --passthrough-env VAR Pass host env var into jail (repeatable).
                        Also valid in flox-env mode.

flox-env-only options:
  -d DIR            Local Flox environment directory.
  -r OWNER/NAME     Remote Flox catalog environment.
  --mutable         Bind /nix/store and /nix/var rw for flox install.
  --x11             Bind X socket + Xauthority.
  --gpu             Bind /dev/dri + PCI topology.
  --dev-shm         Bind /dev/shm rw.
  --dry-run         Print bwrap argv and exit.
  --no-activate     Skip flox activate wrapper.

Defaults:
  run mode:       net off; HOME=/tmp; cwd=/tmp; no project binding.
  agent mode:     net on;  HOME=<agent-home>; host PATH inherited.
  flox-env mode:  net off; HOME=tmpfs; closure-scoped /nix/store.
`, prog)
}

// parseConfig parses the flags for the given mode from args.
// args should NOT include the subcommand name itself.
func parseConfig(mode string, args []string) (*Config, error) {
	cfg := &Config{
		Mode:     mode,
		Hostname: "bubblewrap-jail",
	}

	i := 0
	for i < len(args) {
		switch args[i] {
		case "--net":
			t := true
			cfg.Net = &t
			i++
		case "--no-net":
			f := false
			cfg.Net = &f
			i++
		case "--bind":
			if i+2 >= len(args) {
				return nil, fmt.Errorf("--bind needs SRC DST")
			}
			cfg.Binds = append(cfg.Binds, [2]string{args[i+1], args[i+2]})
			i += 3
		case "--ro-bind":
			if i+2 >= len(args) {
				return nil, fmt.Errorf("--ro-bind needs SRC DST")
			}
			cfg.RoBinds = append(cfg.RoBinds, [2]string{args[i+1], args[i+2]})
			i += 3
		case "--setenv":
			if i+2 >= len(args) {
				return nil, fmt.Errorf("--setenv needs K V")
			}
			cfg.SetEnvs = append(cfg.SetEnvs, [2]string{args[i+1], args[i+2]})
			i += 3
		case "--hostname":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--hostname needs NAME")
			}
			cfg.Hostname = args[i+1]
			i += 2
		case "--project":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--project needs DIR")
			}
			cfg.Project = args[i+1]
			i += 2
		case "--project-as":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--project-as needs DIR")
			}
			cfg.ProjectAs = args[i+1]
			i += 2
		case "--project-ro":
			cfg.ProjectRo = true
			i++
		case "--agent-home":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--agent-home needs DIR")
			}
			cfg.AgentHome = args[i+1]
			i += 2
		case "--bind-force":
			cfg.BindForce = true
			i++
		case "--passthrough-env":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--passthrough-env needs VAR")
			}
			cfg.PassthroughEnvs = append(cfg.PassthroughEnvs, args[i+1])
			cfg.PassthroughSet = true
			i += 2
		case "--no-seccomp":
			cfg.NoSeccomp = true
			i++
		case "--lock-file":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--lock-file needs PATH")
			}
			// Pre-validate existence — bwrap will fail with a cryptic
			// "Can't find source path" if the file is missing or
			// inaccessible.  Check err != nil (not just IsNotExist) so
			// we also catch permission-denied and other stat failures.
			if _, err := os.Stat(args[i+1]); err != nil {
				return nil, fmt.Errorf("--lock-file path does not exist: %s (create it first; bwrap will not)", args[i+1])
			}
			cfg.LockFile = args[i+1]
			i += 2
		case "--sync-fd":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--sync-fd needs FD")
			}
			if err := validateFd(args[i+1], "--sync-fd"); err != nil {
				return nil, err
			}
			cfg.SyncFd = args[i+1]
			i += 2
		case "--info-fd":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--info-fd needs FD")
			}
			if err := validateFd(args[i+1], "--info-fd"); err != nil {
				return nil, err
			}
			cfg.InfoFd = args[i+1]
			i += 2
		// flox-env flags
		case "-d":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("-d needs DIR")
			}
			cfg.LocalEnv = args[i+1]
			i += 2
		case "-r":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("-r needs OWNER/NAME")
			}
			cfg.RemoteEnv = args[i+1]
			i += 2
		case "--mutable":
			cfg.Mutable = true
			i++
		case "--x11":
			cfg.X11 = true
			i++
		case "--gpu":
			cfg.GPU = true
			i++
		case "--dev-shm":
			cfg.DevShm = true
			i++
		case "--dry-run":
			cfg.DryRun = true
			i++
		case "--no-activate":
			cfg.NoActivate = true
			i++
		case "-h", "--help":
			usage(os.Stdout)
			os.Exit(0)
		case "--":
			cfg.Command = args[i+1:]
			i = len(args) // break
		default:
			if strings.HasPrefix(args[i], "-") {
				return nil, fmt.Errorf("unknown option: %s", args[i])
			}
			// Positional arg before -- : treat as start of command
			cfg.Command = args[i:]
			i = len(args)
		}
	}

	if len(cfg.Command) == 0 {
		return nil, fmt.Errorf("no command given")
	}

	return cfg, nil
}

// validate checks flag constraints: mode-gating, mutual exclusion, reserved names.
func (cfg *Config) validate() error {
	// Agent-only flags rejected outside agent.
	// NOTE: the "agent-only" error strings are load-bearing for red-team.sh
	// assertions.  Keep them verbatim.
	if cfg.Mode != "agent" {
		if cfg.Project != "" {
			return fmt.Errorf("--project is agent-only")
		}
		if cfg.ProjectAs != "" {
			return fmt.Errorf("--project-as is agent-only")
		}
		if cfg.AgentHome != "" {
			return fmt.Errorf("--agent-home is agent-only")
		}
		if cfg.ProjectRo {
			return fmt.Errorf("--project-ro is agent-only")
		}
	}

	// --passthrough-env is valid in agent + flox-env, not run.
	if cfg.Mode == "run" && cfg.PassthroughSet {
		return fmt.Errorf("--passthrough-env is agent-only")
	}

	// flox-env flags rejected outside flox-env.
	if cfg.Mode != "flox-env" {
		if cfg.LocalEnv != "" {
			return fmt.Errorf("-d is flox-env-only")
		}
		if cfg.RemoteEnv != "" {
			return fmt.Errorf("-r is flox-env-only")
		}
		if cfg.Mutable {
			return fmt.Errorf("--mutable is flox-env-only")
		}
		if cfg.X11 {
			return fmt.Errorf("--x11 is flox-env-only")
		}
		if cfg.GPU {
			return fmt.Errorf("--gpu is flox-env-only")
		}
		if cfg.DevShm {
			return fmt.Errorf("--dev-shm is flox-env-only")
		}
		if cfg.DryRun {
			return fmt.Errorf("--dry-run is flox-env-only")
		}
		if cfg.NoActivate {
			return fmt.Errorf("--no-activate is flox-env-only")
		}
	}

	// flox-env: require exactly one of -d or -r.
	if cfg.Mode == "flox-env" {
		if cfg.LocalEnv != "" && cfg.RemoteEnv != "" {
			return fmt.Errorf("flox-env: -d and -r are mutually exclusive")
		}
		if cfg.LocalEnv == "" && cfg.RemoteEnv == "" {
			return fmt.Errorf("flox-env: -d DIR or -r OWNER/NAME required")
		}
	}

	// Passthrough env reserved-name rejection.
	// Seed from env var default if no --passthrough-env flag was given.
	if !cfg.PassthroughSet {
		envDefault := os.Getenv("BUBBLEWRAP_JAIL_PASSTHROUGH_ENV")
		if envDefault == "" {
			envDefault = "ANTHROPIC_API_KEY"
		}
		cfg.PassthroughEnvs = strings.Split(envDefault, ",")
	}
	for _, v := range cfg.PassthroughEnvs {
		if v == "" {
			continue
		}
		switch v {
		case "PATH", "HOME", "TMPDIR", "TERM", "LANG", "PWD":
			return fmt.Errorf("--passthrough-env may not be a reserved name: %s", v)
		}
	}

	// Reserved-mountpoint guard (F2) on user --bind/--ro-bind destinations.
	if !cfg.BindForce {
		for _, b := range cfg.Binds {
			if err := checkEssentialDst(b[1]); err != nil {
				return err
			}
		}
		for _, b := range cfg.RoBinds {
			if err := checkEssentialDst(b[1]); err != nil {
				return err
			}
		}
	}

	return nil
}

// applyDefaults resolves mode-specific defaults (net, project dir, agent home).
func (cfg *Config) applyDefaults() error {
	// Net default: agent=on, run/flox-env=off.
	if cfg.Net != nil {
		cfg.ResolvedNet = *cfg.Net
	} else {
		envNet := os.Getenv("BUBBLEWRAP_JAIL_NET")
		switch envNet {
		case "1":
			cfg.ResolvedNet = true
		case "0":
			cfg.ResolvedNet = false
		case "":
			cfg.ResolvedNet = cfg.Mode == "agent"
		default:
			return fmt.Errorf("invalid BUBBLEWRAP_JAIL_NET value: %s (expected 0 or 1)", envNet)
		}
	}

	if cfg.Mode == "agent" {
		if err := cfg.resolveAgentDefaults(); err != nil {
			return err
		}
	}

	if cfg.Mode == "flox-env" {
		if home := os.Getenv("HOME"); home == "" {
			return fmt.Errorf("flox-env: $HOME not set on host; cannot construct sandbox home")
		}
	}

	return nil
}

// validateFd checks that a string is a non-negative integer and not 10 or 11
// (reserved by the wrapper for seccomp BPF fd).
func validateFd(s, flagName string) error {
	// Must be a non-negative integer (decimal digits only).
	for _, c := range s {
		if c < '0' || c > '9' {
			return fmt.Errorf("%s must be a non-negative integer: %s", flagName, s)
		}
	}
	if s == "" {
		return fmt.Errorf("%s must be a non-negative integer: (empty)", flagName)
	}
	// Reject fd 10 and 11 — reserved by the wrapper for seccomp BPF.
	// Parse as decimal (NOT octal).  strconv.Atoi parses decimal by default
	// (no octal interpretation of leading zeros), which is the correct
	// behavior — see the v0.4.3 leading-zero fix in the bash version.
	n, err := strconv.Atoi(s)
	if err == nil && (n == 10 || n == 11) {
		return fmt.Errorf("%s cannot be 10 or 11 (reserved by wrapper for seccomp BPF)", flagName)
	}
	return nil
}

// checkEssentialDst rejects --bind/--ro-bind destinations that would shadow
// FHS-essential directories.
func checkEssentialDst(dst string) error {
	switch dst {
	case "/", "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/proc", "/dev", "/nix":
		return fmt.Errorf("--bind/--ro-bind dst would shadow essential dir: %s (use --bind-force to override)", dst)
	}
	return nil
}

// resolveAgentDefaults resolves project dir, project-as, and agent home.
func (cfg *Config) resolveAgentDefaults() error {
	// Project dir: --project > BUBBLEWRAP_JAIL_PROJECT > $PWD.
	if cfg.Project == "" {
		cfg.Project = os.Getenv("BUBBLEWRAP_JAIL_PROJECT")
		if cfg.Project == "" {
			var err error
			cfg.Project, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("cannot resolve project dir: %w", err)
			}
		}
	}
	info, err := os.Stat(cfg.Project)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("project dir not a directory: %s", cfg.Project)
	}
	// Canonicalize.
	cfg.ResolvedProject = realpath(cfg.Project)

	// Project-as: default = same-path.
	if cfg.ProjectAs == "" {
		cfg.ResolvedProjAs = cfg.ResolvedProject
	} else {
		if !strings.HasPrefix(cfg.ProjectAs, "/") {
			return fmt.Errorf("--project-as must be an absolute path: %s", cfg.ProjectAs)
		}
		// Reject FHS-essential paths.
		switch cfg.ProjectAs {
		case "/", "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/proc", "/dev",
			"/tmp", "/var", "/run", "/nix", "/root", "/home":
			return fmt.Errorf("--project-as cannot shadow essential directory: %s", cfg.ProjectAs)
		}
		for _, prefix := range []string{"/bin/", "/sbin/", "/usr/", "/lib/", "/lib64/", "/etc/", "/proc/", "/dev/", "/nix/"} {
			if strings.HasPrefix(cfg.ProjectAs, prefix) {
				return fmt.Errorf("--project-as cannot be under essential directory: %s", cfg.ProjectAs)
			}
		}
		cfg.ResolvedProjAs = cfg.ProjectAs
	}

	// Agent home.
	if cfg.AgentHome == "" {
		cfg.AgentHome = os.Getenv("BUBBLEWRAP_JAIL_HOME")
		if cfg.AgentHome == "" {
			if floxCache := os.Getenv("FLOX_ENV_CACHE"); floxCache != "" {
				cfg.AgentHome = floxCache + "/agent-home"
			} else {
				xdg := os.Getenv("XDG_CACHE_HOME")
				if xdg == "" {
					home := os.Getenv("HOME")
					if home == "" {
						home = "/tmp"
					}
					xdg = home + "/.cache"
				}
				cfg.AgentHome = xdg + "/bubblewrap-jail/agent-home"
			}
		}
	}
	if err := os.MkdirAll(cfg.AgentHome, 0o755); err != nil {
		return fmt.Errorf("cannot create agent home: %w", err)
	}
	cfg.ResolvedHome = realpath(cfg.AgentHome)

	return nil
}

// realpath resolves a path to its canonical absolute form, following all
// symlinks.  Equivalent to `readlink -f` / `cd "$dir" && pwd -P` in bash.
func realpath(p string) string {
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
