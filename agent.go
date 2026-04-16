package main

import "os"

// buildAgentFS returns the filesystem layout args for agent mode.
// Same host-overlaid layout as run mode.
func buildAgentFS() []string {
	return buildRunFS()
}

// buildAgentEnv returns the env/binding args for agent mode:
// project dir rw (or ro if --project-ro), persistent agent home,
// host PATH inherited, ~/.gitconfig ro-bound, passthrough envs,
// NO --new-session (interactive tty preserved, TIOCSTI mitigated
// by seccomp instead).
func buildAgentEnv(cfg *Config) []string {
	var args []string

	// Project bind: rw by default, ro if --project-ro.
	if cfg.ProjectRo {
		args = append(args, "--ro-bind", cfg.ResolvedProject, cfg.ResolvedProjAs)
	} else {
		args = append(args, "--bind", cfg.ResolvedProject, cfg.ResolvedProjAs)
	}

	// Agent home + env.
	args = append(args,
		"--bind", cfg.ResolvedHome, cfg.ResolvedHome,
		"--setenv", "HOME", cfg.ResolvedHome,
		"--setenv", "TMPDIR", "/tmp",
		"--chdir", cfg.ResolvedProjAs,
	)

	// Inherit host $PATH so Flox/Nix tools resolve inside the jail.
	if hostPath := os.Getenv("PATH"); hostPath != "" {
		args = append(args, "--setenv", "PATH", hostPath)
	}

	// Pass host ~/.gitconfig ro, if present.
	if home := os.Getenv("HOME"); home != "" {
		gitconfig := home + "/.gitconfig"
		if _, err := os.Stat(gitconfig); err == nil {
			args = append(args, "--ro-bind", gitconfig, cfg.ResolvedHome+"/.gitconfig")
		}
	}

	// Passthrough env vars.
	for _, v := range cfg.PassthroughEnvs {
		if v == "" {
			continue
		}
		if val := os.Getenv(v); val != "" {
			args = append(args, "--setenv", v, val)
		}
	}

	// NOTE: no --new-session in agent mode.  TIOCSTI is mitigated by
	// the seccomp BPF filter instead.

	return args
}
