package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// floxEnvState holds resolved state for the flox-env subcommand.
// Computed by resolveFloxEnv before the bwrap argv is built.
type floxEnvState struct {
	closure     []string // sorted, deduped nix store paths
	bashPath    string   // absolute path to bash in the closure (for /bin symlinks)
	floxBinPath string   // absolute path to the host's flox binary (for /usr/bin/flox symlink)
	localAbsDir string   // absolute path of the local env dir (if -d); empty for -r
}

// resolveFloxEnv resolves the target Flox env, computes its closure (unless
// mutable mode, which skips closure enumeration), and finds bash in the
// closure for the /bin/sh and /bin/bash symlinks.
func resolveFloxEnv(cfg *Config) (*floxEnvState, error) {
	// Verify runtime deps.
	if _, err := exec.LookPath("flox"); err != nil {
		return nil, fmt.Errorf("flox-env: flox CLI not on PATH")
	}
	if _, err := exec.LookPath("nix-store"); err != nil && !cfg.Mutable {
		return nil, fmt.Errorf("flox-env: nix-store not on PATH (required for closure computation)")
	}

	// Resolve the flox binary's store path.
	floxPath, err := exec.LookPath("flox")
	if err != nil {
		return nil, fmt.Errorf("flox-env: flox not found: %w", err)
	}
	floxResolved, err := filepath.EvalSymlinks(floxPath)
	if err != nil {
		return nil, fmt.Errorf("flox-env: resolve flox path: %w", err)
	}

	fes := &floxEnvState{
		floxBinPath: floxResolved,
	}

	// Resolve env targets.
	var envTargets []string
	if cfg.LocalEnv != "" {
		absDir, err := filepath.Abs(cfg.LocalEnv)
		if err != nil {
			return nil, fmt.Errorf("flox-env: resolve local env: %w", err)
		}
		info, err := os.Stat(absDir)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("flox-env: local env not a directory: %s", cfg.LocalEnv)
		}
		// Resolve symlinks — matches bash's `cd "$dir" && pwd -P`.
		resolved, err := filepath.EvalSymlinks(absDir)
		if err != nil {
			resolved = absDir // fallback to unresolved
		}
		fes.localAbsDir = resolved
		envTargets, err = resolveLocalEnvTargets(absDir)
		if err != nil {
			return nil, fmt.Errorf("flox-env: %w", err)
		}
	} else {
		envTargets, err = resolveRemoteEnvTargets(cfg.RemoteEnv)
		if err != nil {
			return nil, fmt.Errorf("flox-env: %w", err)
		}
	}

	if cfg.Mutable {
		// Mutable mode: skip full closure enumeration (whole /nix/store is
		// bound rw).  Still need bash for /bin symlinks — do a quick closure
		// of just the env targets to find bash.
		quickClosure, err := computeClosure(envTargets)
		if err != nil {
			return nil, fmt.Errorf("flox-env mutable: %w", err)
		}
		bashPath, err := findBashInClosure(quickClosure)
		if err != nil {
			// Try adding flox binary's closure too.
			seeds := append(envTargets, floxResolved)
			fullClosure, err2 := computeClosure(seeds)
			if err2 != nil {
				return nil, fmt.Errorf("flox-env mutable: %w", err2)
			}
			bashPath, err = findBashInClosure(fullClosure)
			if err != nil {
				return nil, fmt.Errorf("flox-env: %w", err)
			}
		}
		fes.bashPath = bashPath
	} else {
		// Immutable mode: compute full closure (flox binary + env targets).
		seeds := append([]string{floxResolved}, envTargets...)
		closure, err := computeClosure(seeds)
		if err != nil {
			return nil, fmt.Errorf("flox-env: %w", err)
		}
		fes.closure = closure

		bashPath, err := findBashInClosure(closure)
		if err != nil {
			return nil, fmt.Errorf("flox-env: %w", err)
		}
		fes.bashPath = bashPath
	}

	return fes, nil
}

// buildFloxEnvFS returns the filesystem layout for flox-env mode.
func buildFloxEnvFS(cfg *Config, fes *floxEnvState) []string {
	var args []string
	home := os.Getenv("HOME")

	// /etc tmpfs + allowlist (same as run/agent, plus /etc/nix).
	args = append(args, etcAllowlistBase()...)
	args = append(args, "--ro-bind-try", "/etc/nix", "/etc/nix")

	// /proc, /dev, scratch tmpfs.
	args = append(args, procDevTmpfs()...)

	// Ephemeral home.
	args = append(args, "--tmpfs", home)

	// /nix/store visibility.
	if cfg.Mutable {
		args = append(args, "--bind", "/nix/store", "/nix/store")
		args = append(args, "--bind", "/nix/var", "/nix/var")
	} else {
		// Immutable: tmpfs overlay + per-path ro-bind for closure paths.
		args = append(args, "--tmpfs", "/nix/store")
		if _, err := os.Stat("/nix/var/nix/db"); err == nil {
			args = append(args, "--ro-bind", "/nix/var/nix/db", "/nix/var/nix/db")
		}
		for _, p := range fes.closure {
			args = append(args, "--ro-bind", p, p)
		}
	}

	// Synthetic /bin with bash symlinks into the closure.
	args = append(args,
		"--tmpfs", "/bin",
		"--symlink", fes.bashPath, "/bin/sh",
		"--symlink", fes.bashPath, "/bin/bash",
	)

	// Synthetic /usr/bin with flox symlink.
	args = append(args,
		"--tmpfs", "/usr/bin",
		"--symlink", fes.floxBinPath, "/usr/bin/flox",
	)

	return args
}

// buildFloxEnvEnv returns the env/binding args for flox-env mode.
func buildFloxEnvEnv(cfg *Config, fes *floxEnvState) []string {
	var args []string
	home := os.Getenv("HOME")

	// Env setup.
	args = append(args,
		"--setenv", "HOME", home,
		"--setenv", "TMPDIR", "/tmp",
		"--setenv", "PATH", "/usr/bin:/bin",
		"--setenv", "USER", envOr("USER", "user"),
		"--setenv", "SHELL", "/bin/bash",
		"--setenv", "FLOX_SHELL", "bash",
		"--chdir", home,
	)

	// Flox config bindings.
	floxConfig := filepath.Join(home, ".config", "flox")
	if _, err := os.Stat(floxConfig); err == nil {
		args = append(args, "--ro-bind", floxConfig, floxConfig)
	}
	floxData := filepath.Join(home, ".local", "share", "flox")
	if _, err := os.Stat(floxData); err == nil {
		args = append(args, "--bind", floxData, floxData)
	}

	// Env reference: local → /.flox mount; remote → ~/.cache/flox bind.
	if cfg.LocalEnv != "" {
		floxDir := filepath.Join(fes.localAbsDir, ".flox")
		args = append(args, "--bind", floxDir, "/.flox")
	} else {
		floxCache := filepath.Join(home, ".cache", "flox")
		if _, err := os.Stat(floxCache); err == nil {
			args = append(args, "--bind", floxCache, floxCache)
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

	// Optional resource passthroughs.
	if cfg.X11 {
		if display := os.Getenv("DISPLAY"); display != "" {
			// Extract display number.
			xnum := ""
			if idx := strings.Index(display, ":"); idx >= 0 {
				xnum = display[idx+1:]
				if dotIdx := strings.Index(xnum, "."); dotIdx >= 0 {
					xnum = xnum[:dotIdx]
				}
			}
			args = append(args, "--setenv", "DISPLAY", display)
			xsock := "/tmp/.X11-unix/X" + xnum
			if _, err := os.Stat(xsock); err == nil {
				args = append(args, "--ro-bind", xsock, xsock)
			}
			xauth := filepath.Join(home, ".Xauthority")
			if _, err := os.Stat(xauth); err == nil {
				args = append(args, "--ro-bind", xauth, xauth)
			}
		}
	}
	if cfg.GPU {
		if _, err := os.Stat("/dev/dri"); err == nil {
			args = append(args, "--dev-bind", "/dev/dri", "/dev/dri")
		}
		if _, err := os.Stat("/sys/dev/char"); err == nil {
			args = append(args, "--ro-bind", "/sys/dev/char", "/sys/dev/char")
		}
		if _, err := os.Stat("/sys/devices/pci0000:00"); err == nil {
			args = append(args, "--ro-bind", "/sys/devices/pci0000:00", "/sys/devices/pci0000:00")
		}
		if _, err := os.Stat("/run/opengl-driver"); err == nil {
			args = append(args, "--ro-bind", "/run/opengl-driver", "/run/opengl-driver")
		}
	}
	if cfg.DevShm {
		if _, err := os.Stat("/dev/shm"); err == nil {
			args = append(args, "--dev-bind", "/dev/shm", "/dev/shm")
		}
	}

	// Mutable mode warning.
	if cfg.Mutable {
		errf("mutable mode: /nix/store and /nix/var are bound read-write; sandbox can mutate the host nix database")
	}

	return args
}

// buildFloxEnvCommand wraps the user's command in `flox activate`.
func buildFloxEnvCommand(cfg *Config) []string {
	var cmd []string
	if cfg.LocalEnv != "" {
		cmd = append(cmd, "flox", "activate", "-d", "/")
	} else {
		cmd = append(cmd, "flox", "activate", "-r", cfg.RemoteEnv)
	}
	if len(cfg.Command) > 0 {
		cmd = append(cmd, "--")
		cmd = append(cmd, cfg.Command...)
	}
	return cmd
}
