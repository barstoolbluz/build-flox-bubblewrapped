package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// getNixRequisites queries the nix store for all requisites (dependencies)
// of a store path.  Adapted from flox-bwrap's paths.go:57-73.
func getNixRequisites(path string) ([]string, error) {
	cmd := exec.Command("nix-store", "--query", "--requisites", path)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nix-store --query --requisites %s: %w", path, err)
	}
	var paths []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		p := strings.TrimSpace(scanner.Text())
		if p != "" {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// resolveLocalEnvTargets returns the nix store paths that the env's
// .flox/run/* symlinks point to.  Adapted from flox-bwrap's
// parseLocalEnvRequisites (paths.go:131-171).
func resolveLocalEnvTargets(envDir string) ([]string, error) {
	absDir, err := filepath.Abs(envDir)
	if err != nil {
		return nil, err
	}
	runDir := filepath.Join(absDir, ".flox", "run")
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return nil, fmt.Errorf("no .flox/run in %s (run 'flox activate' there once first to populate it): %w", absDir, err)
	}

	var targets []string
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink == 0 {
			continue
		}
		linkPath := filepath.Join(runDir, entry.Name())
		target, err := os.Readlink(linkPath)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(target, "/nix/store/") {
			continue
		}
		resolved, err := filepath.EvalSymlinks(linkPath)
		if err != nil {
			continue
		}
		targets = append(targets, resolved)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid /nix/store run symlinks in %s", runDir)
	}
	return targets, nil
}

// resolveRemoteEnvTargets runs `flox pull -r ref` and returns the nix store
// paths that ~/.cache/flox/run/<owner>/*.<name>.* symlinks point to.
// Adapted from flox-bwrap's parseRemoteEnvRequisites (paths.go:76-128).
func resolveRemoteEnvTargets(ref string) ([]string, error) {
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid remote env format: %s (expected owner/name)", ref)
	}
	owner, name := parts[0], parts[1]

	// Pull the env.
	pullCmd := exec.Command("flox", "pull", "-r", ref)
	pullCmd.Stderr = os.Stderr
	if err := pullCmd.Run(); err != nil {
		return nil, fmt.Errorf("flox pull failed for %s: %w", ref, err)
	}

	home := os.Getenv("HOME")
	if home == "" {
		home = "/tmp"
	}
	runDir := filepath.Join(home, ".cache", "flox", "run", owner)
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return nil, fmt.Errorf("no ~/.cache/flox/run/%s after pull: %w", owner, err)
	}

	var targets []string
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink == 0 {
			continue
		}
		// Match "x86_64-linux.<name>.dev" and similar.
		if !strings.Contains(entry.Name(), "."+name+".") {
			continue
		}
		linkPath := filepath.Join(runDir, entry.Name())
		target, err := os.Readlink(linkPath)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(target, "/nix/store/") {
			continue
		}
		resolved, err := filepath.EvalSymlinks(linkPath)
		if err != nil {
			continue
		}
		targets = append(targets, resolved)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no run symlinks for %s in %s", ref, runDir)
	}
	return targets, nil
}

// computeClosure computes the union of transitive closures for a set of
// seed paths.  Returns a sorted, deduplicated list.
// Adapted from flox-bwrap's getNixRequisites + dedup (paths.go:57-73, 174-184).
func computeClosure(seeds []string) ([]string, error) {
	seen := make(map[string]bool)
	for _, seed := range seeds {
		paths, err := getNixRequisites(seed)
		if err != nil {
			return nil, err
		}
		for _, p := range paths {
			seen[p] = true
		}
	}
	var result []string
	for p := range seen {
		result = append(result, p)
	}
	sort.Strings(result)
	return result, nil
}

// findBashInClosure returns the path to bin/bash in the first closure entry
// that has an executable bash.  Adapted from flox-bwrap's paths.go:40-47.
func findBashInClosure(paths []string) (string, error) {
	for _, p := range paths {
		candidate := filepath.Join(p, "bin", "bash")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no bin/bash found in closure (%d paths searched)", len(paths))
}
