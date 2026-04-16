package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

// tiocstiBPF is the precompiled seccomp BPF blob that blocks
// ioctl(_, TIOCSTI, _) with EPERM.  Generated at build time by
// gen-seccomp.c (see src/gen-seccomp.c) and embedded via //go:embed.
// The blob is architecture-specific (x86_64 vs aarch64); the build
// produces the correct one for the target.
//
//go:embed tiocsti.bpf
var tiocstiBPF []byte

// loadSeccompFd prepares the seccomp BPF blob on fd 10 and returns the
// bwrap flags to load it.  If the blob is empty (dev build without
// tiocsti.bpf generated), prints a warning and returns nil.
//
// Steps:
//  1. Check blob is non-empty.
//  2. If not dry-run: run a preflight probe to verify bwrap accepts the blob.
//  3. Create a memfd, write the blob, seek to 0.
//  4. Dup2 the memfd to fd 10 (bwrap convention).
//  5. Clear FD_CLOEXEC on fd 10 so bwrap inherits it across exec.
//  6. Return ["--seccomp", "10"].
func loadSeccompFd(bwrapPath string, dryRun bool) ([]string, error) {
	if len(tiocstiBPF) == 0 {
		errf("warning: no embedded seccomp BPF (running from unbuilt source?), TIOCSTI filter not applied")
		return nil, nil
	}

	if !dryRun {
		if err := preflightSeccomp(bwrapPath); err != nil {
			return nil, err
		}

		// Create a memfd and write the BPF blob into it.
		fd, err := unix.MemfdCreate("seccomp-bpf", 0)
		if err != nil {
			return nil, fmt.Errorf("memfd_create for seccomp: %w", err)
		}
		if _, err := unix.Write(fd, tiocstiBPF); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("write seccomp BPF to memfd: %w", err)
		}
		if _, err := unix.Seek(fd, 0, 0); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("seek seccomp memfd: %w", err)
		}

		// Place on fd 10 (the wrapper's convention; must not conflict with
		// --sync-fd or --info-fd, which are validated to reject 10 and 11).
		if err := unix.Dup2(fd, 10); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("dup2 seccomp fd to 10: %w", err)
		}
		if fd != 10 {
			unix.Close(fd)
		}

		// Clear FD_CLOEXEC so bwrap inherits fd 10 across exec.
		if _, err := unix.FcntlInt(uintptr(10), unix.F_SETFD, 0); err != nil {
			return nil, fmt.Errorf("clear cloexec on fd 10: %w", err)
		}
	}

	return []string{"--seccomp", "10"}, nil
}

// preflightSeccomp runs a throwaway bwrap with the BPF loaded to verify
// the kernel accepts it.  This catches truncated blobs, kernel ABI
// mismatches, and libseccomp version skew before the real exec.
//
// Uses a pipe to pass the BPF to bwrap on fd 11 (not 10, to avoid
// conflict with fds the parent may have open).  ExtraFiles[N] maps to
// fd 3+N in the child, so ExtraFiles[8] = fd 11.
func preflightSeccomp(bwrapPath string) error {
	pr, pw, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("seccomp preflight: pipe: %w", err)
	}
	defer pr.Close()

	if _, err := pw.Write(tiocstiBPF); err != nil {
		pw.Close()
		return fmt.Errorf("seccomp preflight: write pipe: %w", err)
	}
	pw.Close()

	// ExtraFiles[0] → fd 3, ..., [8] → fd 11.
	extras := make([]*os.File, 9)
	extras[8] = pr

	cmd := exec.Command(bwrapPath,
		"--ro-bind", "/", "/",
		"--disable-userns", "--assert-userns-disabled",
		"--unshare-user", "--unshare-pid", "--die-with-parent",
		"--seccomp", "11",
		"true",
	)
	cmd.ExtraFiles = extras
	out, err := cmd.CombinedOutput()
	if err != nil {
		detail := string(out)
		if detail == "" {
			detail = "no stderr from bwrap"
		}
		return fmt.Errorf("seccomp BPF rejected by bwrap: (%s)", detail)
	}
	return nil
}
