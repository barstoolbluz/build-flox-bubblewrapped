package main

// buildRunFS returns the filesystem layout args for run mode:
// host-overlaid /usr, /bin, /sbin, /lib, /lib64, /nix (all ro);
// /etc tmpfs + surgical allowlist; /proc, /dev, /tmp scratch.
func buildRunFS() []string {
	var args []string

	// Host filesystem skeleton (read-only).
	args = append(args,
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/bin", "/bin",
	)
	args = append(args, roBindTry("/sbin")...)
	args = append(args, roBindTry("/lib")...)
	args = append(args, roBindTry("/lib64")...)
	args = append(args, roBindTry("/nix")...)

	// /etc tmpfs + baseline allowlist.
	args = append(args, etcAllowlistBase()...)

	// /proc, /dev, scratch tmpfs.
	args = append(args, procDevTmpfs()...)

	return args
}

// buildRunEnv returns the env/binding args for run mode:
// neutral HOME=/tmp, cwd=/tmp, --new-session (no controlling tty).
func buildRunEnv() []string {
	return []string{
		"--setenv", "HOME", "/tmp",
		"--setenv", "TMPDIR", "/tmp",
		"--chdir", "/tmp",
		"--new-session",
	}
}
