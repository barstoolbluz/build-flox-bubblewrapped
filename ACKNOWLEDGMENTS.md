# Acknowledgments

## devusb/flox-bwrap

The `bubblewrap-jail flox-env` subcommand (shipped in v0.6.0) was inspired by
and conceptually borrows from [devusb/flox-bwrap](https://github.com/devusb/flox-bwrap),
a small Go binary for running Flox environments inside a bubblewrap sandbox.
`flox-bwrap` is licensed MIT.

No code is copied verbatim — `bubblewrap-jail` is a shell script and we
re-implemented the following patterns from scratch in bash — but the
underlying techniques are directly derived from `flox-bwrap`'s approach, and
credit is due:

- **Closure computation via `nix-store --query --requisites`** for each
  resolved run-symlink target, then dedup (see `flox-bwrap/paths.go:57-73`
  and `paths.go:174-184`; our ports are the `compute_closure` and
  `resolve_local_env` / `resolve_remote_env` helpers in `src/bubblewrap-jail`).
- **The `/.flox` mount trick** — binding the host env's `.flox` directory to
  `/.flox` inside the sandbox so `flox activate -d /` works as a clean
  "activate the env at the sandbox root" incantation (see
  `flox-bwrap/sandbox.go:103-105`).
- **Bash-in-closure discovery** — iterating closure paths looking for the
  first one whose `bin/bash` is executable, to build `/bin/sh` and
  `/bin/bash` symlinks without exposing host `/bin` (see
  `flox-bwrap/paths.go:40-47`; our port is `find_bash_in_closure`).
- **Synthetic `/bin` and `/usr/bin`** via `--tmpfs` + `--symlink` instead of
  binding host `/bin` and `/usr/bin`, so the sandbox sees only the specific
  binaries we expose (see `flox-bwrap/sandbox.go:50-58`).
- **`--mutable` mode** — binding `/nix/store` and `/nix/var` read-write so
  `flox install` can mutate the env from inside the sandbox, with the
  caveat that source-build installs fail under `--disable-userns` (see
  `flox-bwrap/sandbox.go:40-48` and `main.go:33-35`).
- **Optional X11 / GPU passthrough** flags (see `flox-bwrap/sandbox.go:132-169`;
  ours are `--x11` and `--gpu` on the `flox-env` subcommand).

What `bubblewrap-jail` adds on top of `flox-bwrap`'s layout, and what drove
the decision to compose rather than replace:

- **TIOCSTI seccomp filter** (via libseccomp-generated BPF blob loaded through
  `--seccomp`) to close the tty-injection class.
- **`--disable-userns --assert-userns-disabled`** to prevent nested user
  namespaces from inside the sandbox.
- **`--die-with-parent`** so orphaned sandbox processes cannot outlive
  their launcher.
- **`/etc` tmpfs with surgical ro-bind allowlist + `--remount-ro` seal.**
- **Reserved-mountpoint guard** on user `--bind` / `--ro-bind` destinations.
- **Orchestrator lifecycle hooks** (`--lock-file`, `--sync-fd`, `--info-fd`)
  pass-through to bwrap.
- **`check` subcommand** (and `doctor` alias) for host feature probes,
  including OPT-level probes for the `flox-env` runtime deps
  (`nix-store`, `flox`, `/etc/nix`).
- **Reproducible single-file audit surface.** `bubblewrap-jail` is one ~1400-line
  bash script plus a ~100-line C seccomp generator. The entire sandbox
  policy is reviewable in one editor session.

Thanks to Morgan Helton (@devusb) for the clean, readable reference
implementation.
