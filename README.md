# bubblewrap-jail

[![CI](https://github.com/barstoolbluz/build-flox-bubblewrapped/actions/workflows/ci.yml/badge.svg)](https://github.com/barstoolbluz/build-flox-bubblewrapped/actions/workflows/ci.yml)

An opinionated [bubblewrap](https://github.com/containers/bubblewrap) wrapper
that provides hardened sandboxes for running agents (Claude Code, etc.) and
untrusted commands. Packaged as a [Flox](https://flox.dev) build.

## Threat model

**Prompt-injection defense.** The threat model assumes the agent or command
inside the jail is buggy or steerable but **not** actively malicious. The
wrapper defends against exfiltration of SSH keys, GPG keys, cloud credentials,
and arbitrary `$HOME/*` paths by an agent that has been talked into reading
them.

This is **not** a general-purpose hostile-code sandbox. Agent mode deliberately
allows every syscall except `ioctl(_, TIOCSTI, _)` (see the seccomp filter
below), because closing the prompt-injection class is the goal — not arbitrary
malicious-binary containment.

Full threat model and design rationale: see the comment block at the top of
[`src/bubblewrap-jail`](src/bubblewrap-jail).

## Subcommands

- **`bubblewrap-jail run [opts] -- CMD`** — Jail an arbitrary command. Minimal
  filesystem view, no project binding, no secrets, `--new-session` (no
  controlling tty). Net off by default.
- **`bubblewrap-jail agent [opts] -- CMD`** — Jail an agent. Project dir bound
  rw, persistent agent home, host `$PATH` inherited, `~/.gitconfig` ro-bound,
  opt-in env-var passthrough (default `ANTHROPIC_API_KEY`), interactive
  controlling tty preserved. Net on by default.
- **`bubblewrap-jail flox-env [opts] -- CMD`** — Jail a Flox environment as a
  hardened container. The sandbox sees only the Flox env's closure
  (default, immutable) or the full `/nix/store` rw (`--mutable`, for
  `flox install`). Supports local envs via `-d DIR` and remote catalog envs
  via `-r OWNER/NAME`. Requires `nix-store` and `flox` on `$PATH` at
  invocation time. Net off by default; `--x11`, `--gpu`, `--dev-shm`, and
  `--dry-run` are available as opt-ins.
- **`bubblewrap-jail check`** — Probe the host for required bwrap/kernel
  features. Reports PASS/FAIL per check; exits 0 if all green.

Run `bubblewrap-jail --help` for the full option list.

## Hardened defaults

- All namespaces unshared: `--unshare-user --unshare-ipc --unshare-pid
  --unshare-uts --unshare-cgroup-try`
- `--disable-userns --assert-userns-disabled` to block nested user namespaces
- `--die-with-parent` lifecycle
- `/etc` as tmpfs with a surgical `ro-bind` allowlist, then `--remount-ro` to
  seal the parent (so the agent cannot drop e.g. `ld.so.preload`)
- `--clearenv` plus a minimal allowlist (`PATH`, `HOME`, `TERM`, `LANG`,
  `TMPDIR`, plus the passthrough var if set)
- Seccomp BPF blocking `ioctl(_, TIOCSTI, _)` with `EPERM` — closes the
  TTY-injection attack class without `--new-session` (so interactive agents
  keep their controlling tty)
- **Not** mounted by default: `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config`,
  `/etc/shadow`, `/etc/ssh`, `/etc/sudoers`, `/etc/pam.d`

User-supplied `--bind` / `--ro-bind` flags are applied **after** the default
policy and can re-expose anything; the defaults are policy, not a guarantee.

## Flox environment sandboxing (v0.6.0+)

The `flox-env` subcommand runs a Flox environment as a hardened,
container-like sandbox. All the hardening above (TIOCSTI seccomp,
`--disable-userns`, `--die-with-parent`, `/etc` seal) applies; the
differences are in the filesystem layout.

**Immutable mode** (default) — closure-scoped, airtight:

```bash
# Run a shell inside a local Flox env's closure
bubblewrap-jail flox-env -d ./my-project -- bash

# Run a specific command inside a remote Flox catalog env
bubblewrap-jail flox-env -r myorg/data-pipeline -- python main.py

# Inspect the sandbox policy without running anything
bubblewrap-jail flox-env -d ./my-project --dry-run -- some-command
```

In immutable mode the sandbox sees only the transitive closure of (the
flox binary + the env's run-symlink targets). Host `/usr`, `/bin`,
`/lib*`, and the bulk of `/nix/store` are **not** visible. `/bin/sh`,
`/bin/bash`, and `/usr/bin/flox` are synthesized via tmpfs + symlink to
the corresponding paths in the closure.

**Mutable mode** (`--mutable`) — for `flox install` inside the sandbox:

```bash
# Let the sandboxed agent install packages into its own env
bubblewrap-jail flox-env --mutable --net -d ./my-project -- flox install ripgrep
```

Mutable mode binds the **full** host `/nix/store` and `/nix/var`
read-write so the nix daemon socket is reachable and the sandbox can
write to the store via the daemon. This is a deliberate security
trade-off: the sandboxed process can read every store path on the host
and mutate the host nix database. **Only use `--mutable` with trusted
agents.** Source-build installs (non-cache-hit) will still fail because
`nix-build` uses its own userns-based sandbox, which cannot nest under
bubblewrap-jail's `--disable-userns`; cache-hit installs (the common
case) work fine.

**Runtime dependencies:** `flox-env` needs `nix-store` and `flox` on
`$PATH` at wrapper-invocation time (not inside the sandbox — closure
computation happens before the bwrap exec). The `check` subcommand
reports these as OPT probes so `bubblewrap-jail check` tells you whether
`flox-env` will work on your host.

**Optional resource passthroughs** (off by default, only valid in
`flox-env` mode):

- `--x11` — bind the X socket + `~/.Xauthority` for GUI workloads
- `--gpu` — bind `/dev/dri`, `/sys/dev/char`, `/sys/devices/pci0000:00`,
  `/run/opengl-driver` for CUDA/ML workloads
- `--dev-shm` — bind `/dev/shm` for databases and SHM-based IPC

These are port-for-port equivalents of `flox-bwrap`'s corresponding flags
(see `ACKNOWLEDGMENTS.md`).

## Layout

```
.
├── src/
│   ├── bubblewrap-jail        the wrapper script (~520 lines)
│   └── gen-seccomp.c          libseccomp helper, compiled at build time
├── test/
│   └── red-team.sh            70-assertion attack-matrix test harness
└── .flox/env/manifest.toml    build environment + [build.bubblewrap-jail]
```

## Building

The build is a Flox nix-expression at [`.flox/pkgs/bubblewrap-jail.nix`](.flox/pkgs/bubblewrap-jail.nix)
(a single `stdenv.mkDerivation`). Only git-tracked files are visible inside
the Nix build sandbox, no network access, build inputs come from the
expression's function arguments (`{ lib, stdenv, pkg-config, libseccomp,
shellcheck }`), not from the manifest's `[install]` block.

```bash
flox build bubblewrap-jail
readlink result-bubblewrap-jail   # → /nix/store/HASH-bubblewrap-jail-VERSION
```

The build:

1. Runs `shellcheck --severity=style` on the wrapper
2. Compiles `src/gen-seccomp.c` against libseccomp via `$CC` + `pkg-config`
3. Generates the TIOCSTI BPF blob via the helper
4. Verifies the BPF size is plausible (32–4096 bytes)
5. Generates the human-readable PFC dump (`gen-seccomp --pfc`)
6. Installs the script and both blobs into `$out`
7. Substitutes the `@BPF_PATH@` and `@VERSION@` placeholders in the installed
   script via `substituteInPlace --replace-fail`

The runtime closure is tight (6 paths as of v0.5.0: the wrapper itself plus
its shebang-patched bash and transitive C runtime) — no `shellcheck`, `gcc`,
`libseccomp-dev`, or `pkg-config` leakage. **`bubblewrap` itself is not in the
closure**: the wrapper calls `bwrap` via `$PATH` at runtime, so consumer envs
must install `bubblewrap` alongside `bubblewrap-jail`.

For audit, the package also ships a human-readable dump of the seccomp
filter at `$out/share/bubblewrap-jail/tiocsti.pfc` (libseccomp's "pseudo
filter code" representation). Read it directly to see exactly what
syscalls/arguments the filter affects, without needing libseccomp
tooling on the inspecting host.

## Installing into a consumer Flox environment

Until this is published to a Flox catalog, install via store-path pin.
Note: as of v0.5.0 the package does **not** bring `bubblewrap` into its
runtime closure, so the consumer env must install `bubblewrap` explicitly
alongside it.

```toml
# In your consumer Flox env's manifest.toml
[install]
bubblewrap-jail.store-path = "/nix/store/HASH-bubblewrap-jail-VERSION"
bubblewrap-jail.systems    = ["x86_64-linux", "aarch64-linux"]
bubblewrap.pkg-path        = "bubblewrap"
bubblewrap.systems         = ["x86_64-linux", "aarch64-linux"]
```

After rebuilding, refresh the consumer pin with the new store path and
`flox edit -f` the manifest.

## Tests

```bash
bash test/red-team.sh                          # against the built artifact
bash test/red-team.sh ./src/bubblewrap-jail    # against source (seccomp skipped)
```

157 assertions covering filesystem isolation, network policy, privilege
escape, environment allowlist, project-dir precedence, bind API contract,
`--passthrough-env` and reserved-name rejection, `--project-as` validation,
TIOCSTI seccomp blocking, interactive controlling-tty behavior, `--help`
resilience under empty `PATH`, and the `check` subcommand.

The harness uses `set -u` (not `-e`): each assertion runs and contributes to
a pass/fail count, then the suite exits 0 if all green or 1 otherwise.
