# bubblewrap-jail roadmap

Layered tracking of reviewer feedback and follow-on work.  Four
sections:

1. **Must-have before broader internal use** — original reviewer
   blockers (C*, S*, O*, V1).  Written at v0.2.4; closed out by v0.2.7.
2. **Strongly recommended** — original reviewer hardening items
   (B*, E*, F*).  Closed out by v0.3.2.
3. **Reviewer non-blockers (closed in v0.4.x)** — R1/R2/R3 plus the
   A1 audit-loop fix.
4. **Nice-to-have** — post-roadmap proposals (L*, D*, U*).  L1/L2
   are historical aliases for V1; D1 and U1 are open.

Each narrative entry below carries an inline status tag and, where
applicable, a "Landed in vX.Y.Z" pointer to the release that closed
the gap.  The authoritative cumulative state lives in the **execution
status tables** at the bottom of this file — when in doubt, trust
the tables.

Status legend:
- `[DONE]` — shipped and verified
- `[PARTIAL]` — base case shipped; specific gaps remain (noted inline)
- `[TODO]` — not started

---

## Must-have before broader internal use

### 1. Correctness and compatibility

- **C1. `[DONE]` Verify every Bubblewrap flag actually used in `check`, not
  just a subset.**
  Shipped in v0.2.3 (added 9 missing probes; total now 22) and v0.2.4
  (word-boundary grep so `--bind` doesn't false-match `--bind-try`). Probe
  list lives at `src/bubblewrap-jail:154-180`. Invariant comment pins the
  rule: "this list MUST stay in sync with the flags the wrapper actually
  passes at runtime".

- **C2. `[DONE]` Fail with a clear message if the seccomp blob is
  requested but missing, unreadable, or rejected by the running bwrap.**
  Missing/unreadable cases: handled at `src/bubblewrap-jail:566-585`
  ("seccomp BPF not readable: $BPF_PATH (package broken?)"). Rejected-by-
  bwrap case: originally propagated bwrap's own error after `exec`. **Gap
  (closed):** a pre-flight validation (`bwrap … --seccomp 11 … true`)
  runs before the real exec so we can wrap the failure in a clear
  context message. **Landed in v0.2.5**; see the seccomp block in
  `src/bubblewrap-jail` (around the pre-flight probe) for the
  current implementation. Also captures bwrap's stderr in the die
  message (A1 refinement in v0.3.4).

- **C3. `[DONE]` Add `--die-with-parent`, at least in agent mode.**
  Shipped in v0.1.0. It's in the base args block at
  `src/bubblewrap-jail:413`, so both `run` and `agent` get it.

### 2. Security contract

- **S1. `[DONE]` Keep docs explicit that this is an interactive isolation
  wrapper, not a general hostile-code sandbox.**
  Stated in `src/bubblewrap-jail:10-15` (threat model header) and reinforced
  in `src/gen-seccomp.c:10-16` (Scope section added in v0.2.3). Also called
  out in `README.md` "Threat model" section.

- **S2. `[DONE]` Keep the TIOCSTI mitigation in agent mode.**
  Shipped in v0.2.0. The filter is loaded by default in both `run` and
  `agent` (subject to `--no-seccomp` opt-out which prints a warning).
  Generator: `src/gen-seccomp.c`. Wrapper load site:
  `src/bubblewrap-jail:566-585`.

- **S3. `[DONE]` Fix the stale TIOCSTI sysctl comment.**
  Fixed in v0.2.3 (F1). Now correctly references `dev.tty.legacy_tiocsti`
  (not `legacy_tiocsti_restrict`) and Linux 6.2 (when the CAP_SYS_ADMIN
  enforcement landed). See `src/bubblewrap-jail:498-510`.

### 3. Operational behavior

- **O1. `[DONE]` Decide and test parent death / child death / signal
  forwarding.**
  Parent death: `--die-with-parent` already present; static guard
  test added. Child death: bwrap exits when child exits — covered
  by every existing test implicitly. Signal forwarding: SIGTERM
  via `timeout(1)` tested end-to-end for both `run` and `agent`
  modes. Exit-code propagation: explicit tests including a specific
  code-42 check. Decisions documented in the script header's
  "Lifecycle and signals" section. **Landed in v0.2.6.**

- **O2. `[DONE]` Regression tests for the listed cases.**
  All 8 sub-items now covered:
  - `[DONE]` run vs agent
  - `[DONE]` `--net` vs default no-net
  - `[DONE]` `--bind` / `--ro-bind`
  - `[DONE]` `--project-as`
  - `[DONE]` tty interactive mode (T5 in v0.2.1)
  - `[DONE]` missing `/nix` — static guard that the wrapper uses
    `--ro-bind-try /nix` (not `--ro-bind`), so a host without /nix
    is handled gracefully. **Landed in v0.2.7.**
  - `[DONE]` missing seccomp artifact — overlaps with C2; corrupt-
    BPF end-to-end test using a zero-byte BPF and a copy of the
    wrapper with its `BPF_PATH` sed-rewritten. **Landed in v0.2.5.**
  - `[DONE]` exit-code propagation — `run`/`agent` tests for true/
    false, specific exit code 42 through the wrapper. **Landed in
    v0.2.6.**

### 4. Observability

- **V1. `[DONE]` Machine-readable mode using bubblewrap's external
  monitoring options (`--lock-file`, `--sync-fd`).**
  Shipped as pass-throughs with integer validation. `--lock-file`
  auto-binds the path into the jail so bwrap can open it after
  namespace setup; `--sync-fd` gives pipe-EOF lifecycle tracking.
  Both reject fd 10 and 11 (reserved by the wrapper for the seccomp
  BPF) via arithmetic comparison that handles leading-zero variants
  (A1 in v0.4.3). **Landed in v0.2.7.** `--info-fd` added as a
  machine-readable sibling in v0.4.0 (R2 below).

---

## Strongly recommended

### 5. Build and reviewability

- **B1. `[DONE]` Keep `gen-seccomp.c`.**
  Reviewer approved keeping it in v0.2.3 audit; it's narrow, readable, and
  audit-friendly. Header comment cleaned up in v0.2.3.

- **B2. `[DONE]` Emit a human-readable representation of the BPF filter
  during build or test runs.**
  `gen-seccomp` accepts a `--pfc` flag that uses libseccomp's
  `seccomp_export_pfc()` to emit the pseudo-filter-code textual
  form.  Build runs both `./gen-seccomp > tiocsti.bpf` and
  `./gen-seccomp --pfc > tiocsti.pfc` and installs both alongside
  each other in `$out/share/bubblewrap-jail/`. **Landed in v0.3.2.**

### 6. Environment policy

- **E1. `[DONE]` Clean allowlist surface for environment passthrough.**
  `--passthrough-env VAR` is repeatable (each occurrence adds a var
  to the allowlist); `BUBBLEWRAP_JAIL_PASSTHROUGH_ENV` accepts a
  comma-separated CSV list; reserved-name rejection (PATH, HOME,
  TMPDIR, TERM, LANG, PWD) is applied per entry. Empty entries
  from leading/trailing/double commas are silently tolerated.
  **Landed in v0.3.0.**

- **E2. `[DONE]` Keep `--clearenv` as the base; every inherited variable
  deliberate.**
  Already true. `src/bubblewrap-jail:444-450` does `--clearenv` then
  explicit `--setenv` for each allowed variable. No implicit inheritance.

- **E3. `[DONE]` Document which variables are always injected in `run`
  and `agent`.**
  Help text now has a dedicated "Environment in jail:" section
  enumerating exactly what each mode sets after `--clearenv`, plus
  the passthrough var(s) and user-supplied `--setenv` flags.
  **Landed in v0.3.0.**

### 7. Filesystem policy

- **F1. `[DONE]` Add an explicit read-only mode for the project tree.**
  `--project-ro` switches the project bind from `--bind` to
  `--ro-bind`. Useful for read-only review/inspection workflows
  where the agent should not be able to mutate the source.
  Works alongside `--project-as` (tested). **Landed in v0.3.1.**

- **F2. `[DONE]` Reject overlaps with reserved mountpoints in user
  `--bind` / `--ro-bind` unless explicitly forced.**
  User-supplied `--bind` / `--ro-bind` destinations are rejected
  when they match FHS-essential paths (`/`, `/bin`, `/sbin`, `/usr`,
  `/lib`, `/lib64`, `/etc`, `/proc`, `/dev`, `/nix`). `--bind-force`
  opts out for advanced users who genuinely need to shadow an
  essential. Sub-paths are still allowed, so T4's `user --bind into
  /etc/foo` continues to work. **Landed in v0.3.1.**

- **F3. `[DONE]` Document mount ordering — bwrap applies operations in
  argv order.**
  `--help` now has a dedicated "Mount ordering" section enumerating
  the 10-step argv order bwrap sees: skeleton → /etc tmpfs+allowlist
  → scratch tmpfs → network → env → mode binds → user extras →
  lifecycle (--lock-file/--sync-fd/--info-fd) → --remount-ro /etc
  seal → --seccomp. Steps 8 and 9 were initially mis-ordered in the
  help text and corrected in v0.3.3 (A8). **Landed in v0.3.1**
  (v0.3.3 docs fix).

---

## Reviewer non-blockers (closed in v0.4.x)

After the original 17-item roadmap closed at v0.3.2, the reviewer
flagged three additional items explicitly as **non-blockers** — not
shipping blockers, but worth addressing.  All three landed in v0.4.x.

### R1. `[DONE]` Split `check` probes into required vs optional

Reviewer concern: `check` was treating `--lock-file` and `--sync-fd`
as hard requirements even though they're runtime-optional wrapper
features.  A host with older bwrap could be reported as red even
though the core `run` / `agent` modes would still work fine.

Shipped in v0.4.0.  `check` now distinguishes:
- **22 required** bwrap flags — missing any is a hard FAIL
- **3 optional** flags (`--lock-file`, `--sync-fd`, `--info-fd`)
  reported on `OPT` lines that don't affect the exit code

Summary line extended: `=== result: 29 passed, 0 failed; optional:
3 supported / 0 missing ===`.

### R2. `[DONE]` Expose `--info-fd`

Reviewer suggested bwrap's `--info-fd FD` — a JSON metadata blob
written to an inherited fd after setup, containing the child's
host-side PID and namespace info.  Useful for orchestrators that
want structured sandbox state without parsing stderr.

Shipped in v0.4.0 as a pass-through with integer validation and
reserved-fd rejection (see A1 below).  End-to-end tested with both
jq and grep fallback paths.

### R3. `[DONE]` CI exercising the full matrix

Reviewer asked for CI running against: `run`, `agent`, `--project-ro`,
`--project-as`, `--lock-file`, `--sync-fd`, seccomp on/off,
parent-death behavior, and more.

Shipped in v0.4.1.  GitHub Actions workflow at `.github/workflows/ci.yml`:
- Runner: `ubuntu-24.04` (single runner)
- Defensive AppArmor unprivileged-userns sysctl relax
  (Nix-built bwrap has no AppArmor profile, so the Ubuntu 24.04
  default restriction blocks unprivileged userns without this step)
- `flox/install-flox-action@v2`
- `flox build bubblewrap-jail`
- `check` subcommand (asserts exit 0)
- Full `red-team.sh` suite via `flox activate --`

First run: **green**.  CI badge on `README.md`.

---

## Nice-to-have

Post-roadmap items proposed during ongoing use.  Not blocking,
not strongly-recommended — just things worth doing when time
permits.

### 8. Lifecycle and orchestration

- **L1. `[DONE in v0.2.7]` Add `--lock-file` support for supervisors.**
  Shipped as part of V1 above (the reviewer's original observability
  item).  Pass-through to bwrap's `--lock-file PATH`, with automatic
  bind-mount of the lock path into the jail so bwrap can open it
  from inside the namespace.  See the V1 entry and the V1 test block
  in `test/red-team.sh` for details.

- **L2. `[DONE in v0.2.7]` Add `--sync-fd` support if another process
  needs a reliable "sandbox is alive" signal.**
  Shipped as part of V1.  Pipe-EOF semantics: parent reads from a
  pipe, wrapper inherits the write end via `--sync-fd`, pipe closes
  when the sandbox exits.  `--info-fd` (added in v0.4.0 as R2 above)
  is the machine-readable sibling — same fd-inheritance pattern,
  JSON output.

### 9. Durability

- **D1. `[TODO]` Opt-in flush step for rw modes.**
  Users who care about writes surviving abrupt exits can currently
  lose data if the sandbox is killed mid-write.  Add an opt-in flag
  (e.g. `--sync-on-exit`) that runs `syncfs(2)` on the project
  filesystem (or agent-home filesystem) before exit, to flush
  pending writes without a global `sync(1)`.  Linux's `syncfs()`
  syscall gives targeted per-filesystem synchronization rather
  than the system-wide flush that `sync` does.

  Design notes:
  - Default should be OFF — syncing costs, most workloads don't
    need it, and we don't want to surprise existing users.
  - No shell builtin for `syncfs`; options for the implementation:
    - Small C helper compiled at build time (symmetric with
      `gen-seccomp.c`); call via a trap/handler in the wrapper.
    - `python3 -c 'import ctypes; ...'` — adds a Python runtime
      dep, probably not worth it.
    - Spawn a one-shot helper from inside the sandbox just before
      exit, via bwrap's existing file-descriptor passing.
  - Must execute INSIDE the jail (so it sees the project filesystem
    via the bind) but BEFORE the jail exits — tricky to sequence
    without racing the exec boundary.

### 10. UX

- **FX1. `[DONE]` Flox environment sandboxing subcommand.**
  New `bubblewrap-jail flox-env` subcommand that runs arbitrary Flox
  environments (local `-d DIR` or remote catalog `-r OWNER/NAME`) inside
  a hardened bwrap sandbox.  Inherits all existing hardening (TIOCSTI
  seccomp, `--disable-userns`, `--die-with-parent`, `/etc` seal), adds
  closure-scoped `/nix/store` visibility via `--tmpfs /nix/store` overlay
  + per-path `--ro-bind` (immutable, default), or `--mutable` for full
  `/nix/store` rw + `/nix/var` rw so `flox install` can mutate the env
  via the nix daemon.  Synthesizes `/bin`, `/usr/bin/flox` via tmpfs +
  symlink pattern.  Optional `--x11`, `--gpu`, `--dev-shm`, `--dry-run`
  flags.  Runtime deps `nix-store` + `flox` reported as OPT probes by
  `check`.  Inspired by devusb/flox-bwrap; see ACKNOWLEDGMENTS.md.
  **Landed in v0.6.0.** Tests: 16 new red-team assertions.
  **Known limitation:** source-build installs in mutable mode fail
  (nix-build uses its own userns sandbox which can't nest under
  `--disable-userns`); cache-hit installs work fine.

- **U1. `[PARTIAL]` A `doctor` / `check --verbose` mode.**
  The existing `check` subcommand already prints every item on the
  reviewer's list:

  - `[DONE]` detected bwrap version →
    `PASS  bwrap version: X.Y.Z`
  - `[DONE]` required flags present/missing →
    22 PASS lines + 3 OPT lines (after v0.4.0's split)
  - `[DONE]` seccomp artifact status →
    `PASS  seccomp BPF readable (N bytes at ...)`
    `PASS  seccomp BPF loads into bwrap`
  - `[DONE]` /nix availability →
    `PASS  /nix/store present`
  - `[DONE]` whether user namespaces appear usable →
    `PASS  kernel user namespaces enabled (max_user_namespaces=N)`
    `PASS  minimal bwrap launch works`

  **Gaps:**
  - No explicit `--verbose` flag (though the default output already
    prints every probe result).
  - No machine-readable format (`--json` would help orchestrators).
  - No `doctor` alias for discoverability.  `check` is the reviewer's
    preferred name, but some users may look for `doctor` by analogy
    with `brew doctor`, `rustup doctor`, etc.  An alias would be
    one line in the subcommand dispatcher.

---

## Execution status — original roadmap (v0.2.5 → v0.3.2)

All 17 items from the reviewer's original must-have and strongly-
recommended sections shipped between v0.2.5 and v0.3.2.  **Done.**

| # | Item | Status | Lands in |
|---|------|--------|----------|
| C1 | Full bwrap flag probe in `check` | DONE | v0.2.3, v0.2.4 |
| C2 | Clear seccomp failure modes | DONE | v0.2.5 (rejected-case pre-flight) |
| C3 | `--die-with-parent` | DONE | v0.1.0 |
| S1 | Scope docs | DONE | v0.2.3 |
| S2 | TIOCSTI seccomp in agent | DONE | v0.2.0 |
| S3 | Stale sysctl comment | DONE | v0.2.3 |
| O1 | Lifecycle / signal handling | DONE | v0.2.6 |
| O2 | Missing-/nix, missing-BPF, exit-code tests | DONE | v0.2.5, v0.2.6, v0.2.7 |
| V1 | `--lock-file` / `--sync-fd` | DONE | v0.2.7 |
| B1 | Keep `gen-seccomp.c` | DONE | v0.2.0 |
| B2 | Human-readable BPF (PFC) | DONE | v0.3.2 |
| E1 | Multi-var passthrough allowlist | DONE | v0.3.0 |
| E2 | `--clearenv` base | DONE | v0.1.0 |
| E3 | Document injected env table | DONE | v0.3.0 |
| F1 | `--project-ro` mode | DONE | v0.3.1 |
| F2 | Reserved-mountpoint guard on user binds | DONE | v0.3.1 |
| F3 | Mount ordering docs | DONE | v0.3.1 |

## Execution status — reviewer non-blockers (v0.4.x)

| # | Item | Status | Lands in |
|---|------|--------|----------|
| R1 | Optional-probe split in `check` | DONE | v0.4.0 |
| R2 | `--info-fd` pass-through | DONE | v0.4.0 |
| R3 | GitHub Actions CI workflow | DONE | v0.4.1 |
| A1 | Reject fd 10/11 for `--sync-fd`/`--info-fd` (audit loop) | DONE | v0.4.2 → v0.4.3 |

## Execution status — nice-to-have

| # | Item | Status | Lands in |
|---|------|--------|----------|
| L1  | `--lock-file` for supervisors | DONE (same as V1) | v0.2.7 |
| L2  | `--sync-fd` for liveness signal | DONE (same as V1) | v0.2.7 |
| D1  | Opt-in `syncfs()` flush for rw modes | TODO | — |
| U1  | `doctor` / `check --verbose` mode | PARTIAL | existing `check` covers content; no `--verbose`/`--json`/`doctor` alias (json+doctor closed in v0.4.6) |
| FX1 | `flox-env` subcommand (immutable + mutable) | DONE | v0.6.0 |

Final state as of v0.6.0:
- red-team **157 / 0** against built artifact (140 legacy + 16 flox-env + 1 reshuffle)
- red-team source mode **129 / 5** (5 expected seccomp-gated failures when BPF_PATH is unsubstituted)
- check **29 / 0 required, 6 optional supported / 0 missing** (3 bwrap flag opts + 3 flox-env runtime-dep opts)
- run/agent runtime closure **6 paths** (shebang-patched bash + glibc + libs)
- BPF blob **104 bytes**
- shellcheck clean
- CI green on ubuntu-24.04
