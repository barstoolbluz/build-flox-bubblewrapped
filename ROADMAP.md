# bubblewrap-jail roadmap

Reviewer feedback for what's needed before broader internal use, plus
strongly-recommended hardening. Status reflects v0.2.4.

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

- **C2. `[PARTIAL]` Fail with a clear message if the seccomp blob is
  requested but missing, unreadable, or rejected by the running bwrap.**
  Missing/unreadable cases: handled at `src/bubblewrap-jail:566-585`
  ("seccomp BPF not readable: $BPF_PATH (package broken?)"). Rejected-by-
  bwrap case: currently propagates bwrap's own error after `exec`. **Gap:**
  add a pre-flight validation (small `bwrap … --seccomp 11 … true`) before
  the real exec so we can wrap the failure in a clear context message
  instead of a bare bwrap stderr line.

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

- **O1. `[TODO]` Decide and test parent death / child death / signal
  forwarding.**
  Parent death: `--die-with-parent` already present, but no test
  asserts it. Child death: bwrap's default behavior is "exit when
  child exits" — also untested. Signal forwarding: bwrap forwards
  signals to the child; we should verify SIGTERM/SIGINT propagation
  and exit-code preservation. Need explicit decisions documented in
  the script header, then end-to-end tests.

- **O2. `[PARTIAL]` Regression tests for the listed cases.**
  Already covered:
  - `[DONE]` run vs agent
  - `[DONE]` `--net` vs default no-net
  - `[DONE]` `--bind` / `--ro-bind`
  - `[DONE]` `--project-as`
  - `[DONE]` tty interactive mode (T5 in v0.2.1)

  **Gaps:**
  - `[TODO]` missing `/nix` (probe whether the wrapper degrades gracefully
    or fails clearly)
  - `[TODO]` missing seccomp artifact (corrupt BPF / unreadable / rejected;
    overlaps with C2)
  - `[TODO]` exit-code propagation (`bubblewrap-jail run -- false` should
    exit non-zero; specific codes should pass through)

### 4. Observability

- **V1. `[TODO]` Machine-readable mode using bubblewrap's external
  monitoring options (`--lock-file`, `--sync-fd`).**
  Not currently exposed by the wrapper. `--lock-file PATH` lets a parent
  wait for the sandbox to fully start; `--sync-fd FD` is a stable primitive
  for lifecycle tracking and CI integration. Add pass-through flags and
  document the invariant they provide.

---

## Strongly recommended

### 5. Build and reviewability

- **B1. `[DONE]` Keep `gen-seccomp.c`.**
  Reviewer approved keeping it in v0.2.3 audit; it's narrow, readable, and
  audit-friendly. Header comment cleaned up in v0.2.3.

- **B2. `[TODO]` Emit a human-readable representation of the BPF filter
  during build or test runs.**
  `seccomp_export_bpf()` already produces the kernel-consumable blob.
  libseccomp also exposes `seccomp_export_pfc()` ("pseudo filter code") for
  human review. Add a `gen-seccomp --pfc` mode (or a separate emit) that
  the build invokes once and saves alongside `tiocsti.bpf` for audit.

### 6. Environment policy

- **E1. `[TODO]` Clean allowlist surface for environment passthrough.**
  Currently `--passthrough-env VAR` accepts a single var name; multi-var
  passthrough requires multiple flags. Decide whether to support repeat
  (`--passthrough-env A --passthrough-env B`), comma-list
  (`--passthrough-env A,B,C`), or both. Requires updating reserved-name
  rejection to scan each entry.

- **E2. `[DONE]` Keep `--clearenv` as the base; every inherited variable
  deliberate.**
  Already true. `src/bubblewrap-jail:444-450` does `--clearenv` then
  explicit `--setenv` for each allowed variable. No implicit inheritance.

- **E3. `[PARTIAL]` Document which variables are always injected in `run`
  and `agent`.**
  Help text mentions some inline but isn't a single table. Add a clear
  "Environment in jail:" section to `--help` enumerating exactly what each
  mode sets, and what it inherits when set on the host.

### 7. Filesystem policy

- **F1. `[TODO]` Add an explicit read-only mode for the project tree.**
  Currently agent mode always rw-binds the project. Add a flag
  (`--project-ro` or similar) that uses `--ro-bind` instead of `--bind`.
  Useful for read-only review/inspection workflows where the agent should
  not be able to mutate the source.

- **F2. `[TODO]` Reject overlaps with reserved mountpoints in user
  `--bind` / `--ro-bind` unless explicitly forced.**
  `--project-as` already rejects FHS-essential prefixes (B4 in v0.2.1).
  Apply the same defensive guard to the user-supplied `--bind` / `--ro-bind`
  destination paths, with an opt-out flag (e.g. `--bind-force`) for users
  who know what they're doing.

- **F3. `[PARTIAL]` Document mount ordering — bwrap applies operations in
  argv order.**
  Already noted partially in `src/bubblewrap-jail:104-106` and the B1 fix
  comment at `src/bubblewrap-jail:547-552`. Could be a single dedicated
  section in `--help` or the script header explaining: (1) base layout
  applied first, (2) network-conditional binds, (3) env block, (4) mode-
  specific binds, (5) user `--bind` / `--ro-bind` / `--setenv` last,
  (6) `--remount-ro /etc` seal.

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
reserved-fd rejection (see F1 below).  End-to-end tested with both
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
| F1 | Reject fd 10/11 for `--sync-fd`/`--info-fd` (audit loop) | DONE | v0.4.2 → v0.4.3 |

## Execution status — nice-to-have

| # | Item | Status | Lands in |
|---|------|--------|----------|
| L1 | `--lock-file` for supervisors | DONE (same as V1) | v0.2.7 |
| L2 | `--sync-fd` for liveness signal | DONE (same as V1) | v0.2.7 |
| D1 | Opt-in `syncfs()` flush for rw modes | TODO | — |
| U1 | `doctor` / `check --verbose` mode | PARTIAL | existing `check` covers content; no `--verbose`/`--json`/`doctor` alias |

Final state as of v0.4.3:
- red-team **129 / 0** (stable across 10 consecutive runs)
- check **29 / 0 required, 3 optional supported / 0 missing**
- runtime closure **35 paths**
- BPF blob **104 bytes**
- shellcheck clean
- CI green on ubuntu-24.04
