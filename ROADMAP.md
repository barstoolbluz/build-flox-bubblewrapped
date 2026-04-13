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

## Execution status

All roadmap items shipped between v0.2.5 and v0.3.2. **Done.**

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

Final state: red-team **110 / 0**, check **29 / 0**, runtime closure 35 paths.
