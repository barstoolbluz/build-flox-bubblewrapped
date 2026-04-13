#!/usr/bin/env bash
#
# red-team.sh — assert bubblewrap-jail enforces its documented properties.
#
# Usage:
#   test/red-team.sh [PATH_TO_BUBBLEWRAP_JAIL]
#
# If no path is given, defaults to ./result-bubblewrap-jail/bin/bubblewrap-jail
# (the symlink produced by `flox build`).  Run this from the build env's
# working directory.
#
# Exit code:
#   0  — every test passed
#   1  — at least one test failed (details printed)

set -u  # intentionally NOT -e; we want to run every test and aggregate

JAIL="${1:-./result-bubblewrap-jail/bin/bubblewrap-jail}"
[ -x "$JAIL" ] || { echo "not executable: $JAIL" >&2; exit 2; }
# Canonicalize to an absolute path so tests that cd elsewhere still find it.
JAIL=$(readlink -f -- "$JAIL")

pass=0
fail=0
failed_tests=()

# Usage: expect_fail "name" "what-should-not-work" -- CMD...
#   CMD must exit non-zero for this to pass.
expect_fail() {
  local name=$1; shift
  [ "$1" = "--" ] && shift
  if "$@" >/dev/null 2>&1; then
    printf '  FAIL: %s\n' "$name"
    fail=$((fail+1)); failed_tests+=("$name")
  else
    printf '  ok:   %s\n' "$name"
    pass=$((pass+1))
  fi
}

# Usage: expect_pass "name" -- CMD...
#   CMD must exit zero for this to pass.
expect_pass() {
  local name=$1; shift
  [ "$1" = "--" ] && shift
  if "$@" >/dev/null 2>&1; then
    printf '  ok:   %s\n' "$name"
    pass=$((pass+1))
  else
    printf '  FAIL: %s\n' "$name"
    fail=$((fail+1)); failed_tests+=("$name")
  fi
}

# Usage: expect_stdout_matches "name" "regex" -- CMD...
#   CMD's stdout must match regex (via grep -E).
expect_stdout_matches() {
  local name=$1 regex=$2; shift 2
  [ "$1" = "--" ] && shift
  local out
  out=$("$@" 2>/dev/null || true)
  if printf '%s' "$out" | grep -Eq -- "$regex"; then
    printf '  ok:   %s\n' "$name"
    pass=$((pass+1))
  else
    printf '  FAIL: %s (out=%q)\n' "$name" "$out"
    fail=$((fail+1)); failed_tests+=("$name")
  fi
}

# Usage: expect_stderr_matches "name" "regex" -- CMD...
#   CMD's stderr must match regex (via grep -E).  For tests that need to
#   verify a specific error message (e.g. C2: clear seccomp failure mode).
expect_stderr_matches() {
  local name=$1 regex=$2; shift 2
  [ "$1" = "--" ] && shift
  local out
  out=$("$@" 2>&1 >/dev/null || true)
  if printf '%s' "$out" | grep -Eq -- "$regex"; then
    printf '  ok:   %s\n' "$name"
    pass=$((pass+1))
  else
    printf '  FAIL: %s (err=%q)\n' "$name" "$out"
    fail=$((fail+1)); failed_tests+=("$name")
  fi
}

# Prepare scratch cache so agent mode works without a flox activation.
SMOKE_CACHE=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf '$SMOKE_CACHE'" EXIT
export FLOX_ENV_CACHE="$SMOKE_CACHE"
export FLOX_ENV_PROJECT="$PWD"

# Canary secrets on the host, to prove they don't leak into the jail.
export AWS_ACCESS_KEY_ID="canary-aws-key-MUST-NOT-LEAK"
export GITHUB_TOKEN="canary-github-token-MUST-NOT-LEAK"
export ANTHROPIC_API_KEY="sk-canary-anthropic-value"

echo "=== bubblewrap-jail red-team test suite ==="
echo "target: $JAIL"
echo

echo "[run mode / filesystem]"
expect_fail "run: /etc/shadow invisible"        -- "$JAIL" run -- cat /etc/shadow
expect_fail "run: /etc/ssh invisible"           -- "$JAIL" run -- ls /etc/ssh
expect_fail "run: /etc/sudoers invisible"       -- "$JAIL" run -- cat /etc/sudoers
expect_fail "run: /home does not exist"         -- "$JAIL" run -- ls /home
expect_fail "run: /root does not exist"         -- "$JAIL" run -- ls /root
expect_fail "run: /mnt does not exist"          -- "$JAIL" run -- ls /mnt
expect_pass "run: /etc/passwd readable"         -- "$JAIL" run -- test -r /etc/passwd
expect_pass "run: /usr readable"                -- "$JAIL" run -- test -r /usr/bin
expect_fail "run: /usr not writable"            -- "$JAIL" run -- touch /usr/flag
expect_fail "run: /etc not writable"            -- "$JAIL" run -- touch /etc/flag
expect_pass "run: /tmp writable"                -- "$JAIL" run -- touch /tmp/run-flag

echo
echo "[run mode / network]"
expect_fail "run: default DNS fails"            -- "$JAIL" run -- timeout 3 getent ahosts example.com
expect_pass "run: --net DNS works"              -- "$JAIL" run --net -- timeout 5 getent ahosts example.com

echo
echo "[run mode / privilege escape]"
expect_fail "run: nested unshare -Ur blocked"   -- "$JAIL" run -- unshare -Ur id
expect_fail "run: nested bwrap blocked"         -- "$JAIL" run -- bwrap --ro-bind / / -- true

echo
echo "[run mode / environment]"
expect_fail "run: canary AWS key not leaked"    -- "$JAIL" run -- sh -c 'printenv AWS_ACCESS_KEY_ID'
expect_fail "run: canary GH token not leaked"   -- "$JAIL" run -- sh -c 'printenv GITHUB_TOKEN'
expect_fail "run: ANTHROPIC_API_KEY not leaked" -- "$JAIL" run -- sh -c 'printenv ANTHROPIC_API_KEY'

echo
echo "[agent mode / filesystem]"
expect_fail "agent: /etc/shadow invisible"      -- "$JAIL" agent -- cat /etc/shadow
expect_fail "agent: /etc/ssh invisible"         -- "$JAIL" agent -- ls /etc/ssh
expect_fail "agent: ~/.ssh (host) invisible"    -- "$JAIL" agent -- ls "$HOME/.ssh"
expect_fail "agent: ~/.aws invisible"           -- "$JAIL" agent -- ls "$HOME/.aws"
expect_pass "agent: project dir readable"       -- "$JAIL" agent -- ls "$FLOX_ENV_PROJECT"
expect_pass "agent: project dir writable"       -- "$JAIL" agent -- touch "$FLOX_ENV_PROJECT/.redteam-write"
rm -f "$FLOX_ENV_PROJECT/.redteam-write"
expect_pass "agent: HOME writable"              -- \
  "$JAIL" agent -- sh -c 'touch "$HOME/.homewrite-test" && rm "$HOME/.homewrite-test"'
expect_pass "agent: /tmp writable"              -- "$JAIL" agent -- touch /tmp/agent-scratch
expect_fail "agent: /usr not writable"          -- "$JAIL" agent -- touch /usr/flag
expect_fail "agent: /etc not writable"          -- "$JAIL" agent -- touch /etc/flag

echo
echo "[agent mode / network]"
expect_pass "agent: default DNS works"          -- "$JAIL" agent -- timeout 5 getent ahosts example.com
expect_fail "agent: --no-net DNS blocked"       -- "$JAIL" agent --no-net -- timeout 3 getent ahosts example.com

echo
echo "[agent mode / privilege escape]"
expect_fail "agent: nested unshare -Ur blocked" -- "$JAIL" agent -- unshare -Ur id
expect_fail "agent: nested bwrap blocked"       -- "$JAIL" agent -- bwrap --ro-bind / / -- true

echo
echo "[agent mode / environment allowlist]"
expect_stdout_matches "agent: ANTHROPIC_API_KEY passthrough" "^sk-canary-anthropic-value\$" -- \
  "$JAIL" agent -- sh -c 'printenv ANTHROPIC_API_KEY'
expect_fail "agent: AWS key not leaked"         -- "$JAIL" agent -- sh -c 'printenv AWS_ACCESS_KEY_ID'
expect_fail "agent: GH token not leaked"        -- "$JAIL" agent -- sh -c 'printenv GITHUB_TOKEN'
expect_stdout_matches "agent: HOME = agent-home" "agent-home\$" -- \
  "$JAIL" agent -- sh -c 'printenv HOME'
# (Old "agent: PWD = project" test was a tautology — it set FLOX_ENV_PROJECT=$PWD
# at harness top, then asserted the jail pwd matched FLOX_ENV_PROJECT.  The
# precedence section below has stronger tests that prove the same thing.)

echo
echo "[agent mode / project dir precedence]"
# Regression tests for the FLOX_ENV_PROJECT-wins-over-PWD bug.
# Create three scratch project dirs under the smoke cache (auto-cleaned).
DIR_A="$SMOKE_CACHE/project-a"
DIR_B="$SMOKE_CACHE/project-b"
DIR_C="$SMOKE_CACHE/project-c"
mkdir -p "$DIR_A" "$DIR_B" "$DIR_C"

# T1: the bug itself.  FLOX_ENV_PROJECT set to DIR_A, shell cwd is DIR_B.
# Expected: jail's pwd is DIR_B.  Old precedence picks DIR_A and fails.
expect_stdout_matches \
  "agent precedence: PWD wins over FLOX_ENV_PROJECT" \
  "^${DIR_B}\$" -- \
  env FLOX_ENV_PROJECT="$DIR_A" bash -c "cd \"\$1\" && \"\$2\" agent -- pwd" _ "$DIR_B" "$JAIL"

# T2: BUBBLEWRAP_JAIL_PROJECT wins over $PWD.
# cwd=DIR_B, env var=DIR_C, expect DIR_C.
expect_stdout_matches \
  "agent precedence: BUBBLEWRAP_JAIL_PROJECT overrides PWD" \
  "^${DIR_C}\$" -- \
  env BUBBLEWRAP_JAIL_PROJECT="$DIR_C" bash -c "cd \"\$1\" && \"\$2\" agent -- pwd" _ "$DIR_B" "$JAIL"

# T3: --project flag wins over everything.
# FLOX_ENV_PROJECT=DIR_A, BUBBLEWRAP_JAIL_PROJECT=DIR_A, cwd=DIR_B, flag=DIR_C.
expect_stdout_matches \
  "agent precedence: --project flag overrides env" \
  "^${DIR_C}\$" -- \
  env FLOX_ENV_PROJECT="$DIR_A" BUBBLEWRAP_JAIL_PROJECT="$DIR_A" \
    bash -c "cd \"\$1\" && \"\$2\" agent --project \"\$3\" -- pwd" _ "$DIR_B" "$JAIL" "$DIR_C"

echo
echo "[bind API contract: SRC DST order matches bwrap(1)]"
# Asymmetric bind: host source file at DIR_A/source.txt, jail target at /tmp/bindtarget.
# If the argument order is wrong (old bug), the mount fails or is inverted.
echo "bind-src-content" > "$DIR_A/source.txt"
expect_stdout_matches \
  "run: --bind SRC DST forwards in bwrap order" \
  "^bind-src-content\$" -- \
  "$JAIL" run --bind "$DIR_A/source.txt" /tmp/bindtarget -- cat /tmp/bindtarget

expect_stdout_matches \
  "run: --ro-bind SRC DST forwards in bwrap order" \
  "^bind-src-content\$" -- \
  "$JAIL" run --ro-bind "$DIR_A/source.txt" /tmp/robindtarget -- cat /tmp/robindtarget

# Verify ro-bind is actually read-only: write should fail.
expect_fail \
  "run: --ro-bind target is not writable" -- \
  "$JAIL" run --ro-bind "$DIR_A/source.txt" /tmp/robindtarget -- \
    sh -c 'echo clobber > /tmp/robindtarget'

# T4: regression for B1 — user --bind into /etc must work.  Before the fix,
# --remount-ro /etc ran before user extras, so bwrap couldn't create the user
# mount point on a read-only /etc and failed with EROFS.
echo "injected-content" > "$DIR_A/etc-source.txt"
expect_stdout_matches \
  "run: user --bind into /etc works (after /etc seal)" \
  "^injected-content\$" -- \
  "$JAIL" run --bind "$DIR_A/etc-source.txt" /etc/user-injected -- cat /etc/user-injected

# T6: user --setenv survives --clearenv and reaches the jail.
expect_stdout_matches \
  "run: user --setenv appears inside jail" \
  "^canary-setenv-value\$" -- \
  "$JAIL" run --setenv FOO canary-setenv-value -- sh -c 'printenv FOO'

# T7: user --hostname overrides the default.
expect_stdout_matches \
  "run: user --hostname overrides default" \
  "^redteamhost\$" -- \
  "$JAIL" run --hostname redteamhost -- hostname

# B3 regression: reserved env-var names are rejected by --passthrough-env.
expect_fail \
  "agent: --passthrough-env rejects reserved name HOME" -- \
  "$JAIL" agent --passthrough-env HOME -- true
expect_fail \
  "agent: --passthrough-env rejects reserved name PATH" -- \
  "$JAIL" agent --passthrough-env PATH -- true

# B3 regression: --passthrough-env actually passes through a non-reserved name.
expect_stdout_matches \
  "agent: --passthrough-env passes a non-reserved var" \
  "^canary-passthrough\$" -- \
  env MY_TOKEN=canary-passthrough \
    "$JAIL" agent --passthrough-env MY_TOKEN -- sh -c 'printenv MY_TOKEN'

# E1: --passthrough-env is repeatable; multiple flags allowlist multiple vars.
expect_stdout_matches \
  "agent: --passthrough-env repeatable (var A reaches jail)" \
  "^val-A\$" -- \
  env CANARY_A=val-A CANARY_B=val-B \
    "$JAIL" agent --passthrough-env CANARY_A --passthrough-env CANARY_B \
    -- sh -c 'printenv CANARY_A'
expect_stdout_matches \
  "agent: --passthrough-env repeatable (var B reaches jail)" \
  "^val-B\$" -- \
  env CANARY_A=val-A CANARY_B=val-B \
    "$JAIL" agent --passthrough-env CANARY_A --passthrough-env CANARY_B \
    -- sh -c 'printenv CANARY_B'

# E1: BUBBLEWRAP_JAIL_PASSTHROUGH_ENV accepts comma-separated list.
expect_stdout_matches \
  "agent: BUBBLEWRAP_JAIL_PASSTHROUGH_ENV CSV (var A reaches jail)" \
  "^csv-A\$" -- \
  env CANARY_A=csv-A CANARY_B=csv-B \
      BUBBLEWRAP_JAIL_PASSTHROUGH_ENV=CANARY_A,CANARY_B \
    "$JAIL" agent -- sh -c 'printenv CANARY_A'
expect_stdout_matches \
  "agent: BUBBLEWRAP_JAIL_PASSTHROUGH_ENV CSV (var B reaches jail)" \
  "^csv-B\$" -- \
  env CANARY_A=csv-A CANARY_B=csv-B \
      BUBBLEWRAP_JAIL_PASSTHROUGH_ENV=CANARY_A,CANARY_B \
    "$JAIL" agent -- sh -c 'printenv CANARY_B'

# E1: reserved-name check applies per-entry — second entry HOME is rejected.
expect_fail \
  "agent: --passthrough-env reserved name in 2nd position rejected" -- \
  "$JAIL" agent --passthrough-env CANARY_A --passthrough-env HOME -- true

# E1: reserved-name check applies to env-var-supplied list too.
expect_fail \
  "agent: BUBBLEWRAP_JAIL_PASSTHROUGH_ENV CSV with reserved name rejected" -- \
  bash -c 'BUBBLEWRAP_JAIL_PASSTHROUGH_ENV=CANARY_A,HOME "$1" agent -- true' _ "$JAIL"

# E1: trailing/double commas in env var CSV are tolerated (empty entries skipped).
expect_stdout_matches \
  "agent: BUBBLEWRAP_JAIL_PASSTHROUGH_ENV CSV tolerates empty entries" \
  "^tolerated\$" -- \
  env CANARY_A=tolerated \
      BUBBLEWRAP_JAIL_PASSTHROUGH_ENV=,,CANARY_A,, \
    "$JAIL" agent -- sh -c 'printenv CANARY_A'

# B4 regression: --project-as / and --project-as /bin are rejected.
expect_fail \
  "agent: --project-as rejects shadowing /" -- \
  "$JAIL" agent --project-as / -- true
expect_fail \
  "agent: --project-as rejects shadowing /bin" -- \
  "$JAIL" agent --project-as /bin -- true
expect_fail \
  "agent: --project-as rejects path under /usr" -- \
  "$JAIL" agent --project-as /usr/local/project -- true

echo
echo "[agent mode / --project-as synthetic path]"
# Default: same-path binding.  cwd inside jail = host project.
expect_stdout_matches \
  "agent: default project path is same-path (no remapping)" \
  "^${DIR_B}\$" -- \
  bash -c "cd \"\$1\" && \"\$2\" agent -- pwd" _ "$DIR_B" "$JAIL"

# --project-as: bind DIR_B on host to /workspace inside jail.
expect_stdout_matches \
  "agent: --project-as maps project to synthetic path" \
  "^/workspace\$" -- \
  bash -c "cd \"\$1\" && \"\$2\" agent --project-as /workspace -- pwd" _ "$DIR_B" "$JAIL"

# --project-as: the synthetic path shows the real project contents.
echo "canary-content" > "$DIR_B/readme.txt"
expect_stdout_matches \
  "agent: --project-as exposes project contents at synthetic path" \
  "^canary-content\$" -- \
  bash -c "cd \"\$1\" && \"\$2\" agent --project-as /workspace -- cat /workspace/readme.txt" _ "$DIR_B" "$JAIL"

# --project-as: writable
expect_pass \
  "agent: --project-as is writable" -- \
  bash -c "cd \"\$1\" && \"\$2\" agent --project-as /workspace -- sh -c 'echo written > /workspace/.writetest && rm /workspace/.writetest'" _ "$DIR_B" "$JAIL"

# --project-as: relative path rejected
expect_fail \
  "agent: --project-as rejects relative path" -- \
  "$JAIL" agent --project-as workspace -- true

# --project-as: reject in run mode
expect_fail \
  "run: --project-as is agent-only" -- \
  "$JAIL" run --project-as /workspace -- true

# F1: --project-ro read-only project mode.  DIR_B has readme.txt from the
# project-as test block above.
expect_pass \
  "agent: --project-ro can read project content (DIR_B/readme.txt)" -- \
  bash -c "cd \"\$1\" && \"\$2\" agent --project-ro -- cat readme.txt" _ "$DIR_B" "$JAIL"
expect_fail \
  "agent: --project-ro makes project not writable" -- \
  bash -c "cd \"\$1\" && \"\$2\" agent --project-ro -- touch .ro-write-test" _ "$DIR_B" "$JAIL"
expect_fail \
  "run: --project-ro is agent-only" -- \
  "$JAIL" run --project-ro -- true

# A6: --project-ro combined with --project-as.  Verify both the read
# path (readme.txt visible at the synthetic dst) and the write block
# (the synthetic dst is not writable).
expect_stdout_matches \
  "agent: --project-ro + --project-as reads synthetic-path content" \
  "^canary-content\$" -- \
  bash -c "cd \"\$1\" && \"\$2\" agent --project-ro --project-as /ro-workspace -- cat /ro-workspace/readme.txt" _ "$DIR_B" "$JAIL"
expect_fail \
  "agent: --project-ro + --project-as not writable at synthetic path" -- \
  bash -c "cd \"\$1\" && \"\$2\" agent --project-ro --project-as /ro-workspace -- touch /ro-workspace/.ro-write-test" _ "$DIR_B" "$JAIL"

# F2: --bind/--ro-bind essential-dir guard.  Reject destinations that
# would shadow FHS-essential paths and break the sandbox.  Sub-paths are
# still allowed (B1's user --bind into /etc/foo still works).
expect_fail "run: --bind dst=/ rejected"          -- "$JAIL" run --bind /tmp / -- true
expect_fail "run: --bind dst=/usr rejected"       -- "$JAIL" run --bind /tmp /usr -- true
expect_fail "run: --bind dst=/bin rejected"       -- "$JAIL" run --bind /tmp /bin -- true
expect_fail "run: --bind dst=/lib rejected"       -- "$JAIL" run --bind /tmp /lib -- true
expect_fail "run: --bind dst=/etc rejected"       -- "$JAIL" run --bind /tmp /etc -- true
expect_fail "run: --bind dst=/proc rejected"      -- "$JAIL" run --bind /tmp /proc -- true
expect_fail "run: --bind dst=/dev rejected"       -- "$JAIL" run --bind /tmp /dev -- true
expect_fail "run: --bind dst=/nix rejected"       -- "$JAIL" run --bind /tmp /nix -- true
expect_fail "run: --ro-bind dst=/usr rejected"    -- "$JAIL" run --ro-bind /tmp /usr -- true

# Sub-paths of essentials are still allowed (T4 above already proves
# this for /etc/foo — the only essential whose parent is rw enough for
# bwrap to mkdir the mount point.  /usr/local/foo would require /usr to
# be writable, which it isn't.  So T4 is the canonical sub-path test).

# F2: --bind-force opts out of the guard.  Test by rebinding /usr → /usr
# (a no-op semantically; the source IS the existing host /usr) and
# verifying the wrapper passes its own check (i.e. doesn't die before
# reaching bwrap).
expect_pass \
  "run: --bind-force lets user shadow essential dir (re-bind /usr→/usr)" -- \
  "$JAIL" run --bind-force --bind /usr /usr -- ls /usr

# N1 regression: --passthrough-env is documented agent-only and must be
# rejected in run mode, not silently accepted with a dead value.
expect_fail \
  "run: --passthrough-env is agent-only" -- \
  "$JAIL" run --passthrough-env MY_TOKEN -- true

echo
echo "[seccomp: TIOCSTI blocked]"
# Inside the jail, ioctl(STDIN, TIOCSTI, ...) should fail with EPERM because
# the seccomp filter short-circuits the syscall regardless of the fd's type.
# Without seccomp, the same call would fail with ENOTTY (stdin is not a tty
# in the test harness).  We distinguish the two errno values explicitly.
SECCOMP_PROBE='use Errno qw(EPERM); ioctl(STDIN, 0x5412, my $c = "x"); exit ($! == EPERM ? 0 : 1)'

expect_pass \
  "agent: seccomp blocks ioctl(TIOCSTI) with EPERM" -- \
  "$JAIL" agent -- perl -e "$SECCOMP_PROBE"

expect_pass \
  "run: seccomp blocks ioctl(TIOCSTI) with EPERM" -- \
  "$JAIL" run --net -- perl -e "$SECCOMP_PROBE"

# Sanity check: with --no-seccomp, the ioctl fails with a different errno
# (ENOTTY on a pipe), so the perl probe exits 1.  expect_fail → pass.
expect_fail \
  "agent --no-seccomp: TIOCSTI not blocked by seccomp (fails with non-EPERM errno)" -- \
  "$JAIL" agent --no-seccomp -- perl -e "$SECCOMP_PROBE"

echo
echo "[lifecycle, signals, exit-code propagation (O1+O2)]"
# O2: exit code propagation.  The wrapper exec()s bwrap as its final
# action, so the wrapper's exit code is the user command's exit code.
expect_pass "run: exit 0 propagated (true)"      -- "$JAIL" run -- true
expect_fail "run: exit nonzero propagated (false)" -- "$JAIL" run -- false
expect_pass "agent: exit 0 propagated (true)"      -- "$JAIL" agent -- true
expect_fail "agent: exit nonzero propagated (false)" -- "$JAIL" agent -- false

# Specific exit code propagated (not just 0/nonzero).
expect_pass \
  "run: specific exit code 42 propagates through wrapper" -- \
  bash -c '"$1" run -- sh -c "exit 42"; rc=$?; test "$rc" = 42' _ "$JAIL"

# O1: signal forwarding.  timeout(1) sends SIGTERM after 1s; bwrap
# forwards it to the sandboxed sleep, sleep dies, wrapper exits non-zero
# (timeout returns 124 by default when the command times out).
expect_fail \
  "run: timeout(1) terminates wrapper via SIGTERM (signal forwarding)" -- \
  timeout 1 "$JAIL" run -- sleep 30
expect_fail \
  "agent: timeout(1) terminates wrapper via SIGTERM (signal forwarding)" -- \
  timeout 1 "$JAIL" agent -- sleep 30

# O1: --die-with-parent must stay wired into the wrapper's bwrap argv.
# This is a static guard; the actual kernel behavior is bwrap's, we just
# need to keep passing the flag.  Looks at the wrapped script behind the
# Flox shim if present.
WRAPPED_SCRIPT="$(dirname "$JAIL")/.bubblewrap-jail-wrapped"
if [ -f "$WRAPPED_SCRIPT" ]; then
  CHECK_SCRIPT="$WRAPPED_SCRIPT"
else
  CHECK_SCRIPT="$JAIL"
fi
expect_pass \
  "wrapper source still passes --die-with-parent" -- \
  grep -q -- "--die-with-parent" "$CHECK_SCRIPT"

# O2: missing /nix should not break the wrapper.  The wrapper uses
# --ro-bind-try (not --ro-bind) for /nix, which silently no-ops on
# hosts where /nix is absent.  We can't easily simulate "missing /nix"
# from a Nix host, so this is a static guard against accidentally
# changing --ro-bind-try /nix to --ro-bind /nix.
expect_pass \
  "wrapper uses --ro-bind-try /nix (graceful when /nix absent)" -- \
  grep -q -- "--ro-bind-try /nix" "$CHECK_SCRIPT"

echo
echo "[B2: human-readable PFC dump shipped alongside BPF blob]"
# B2: the build runs `gen-seccomp --pfc > tiocsti.pfc` and installs the
# result alongside tiocsti.bpf for human review.  Verify it's present
# and references the ioctl syscall (proves it's a real filter dump,
# not an empty file).  Skip in source mode (no installed package).
if [ -f "$WRAPPED_SCRIPT" ]; then
  PFC_FILE="$(dirname "$(dirname "$WRAPPED_SCRIPT")")/share/bubblewrap-jail/tiocsti.pfc"
  expect_pass \
    "B2: PFC dump shipped at share/bubblewrap-jail/tiocsti.pfc" -- \
    test -r "$PFC_FILE"
  expect_stdout_matches \
    "B2: PFC dump references ioctl syscall" \
    "ioctl" -- \
    cat "$PFC_FILE"
  expect_stdout_matches \
    "B2: PFC dump references ERRNO action (the EPERM rule)" \
    "ERRNO" -- \
    cat "$PFC_FILE"
else
  echo "  skip: source-mode wrapper has no installed PFC, B2 tests skipped"
fi

echo
echo "[V1: --lock-file and --sync-fd pass-through]"
# V1: --lock-file ↔ bwrap takes a POSIX advisory READ (shared) lock via
# fcntl(2) on the file for the lifetime of the sandbox.  Note: bwrap uses
# fcntl POSIX locks, NOT flock(2), so flock(1) won't see them — we have
# to inspect /proc/locks directly, matching by the file's inode number.
# /proc/locks format: "ID: TYPE FLAGS RW PID MAJ:MIN:INODE START END".
expect_pass \
  "run: --lock-file holds a POSIX advisory lock during sandbox" -- \
  bash -c '
    LOCK="$2/v1-lock-test"
    : >"$LOCK"
    "$1" run --lock-file "$LOCK" -- sleep 1 &
    JAIL_PID=$!
    sleep 0.3
    INODE=$(stat -c %i "$LOCK")
    locked=0
    grep -q ":$INODE " /proc/locks && locked=1
    wait $JAIL_PID
    [ $locked = 1 ]
  ' _ "$JAIL" "$SMOKE_CACHE"

expect_pass \
  "run: --lock-file lock released after sandbox exits" -- \
  bash -c '
    LOCK="$2/v1-lock-released-test"
    : >"$LOCK"
    "$1" run --lock-file "$LOCK" -- true
    INODE=$(stat -c %i "$LOCK")
    ! grep -q ":$INODE " /proc/locks
  ' _ "$JAIL" "$SMOKE_CACHE"

# V1: --sync-fd ↔ bwrap holds the inherited fd open for the lifetime of
# the sandbox; when the sandbox exits the fd closes.  Test via a pipe:
# parent reads from the read end, wrapper inherits the write end via
# fd 9; once the wrapper exits, the read end sees EOF and `cat` returns 0.
# If --sync-fd weren't honored, the read end would still see EOF (because
# the wrapper exits anyway), so we add a sleep on the write side and
# check that the read genuinely BLOCKED until exit, not returned early.
expect_pass \
  "run: --sync-fd holds fd open for sandbox lifetime, closes at exit" -- \
  bash -c '
    PIPE="$2/v1-sync-pipe"
    rm -f "$PIPE"
    mkfifo "$PIPE"
    # Start the reader: it should block on the FIFO until the wrapper exits.
    ( timeout 5 cat "$PIPE" >/dev/null; echo $? > "$PIPE.rc" ) &
    READER=$!
    # Wrapper holds fd 9 → pipe write end via --sync-fd; sleep 0.3s before
    # exiting so we can prove the reader was actually blocked, not racing.
    "$1" run --sync-fd 9 -- sleep 0.3 9>"$PIPE"
    wait $READER
    rc=$(cat "$PIPE.rc" 2>/dev/null || echo timeout)
    test "$rc" = 0
  ' _ "$JAIL" "$SMOKE_CACHE"

# V1: --sync-fd validation — must be a non-negative integer.
expect_fail \
  "run: --sync-fd rejects non-numeric value" -- \
  "$JAIL" run --sync-fd abc -- true
expect_fail \
  "run: --sync-fd rejects empty value" -- \
  "$JAIL" run --sync-fd "" -- true

# A4: --lock-file pre-validates that the host path exists.
expect_fail \
  "run: --lock-file nonexistent host path rejected by wrapper" -- \
  "$JAIL" run --lock-file /nonexistent/lock/path -- true
expect_stderr_matches \
  "run: --lock-file nonexistent error mentions 'does not exist'" \
  "does not exist" -- \
  "$JAIL" run --lock-file /nonexistent/lock/path -- true

# A3: V1 auto-bind skips when the user has already bound the jail-side
# path — so a user binding a different source at the lock path wins.
# Verify by reading the lock file inside the jail: should see the
# USER-supplied source content, not the host lock-file content.
expect_stdout_matches \
  "run: --lock-file respects user --bind at same jail-side path" \
  "^user-supplied-source\$" -- \
  bash -c '
    LOCK="$2/a3-lock"
    SRC="$2/a3-user-source"
    echo "lock-file-content"     > "$LOCK"
    echo "user-supplied-source"  > "$SRC"
    "$1" run --bind "$SRC" "$LOCK" --lock-file "$LOCK" -- cat "$LOCK"
  ' _ "$JAIL" "$SMOKE_CACHE"

echo
echo "[seccomp: failure modes (C2 — clear errors)]"
# C2 regression: when the BPF blob is present and readable but bwrap rejects
# it (corrupt, kernel-mismatched, libseccomp-skewed), the wrapper must die
# with our context message, not propagate a bare bwrap stderr.  We construct
# a corrupt BPF (100 zero bytes), copy the wrapper to a writable path, sed
# its hardcoded BPF_PATH to point at the corrupt file, and assert.
#
# Subtlety: when JAIL is the result-* symlink, $JAIL is actually a tiny
# 485-byte Flox shim that execs the real script as .bubblewrap-jail-wrapped
# in the same dir (see CLAUDE.md).  We need the real script for the BPF_PATH
# substitution, and we invoke it directly (not via the shim), which works
# because the harness already has bwrap in PATH from the build env.
#
# Source-mode skip: when JAIL is the unbuilt source script, BPF_PATH is the
# unsubstituted "@BPF_PATH@" placeholder.  The sed substitution would have
# nothing meaningful to replace, so skip.
WRAPPED_SCRIPT="$(dirname "$JAIL")/.bubblewrap-jail-wrapped"
if [ -f "$WRAPPED_SCRIPT" ]; then
  REAL_SCRIPT="$WRAPPED_SCRIPT"
else
  REAL_SCRIPT="$JAIL"
fi

if grep -q '^BPF_PATH="/' "$REAL_SCRIPT" 2>/dev/null; then
  CORRUPT_BPF="$SMOKE_CACHE/corrupt.bpf"
  dd if=/dev/zero of="$CORRUPT_BPF" bs=1 count=100 2>/dev/null
  JAIL_CORRUPT="$SMOKE_CACHE/jail-corrupt"
  cp "$REAL_SCRIPT" "$JAIL_CORRUPT"
  chmod u+w "$JAIL_CORRUPT"
  # Match the BPF_PATH= line and substitute the corrupt path.  The | delim
  # avoids escaping / in store paths.
  sed -i "s|^BPF_PATH=.*|BPF_PATH=\"$CORRUPT_BPF\"|" "$JAIL_CORRUPT"

  expect_fail \
    "agent: corrupt BPF causes wrapper to exit non-zero" -- \
    "$JAIL_CORRUPT" agent -- true

  expect_stderr_matches \
    "agent: corrupt BPF error mentions 'rejected by bwrap' (C2 context)" \
    "rejected by bwrap" -- \
    "$JAIL_CORRUPT" agent -- true

  # Same again with --no-seccomp, to prove the opt-out still works even when
  # the BPF is corrupt: should NOT die at the seccomp step.
  expect_pass \
    "agent --no-seccomp: corrupt BPF is bypassed cleanly" -- \
    "$JAIL_CORRUPT" agent --no-seccomp -- true
else
  echo "  skip: source-mode wrapper has unsubstituted BPF_PATH, C2 tests skipped"
fi

echo
echo "[interactive pty: agent preserves controlling tty, run severs it]"
# T5: the reason agent mode does NOT pass --new-session is to keep an
# interactive controlling tty for tools like Claude Code.  Run mode DOES pass
# --new-session, which calls setsid() and severs the controlling-tty link.
#
# Probe: 'test -t 0' is too weak — it only checks isatty(fd) on a character
# device, which is unaffected by setsid().  The strict probe is opening
# /dev/tty for reading: the kernel resolves /dev/tty to the *controlling*
# terminal, so after setsid the open fails with ENXIO.
#
# We use script(1) to allocate a real pty around the harness invocation;
# gated on availability.
if command -v script >/dev/null 2>&1; then
  expect_pass \
    "agent: controlling tty preserved (open /dev/tty succeeds)" -- \
    script -qefc "$JAIL agent -- sh -c 'exec </dev/tty'" /dev/null
  expect_fail \
    "run: --new-session severs controlling tty (open /dev/tty fails)" -- \
    script -qefc "$JAIL run -- sh -c 'exec </dev/tty'" /dev/null
else
  echo "  skip: script(1) not available, T5 pty tests skipped"
fi

echo
echo "[agent mode / PATH inheritance]"
# Agent mode should inherit host $PATH (so Flox/Nix-installed commands work).
# Run mode should keep its minimal baseline PATH.
expect_stdout_matches \
  "agent: inherits host PATH" \
  "/canary/path/from/host" -- \
  env PATH="/canary/path/from/host:$PATH" "$JAIL" agent -- sh -c 'printenv PATH'

expect_stdout_matches \
  "run: uses minimal baseline PATH (no leak from host)" \
  "^/usr/bin:/bin:/usr/sbin:/sbin\$" -- \
  env PATH="/canary/path/from/host:$PATH" "$JAIL" run -- sh -c 'printenv PATH'

echo
echo "[--help works without bwrap in PATH]"
# Invoke bash explicitly to bypass the #!/usr/bin/env bash shebang: we want to
# isolate PATH to test the 'command -v bwrap' check, not test env(1)'s lookup.
BASH_BIN=$(command -v bash)
expect_pass \
  "run: --help succeeds with empty PATH" -- \
  env -i PATH=/nonexistent "$BASH_BIN" "$JAIL" --help

# With bwrap absent, bad subcommand should error cleanly (not crash because of
# an early dependency check).  Non-zero exit = cleanly rejected subcommand.
expect_fail \
  "run: bad subcommand errors cleanly with empty PATH" -- \
  env -i PATH=/nonexistent "$BASH_BIN" "$JAIL" bogus

echo
echo "[check subcommand]"
expect_pass \
  "check: exits 0 on this host" -- \
  "$JAIL" check

expect_pass \
  "check: reports at least 15 PASS lines" -- \
  bash -c 'n=$("$1" check 2>/dev/null | grep -c "^  PASS "); test "$n" -ge 15' _ "$JAIL"

expect_stdout_matches \
  "check: reports 0 failed" \
  "0 failed" -- \
  "$JAIL" check

echo
echo "=== summary: $pass passed, $fail failed ==="
if [ $fail -gt 0 ]; then
  printf 'failed:\n'
  for t in "${failed_tests[@]}"; do printf '  - %s\n' "$t"; done
  exit 1
fi
exit 0
