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
