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
expect_pass "agent: HOME writable"              -- "$JAIL" agent -- touch '/tmp/../tmp/agent-scratch'
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
expect_stdout_matches "agent: PWD = project"    "$FLOX_ENV_PROJECT$" -- \
  "$JAIL" agent -- sh -c 'pwd'

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
echo "=== summary: $pass passed, $fail failed ==="
if [ $fail -gt 0 ]; then
  printf 'failed:\n'
  for t in "${failed_tests[@]}"; do printf '  - %s\n' "$t"; done
  exit 1
fi
exit 0
