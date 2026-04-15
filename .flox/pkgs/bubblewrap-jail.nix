{ lib
, stdenv
, pkg-config
, libseccomp
, shellcheck
}:

# bubblewrap-jail — opinionated bwrap wrapper packaged as a Flox nix-expression
# build.  See src/bubblewrap-jail for the wrapper itself, src/gen-seccomp.c for
# the TIOCSTI seccomp helper, CLAUDE.md for the project conventions, and
# ROADMAP.md for the feature history.
#
# This derivation deliberately does NOT reference bubblewrap.  The installed
# script calls `bwrap` via $PATH at runtime; consumers install both this
# package and the separate `bubblewrap` package in their Flox env (see the
# consumer env at /home/daedalus/dev/floxwrapped).  Keeping bwrap out of this
# closure lets consumers pick the bwrap version they want to run against.
#
# This derivation replaces the previous [build.bubblewrap-jail] block in
# .flox/env/manifest.toml (manifest-build style).  See commit v0.5.0 for the
# migration rationale.

stdenv.mkDerivation (finalAttrs: {
  pname = "bubblewrap-jail";
  version = "0.5.0";

  # Project root.  Flox's nix-expression builds run inside the Nix sandbox,
  # which means only git-tracked files are visible — same constraint the
  # manifest build had under `sandbox = "pure"`.  Any new source file must be
  # `git add`ed before `flox build` will see it.
  src = ../..;

  nativeBuildInputs = [ pkg-config shellcheck ];
  buildInputs       = [ libseccomp ];

  # Default unpack/patch phases are fine: stdenv copies src → build dir.

  buildPhase = ''
    runHook preBuild

    # Phase 1 — shellcheck lint pass (style severity, same as the previous
    # manifest build).  Catches nit-level issues before the build continues.
    shellcheck --severity=style --shell=bash src/bubblewrap-jail

    # Phase 2 — compile gen-seccomp against libseccomp.
    # -Wno-missing-field-initializers silences a benign warning from
    # libseccomp's SCMP_A1 macro, which intentionally leaves the range-high
    # field zeroed.
    $CC -O2 -Wall -Wextra -Wno-missing-field-initializers \
        -o gen-seccomp src/gen-seccomp.c \
        $(pkg-config --cflags --libs libseccomp)

    # Phase 3 — generate the raw BPF blob that blocks ioctl(_, TIOCSTI, _).
    # Refuse implausibly small or large blobs (guards against a gen-seccomp
    # regression that silently emits garbage).
    ./gen-seccomp > tiocsti.bpf
    bpf_bytes=$(wc -c < tiocsti.bpf)
    if [ "$bpf_bytes" -lt 32 ] || [ "$bpf_bytes" -gt 4096 ]; then
      echo "gen-seccomp: unexpected BPF size $bpf_bytes" >&2
      exit 1
    fi

    # Phase 4 — generate the human-readable PFC dump alongside the BPF.
    # Purely an audit artifact: the wrapper doesn't read it at runtime, but
    # it lets an auditor `cat` it directly to see the filter rules without
    # needing libseccomp tooling on the inspecting host.  (Roadmap item B2.)
    ./gen-seccomp --pfc > tiocsti.pfc
    if [ ! -s tiocsti.pfc ]; then
      echo "gen-seccomp --pfc produced empty output" >&2
      exit 1
    fi

    # Phase 5 — A9 regression guard: gen-seccomp must reject extra arguments.
    # A bug that silently ignored them would let typos like `gen-seccomp --pfc
    # out.pfc` pass without the user noticing.
    if ./gen-seccomp --pfc extra-arg >/dev/null 2>&1; then
      echo "gen-seccomp accepts extra arguments (A9 regression)" >&2
      exit 1
    fi

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    install -Dm644 tiocsti.bpf          $out/share/bubblewrap-jail/tiocsti.bpf
    install -Dm644 tiocsti.pfc          $out/share/bubblewrap-jail/tiocsti.pfc
    install -Dm755 src/bubblewrap-jail  $out/bin/bubblewrap-jail

    # Substitute the build-time placeholders in the installed script.
    # `substituteInPlace --replace-fail` errors loudly if a placeholder is
    # missing — stronger than the previous `sed -i` which silently no-op'd
    # on a placeholder-free script.  CRITICAL: each placeholder MUST appear
    # exactly once in src/bubblewrap-jail.  In particular, do NOT put
    # @BPF_PATH@ or @VERSION@ inside any comment in the script — the
    # substitution is global and would rewrite the comment too, breaking
    # either the seccomp detection or the version reporting.  This is the
    # same class of bug as C2 in v0.3.6.
    substituteInPlace $out/bin/bubblewrap-jail \
      --replace-fail '@BPF_PATH@' "$out/share/bubblewrap-jail/tiocsti.bpf" \
      --replace-fail '@VERSION@'  "${finalAttrs.version}"

    runHook postInstall
  '';

  meta = {
    description = "Opinionated bubblewrap wrapper: run/agent subcommands, secure-by-default defaults";
    homepage    = "https://github.com/barstoolbluz/build-flox-bubblewrapped";
    # license: repo has no LICENSE file today; omitted until one lands.
    platforms   = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "bubblewrap-jail";
  };
})
