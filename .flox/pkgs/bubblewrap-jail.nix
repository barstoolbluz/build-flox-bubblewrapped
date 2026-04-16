{ lib
, buildGoModule
, bubblewrap
, pkg-config
, libseccomp
, shellcheck
}:

# bubblewrap-jail — opinionated bwrap wrapper rewritten in Go (v0.9.0).
#
# Build: `flox build bubblewrap-jail`
#
# The Go binary embeds the seccomp BPF blob at compile time via //go:embed.
# gen-seccomp.c (in src/) is compiled and run in preBuild to produce the
# blob before `go build` starts.  The blob and its human-readable PFC dump
# are also installed to $out/share/bubblewrap-jail/ for audit.
#
# bwrap path and version are baked in via -ldflags so the binary is fully
# self-contained at runtime (no @BPF_PATH@ or @VERSION@ substitution).

buildGoModule {
  pname = "bubblewrap-jail";
  version = "0.9.0";

  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      ../../go.mod
      ../../go.sum
      ../../main.go
      ../../config.go
      ../../sandbox.go
      ../../run.go
      ../../agent.go
      ../../floxenv.go
      ../../check.go
      ../../paths.go
      ../../seccomp.go
      ../../src/gen-seccomp.c
    ];
  };

  vendorHash = "sha256-LXR8/S1x5FOxgcp8uXppc2foxwHZq6KANA3WCtX0MoE=";

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ libseccomp ];

  # The go-modules (vendor) derivation inherits preBuild, but doesn't have
  # libseccomp.  Clear preBuild there so only the main build compiles
  # gen-seccomp.
  overrideModAttrs = _: {
    preBuild = "";
    postInstall = "";
  };

  ldflags = [
    "-X main.bwrapPath=${bubblewrap}/bin/bwrap"
    "-X main.version=0.9.0"
  ];

  # Generate the BPF blob + PFC dump BEFORE `go build` runs.
  # go build picks up tiocsti.bpf via //go:embed in seccomp.go.
  preBuild = ''
    cd "$NIX_BUILD_TOP/source"
    $CC -O2 -Wall -Wextra -Wno-missing-field-initializers \
        -o gen-seccomp src/gen-seccomp.c \
        $(pkg-config --cflags --libs libseccomp)
    ./gen-seccomp > tiocsti.bpf
    ./gen-seccomp --pfc > tiocsti.pfc
    bpf_bytes=$(wc -c < tiocsti.bpf)
    if [ "$bpf_bytes" -lt 32 ] || [ "$bpf_bytes" -gt 4096 ]; then
      echo "gen-seccomp: unexpected BPF size $bpf_bytes" >&2
      exit 1
    fi
    if [ ! -s tiocsti.pfc ]; then
      echo "gen-seccomp --pfc produced empty output" >&2
      exit 1
    fi
    # A9 regression guard: gen-seccomp must reject extra arguments.
    if ./gen-seccomp --pfc extra-arg >/dev/null 2>&1; then
      echo "gen-seccomp accepts extra arguments (A9 regression)" >&2
      exit 1
    fi
    cd -
  '';

  postInstall = ''
    # Rename the binary from the Go module name to the project name.
    mv $out/bin/build-flox-bubblewrapped $out/bin/bubblewrap-jail
    # Ship the BPF + PFC for audit (the binary embeds the BPF via
    # //go:embed, so these are purely for human inspection).
    cd "$NIX_BUILD_TOP/source"
    install -Dm644 tiocsti.bpf $out/share/bubblewrap-jail/tiocsti.bpf
    install -Dm644 tiocsti.pfc $out/share/bubblewrap-jail/tiocsti.pfc
    cd -
  '';

  meta = {
    description = "Opinionated bubblewrap wrapper: run/agent/flox-env subcommands, secure-by-default defaults";
    homepage = "https://github.com/barstoolbluz/build-flox-bubblewrapped";
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "bubblewrap-jail";
  };
}
