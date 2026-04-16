package main

import (
	"fmt"
	"os"
)

// bwrapPath can be set at build time via -ldflags "-X main.bwrapPath=/path/to/bwrap".
// If empty, bwrap is looked up via exec.LookPath at runtime.
var bwrapPath string

// version is set at build time via -ldflags "-X main.version=X.Y.Z".
// When unset (dev builds), defaults to "dev".
var version string

const prog = "bubblewrap-jail"

func main() {
	if version == "" {
		version = "dev"
	}

	if len(os.Args) < 2 {
		usage(os.Stderr)
		fatalf("missing subcommand")
	}

	switch os.Args[1] {
	case "run", "agent", "flox-env":
		cfg, err := parseConfig(os.Args[1], os.Args[2:])
		if err != nil {
			usage(os.Stderr)
			fatalf("%v", err)
		}
		if err := cfg.validate(); err != nil {
			usage(os.Stderr)
			fatalf("%v", err)
		}
		if err := cfg.applyDefaults(); err != nil {
			fatalf("%v", err)
		}
		if err := run(cfg); err != nil {
			fatalf("%v", err)
		}

	case "check", "doctor":
		os.Exit(runCheck(os.Args[2:]))

	case "-h", "--help":
		usage(os.Stdout)
		os.Exit(0)

	default:
		usage(os.Stderr)
		fatalf("unknown subcommand: %s", os.Args[1])
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", prog, fmt.Sprintf(format, args...))
	os.Exit(1)
}

func errf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", prog, fmt.Sprintf(format, args...))
}
