/*
 * gen-seccomp.c — build-time helper for bubblewrap-jail.
 *
 * Uses libseccomp to construct a BPF program that blocks the ioctl syscall
 * when its second argument equals TIOCSTI, letting every other syscall
 * through.  The resulting sock_filter[] array is written to stdout via
 * seccomp_export_bpf().  The shell script at runtime passes this blob to
 * bwrap via --seccomp <fd>.
 *
 * Scope (important): this filter exists to close ONE attack class —
 * ioctl(tty_fd, TIOCSTI, &c) being used by sandboxed code to inject
 * characters into the parent's controlling terminal.  It is NOT a
 * general-purpose hostile-code sandbox.  Agent mode deliberately allows
 * every other syscall because the wrapper's threat model is prompt
 * injection (a buggy/steerable agent), not arbitrary malicious binaries.
 * See src/bubblewrap-jail header for the full threat model.
 *
 * Why THIS filter matters: without it, and without bwrap --new-session,
 * a process inside the sandbox can inject characters into its parent's
 * controlling terminal.  We can't pass --new-session in agent mode
 * because setsid() detaches the sandbox from its pty and breaks
 * interactive agent workflows (Claude Code etc. want a real tty).
 *
 * Portability note: the RULE LOGIC here is architecture-independent
 * (libseccomp abstracts the syscall-number differences), but the
 * EMITTED BPF blob is a per-architecture build artifact — BPF encodes
 * raw syscall numbers, and those differ between x86_64, aarch64, etc.
 * Treat tiocsti.bpf as target-specific; build on each target arch.
 *
 * Build: gcc -O2 -Wall -Wextra -o gen-seccomp gen-seccomp.c $(pkg-config --cflags --libs libseccomp)
 * Run:   ./gen-seccomp > tiocsti.bpf
 */

#include <errno.h>
#include <stdio.h>
#include <sys/ioctl.h>

#include <seccomp.h>

int main(void) {
    /* Default action: allow everything. */
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        fprintf(stderr, "gen-seccomp: seccomp_init failed\n");
        return 1;
    }

    /* Rule: ioctl(_, TIOCSTI, _) → EPERM.  Argument 1 (zero-indexed) is
     * the request code; TIOCSTI is a scalar constant so a direct EQ match
     * is safe — seccomp-bpf permits argument comparisons only against
     * scalar values, never dereferenced pointers, so the filter cannot be
     * defeated by aliasing the request through a pointer. */
    int rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
                              SCMP_SYS(ioctl), 1,
                              SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)TIOCSTI));
    if (rc < 0) {
        fprintf(stderr, "gen-seccomp: seccomp_rule_add failed: %d\n", rc);
        seccomp_release(ctx);
        return 2;
    }

    /* Emit the BPF program on stdout (fd 1). */
    rc = seccomp_export_bpf(ctx, 1);
    if (rc < 0) {
        fprintf(stderr, "gen-seccomp: seccomp_export_bpf failed: %d\n", rc);
        seccomp_release(ctx);
        return 3;
    }

    seccomp_release(ctx);
    return 0;
}
