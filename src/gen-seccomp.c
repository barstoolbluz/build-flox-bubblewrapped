/*
 * gen-seccomp.c — build-time helper for bubblewrap-jail.
 *
 * Uses libseccomp to construct a BPF program that blocks the ioctl syscall
 * when its second argument equals TIOCSTI, letting every other syscall
 * through.  The resulting sock_filter[] array is written to stdout via
 * seccomp_export_bpf().  The shell script at runtime passes this blob to
 * bwrap via --seccomp <fd>.
 *
 * Why this matters: without a seccomp filter and without --new-session, a
 * process inside the sandbox can inject characters into its parent's
 * controlling terminal using ioctl(tty_fd, TIOCSTI, &c).  This filter closes
 * that class of attack without detaching the sandbox from its pty (which
 * --new-session would do, breaking interactive agent workflows).
 *
 * Build: gcc -O2 -Wall -Wextra -o gen-seccomp gen-seccomp.c $(pkg-config --cflags --libs libseccomp)
 * Run:   ./gen-seccomp > tiocsti.bpf
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
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
     * is both safe and architecture-portable (seccomp-bpf permits argument
     * comparisons only against scalar values, not dereferenced pointers). */
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
