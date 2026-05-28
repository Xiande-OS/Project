/* sigtest: exercises SIGINT/SIGTERM/SIGUSR1 handlers via raise()+kill().
 *
 * Expected output:
 *     start
 *     got SIGUSR1
 *     got SIGTERM
 *     got SIGINT
 *     end
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

static volatile int last_signo = 0;
static volatile int seq = 0;

static void handler(int signo) {
    /* Use write-based printf via libc; we don't need _exit safety here. */
    printf("got %s\n",
        signo == SIGUSR1 ? "SIGUSR1" :
        signo == SIGTERM ? "SIGTERM" :
        signo == SIGINT  ? "SIGINT"  :
                           "?");
    fflush(stdout);
    last_signo = signo;
    seq++;
}

int main(void) {
    struct sigaction sa = { 0 };
    sa.sa_handler = handler;
    sa.sa_flags = 0;

    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    printf("start\n");
    fflush(stdout);

    raise(SIGUSR1);
    raise(SIGTERM);
    if (kill(getpid(), SIGINT) != 0) {
        printf("kill failed\n");
        return 1;
    }

    printf("end seq=%d\n", seq);
    fflush(stdout);
    return 0;
}
