/* Verify sigprocmask blocks pending delivery until unblocked. */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

static volatile int order = 0;
static volatile int got_usr1_at = 0;

static void on_usr1(int s) {
    (void)s;
    got_usr1_at = ++order;
}

int main(void) {
    struct sigaction sa = {0};
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);

    raise(SIGUSR1);
    /* USR1 should be pending but not delivered yet */
    int before = ++order;
    printf("before unblock: order=%d got_usr1_at=%d\n", before, got_usr1_at);

    sigprocmask(SIG_UNBLOCK, &set, NULL);
    int after = ++order;
    printf("after unblock: order=%d got_usr1_at=%d\n", after, got_usr1_at);

    if (got_usr1_at != 0 && got_usr1_at < after) {
        printf("ok: handler ran between unblock and post-write\n");
    }
    return 0;
}
