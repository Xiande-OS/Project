/* Verify SIGPIPE delivery when writing to a pipe with closed read end. */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

static volatile int got_pipe = 0;

static void on_pipe(int signo) {
    (void)signo;
    got_pipe = 1;
}

int main(void) {
    struct sigaction sa = { 0 };
    sa.sa_handler = on_pipe;
    sigaction(SIGPIPE, &sa, NULL);

    int fds[2];
    if (pipe(fds) != 0) {
        printf("pipe failed\n");
        return 1;
    }
    close(fds[0]);  /* close read end */

    int r = write(fds[1], "x", 1);
    int e = errno;
    printf("write=%d errno=%d got_pipe=%d\n", r, e, got_pipe);
    fflush(stdout);
    return 0;
}
