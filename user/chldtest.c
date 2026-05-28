/* chldtest: fork, child exits 42; parent installs SIGCHLD handler that
 * prints "child sig", parent wait4s.
 *
 * Expected output (order may interleave but both lines appear):
 *     child sig
 *     reaped child status=42
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

static volatile int got_chld = 0;

static void on_chld(int signo) {
    (void)signo;
    /* printf in a signal handler is not strictly async-safe, but musl's
     * vfprintf is reentrant enough for our test. */
    printf("child sig\n");
    fflush(stdout);
    got_chld = 1;
}

int main(void) {
    struct sigaction sa = { 0 };
    sa.sa_handler = on_chld;
    sigaction(SIGCHLD, &sa, NULL);

    pid_t pid = fork();
    if (pid < 0) {
        printf("fork failed\n");
        return 1;
    }
    if (pid == 0) {
        /* child */
        _exit(42);
    }
    /* parent */
    int status = 0;
    pid_t r = wait(&status);
    if (r != pid) {
        printf("wait returned %d, expected %d\n", (int)r, (int)pid);
        return 1;
    }
    int exited = WIFEXITED(status);
    int code = WEXITSTATUS(status);
    printf("reaped child status=%d exited=%d got_chld=%d\n",
        code, exited, got_chld);
    fflush(stdout);
    return 0;
}
