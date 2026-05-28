// pthtest — 4 worker threads each bump a shared counter 1000 times
// under a pthread_mutex. Main joins all of them and prints the total.
// Expected output: counter = 4000
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define N_WORKERS 4
#define N_BUMPS   1000

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static int counter = 0;

static void *worker(void *arg) {
    long who = (long)arg;
    pid_t tid = (pid_t)syscall(SYS_gettid);
    printf("worker %ld tid=%d starting\n", who, tid);
    for (int i = 0; i < N_BUMPS; i++) {
        pthread_mutex_lock(&mtx);
        counter++;
        pthread_mutex_unlock(&mtx);
    }
    printf("worker %ld done\n", who);
    return NULL;
}

int main(void) {
    pthread_t t[N_WORKERS];
    pid_t main_tid = (pid_t)syscall(SYS_gettid);
    printf("main tid=%d pid=%d\n", main_tid, getpid());
    for (long i = 0; i < N_WORKERS; i++) {
        if (pthread_create(&t[i], NULL, worker, (void *)i) != 0) {
            perror("pthread_create");
            return 1;
        }
    }
    for (int i = 0; i < N_WORKERS; i++) {
        pthread_join(t[i], NULL);
    }
    printf("counter = %d\n", counter);
    if (counter == N_WORKERS * N_BUMPS) {
        printf("PASS\n");
        return 0;
    } else {
        printf("FAIL: expected %d\n", N_WORKERS * N_BUMPS);
        return 1;
    }
}
