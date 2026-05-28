// condtest — producer/consumer with pthread_cond_t.
//
// Producer pushes 10 items to a 4-slot ring; consumer pulls them. The
// test exercises pthread_cond_wait/signal which are built on futex.
// Expected: prints sum=45 and PASS.
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define N_ITEMS 10
#define RING_SZ 4

static int ring[RING_SZ];
static int head = 0, tail = 0, n = 0;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  not_full = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  not_empty = PTHREAD_COND_INITIALIZER;

static int sum = 0;

static void *producer(void *arg) {
    (void)arg;
    for (int i = 0; i < N_ITEMS; i++) {
        pthread_mutex_lock(&mtx);
        while (n == RING_SZ) {
            pthread_cond_wait(&not_full, &mtx);
        }
        ring[head] = i;
        head = (head + 1) % RING_SZ;
        n++;
        printf("producer: pushed %d (n=%d)\n", i, n);
        pthread_cond_signal(&not_empty);
        pthread_mutex_unlock(&mtx);
    }
    return NULL;
}

static void *consumer(void *arg) {
    (void)arg;
    for (int i = 0; i < N_ITEMS; i++) {
        pthread_mutex_lock(&mtx);
        while (n == 0) {
            pthread_cond_wait(&not_empty, &mtx);
        }
        int v = ring[tail];
        tail = (tail + 1) % RING_SZ;
        n--;
        sum += v;
        printf("consumer: popped %d (n=%d sum=%d)\n", v, n, sum);
        pthread_cond_signal(&not_full);
        pthread_mutex_unlock(&mtx);
    }
    return NULL;
}

int main(void) {
    pthread_t p, c;
    pthread_create(&p, NULL, producer, NULL);
    pthread_create(&c, NULL, consumer, NULL);
    pthread_join(p, NULL);
    pthread_join(c, NULL);
    printf("sum=%d\n", sum);
    int expected = N_ITEMS * (N_ITEMS - 1) / 2;
    if (sum == expected) {
        printf("PASS\n");
        return 0;
    } else {
        printf("FAIL: expected %d\n", expected);
        return 1;
    }
}
