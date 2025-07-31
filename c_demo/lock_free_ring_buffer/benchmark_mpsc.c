// benchmark_mpsc.c
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "ringbuffer_mpsc.h"

#define THREAD_COUNT 4
#define MSG_COUNT 1000000
#define MSG_SIZE 32
#define BUFFER_CAPACITY (MSG_SIZE * 8192)

typedef struct {
    mpsc_ring_t *rb;
    int tid;
} thread_arg_t;

void *producer_thread(void *arg) {
    thread_arg_t *targ = arg;
    char msg[MSG_SIZE];
    memset(msg, 'A' + targ->tid, MSG_SIZE);

    for (int i = 0; i < MSG_COUNT; ++i) {
        while (!mpsc_ring_enqueue(targ->rb, msg, MSG_SIZE)) {
            // busy wait
        }
    }

    return NULL;
}

void *consumer_thread(void *arg) {
    mpsc_ring_t *rb = (mpsc_ring_t *)arg;
    char buf[MSG_SIZE];

    size_t total = MSG_COUNT * THREAD_COUNT;
    size_t count = 0;

    while (count < total) {
        if (mpsc_ring_dequeue(rb, buf, MSG_SIZE)) {
            count++;
        }
    }

    return NULL;
}

int main() {
    mpsc_ring_t *rb = mpsc_ring_create(BUFFER_CAPACITY);
    pthread_t producers[THREAD_COUNT], consumer;
    thread_arg_t args[THREAD_COUNT];

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    pthread_create(&consumer, NULL, consumer_thread, rb);
    for (int i = 0; i < THREAD_COUNT; ++i) {
        args[i].rb = rb;
        args[i].tid = i;
        pthread_create(&producers[i], NULL, producer_thread, &args[i]);
    }

    for (int i = 0; i < THREAD_COUNT; ++i) {
        pthread_join(producers[i], NULL);
    }
    pthread_join(consumer, NULL);

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("Processed %d messages x %d threads in %.3f seconds (%.2f M msg/s)\n",
           MSG_COUNT, THREAD_COUNT, elapsed,
           (MSG_COUNT * THREAD_COUNT) / (elapsed * 1e6));

    mpsc_ring_destroy(rb);
    return 0;
}
