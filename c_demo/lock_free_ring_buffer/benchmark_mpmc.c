// benchmark_mpmc.c
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "ringbuffer_mpmc.h"

#define PRODUCER_COUNT 4
#define CONSUMER_COUNT 4
#define MSG_COUNT 1000000
#define MSG_SIZE 32
#define BUFFER_CAPACITY (MSG_SIZE * 8192)

typedef struct {
    mpmc_ring_t *rb;
    int tid;
    int msg_count;
} thread_arg_t;

void *producer_thread(void *arg) {
    thread_arg_t *targ = arg;
    char msg[MSG_SIZE];
    memset(msg, 'A' + targ->tid, MSG_SIZE);

    for (int i = 0; i < targ->msg_count; ++i) {
        while (!mpmc_ring_enqueue(targ->rb, msg, MSG_SIZE)) {
            // busy wait
        }
    }

    return NULL;
}

void *consumer_thread(void *arg) {
    thread_arg_t *targ = arg;
    char buf[MSG_SIZE];
    int received = 0;

    while (1) {
        if (mpmc_ring_dequeue(targ->rb, buf, MSG_SIZE)) {
            received++;
            if (received >= targ->msg_count) break;
        }
    }

    return NULL;
}

int main() {
    mpmc_ring_t *rb = mpmc_ring_create(BUFFER_CAPACITY);
    pthread_t producers[PRODUCER_COUNT], consumers[CONSUMER_COUNT];
    thread_arg_t prod_args[PRODUCER_COUNT], cons_args[CONSUMER_COUNT];

    int total_msgs = MSG_COUNT * PRODUCER_COUNT;
    int msgs_per_consumer = total_msgs / CONSUMER_COUNT;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < CONSUMER_COUNT; ++i) {
        cons_args[i].rb = rb;
        cons_args[i].tid = i;
        cons_args[i].msg_count = msgs_per_consumer;
        pthread_create(&consumers[i], NULL, consumer_thread, &cons_args[i]);
    }

    for (int i = 0; i < PRODUCER_COUNT; ++i) {
        prod_args[i].rb = rb;
        prod_args[i].tid = i;
        prod_args[i].msg_count = MSG_COUNT;
        pthread_create(&producers[i], NULL, producer_thread, &prod_args[i]);
    }

    for (int i = 0; i < PRODUCER_COUNT; ++i) {
        pthread_join(producers[i], NULL);
    }

    for (int i = 0; i < CONSUMER_COUNT; ++i) {
        pthread_join(consumers[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("MPMC: %d producers, %d consumers, total %d messages in %.3f sec (%.2f M msg/s)\n",
           PRODUCER_COUNT, CONSUMER_COUNT, total_msgs,
           elapsed, total_msgs / (elapsed * 1e6));

    mpmc_ring_destroy(rb);
    return 0;
}
