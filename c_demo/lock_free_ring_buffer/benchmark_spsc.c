// benchmark_spsc.c
#include "ringbuffer_spsc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#define MSG_SIZE 64
#define COUNT    1000000

typedef struct {
    spsc_ring_t *rb;
    const char *msg;
} thread_arg_t;

void *producer(void *arg) {
    thread_arg_t *targ = arg;
    for (int i = 0; i < COUNT; ++i) {
        while (!spsc_ring_enqueue(targ->rb, targ->msg, MSG_SIZE));
    }
    return NULL;
}

void *consumer(void *arg) {
    thread_arg_t *targ = arg;
    char tmp[MSG_SIZE];
    for (int i = 0; i < COUNT; ++i) {
        while (!spsc_ring_dequeue(targ->rb, tmp, MSG_SIZE));
    }
    return NULL;
}

int main() {
    spsc_ring_t *rb = spsc_ring_create(1 << 16);
    const char *msg = "benchmark_message_payload_____________________________";
    thread_arg_t arg = {rb, msg};

    pthread_t prod, cons;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    pthread_create(&prod, NULL, producer, &arg);
    pthread_create(&cons, NULL, consumer, &arg);

    pthread_join(prod, NULL);
    pthread_join(cons, NULL);

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + 
                     (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Transferred %d messages in %.4f seconds (%.2f ops/sec)\n",
           COUNT, elapsed, COUNT / elapsed);

    spsc_ring_destroy(rb);
    return 0;
}
