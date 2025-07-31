// test_ringbuffer_mpmc.c
#include "ringbuffer_mpmc.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>
#include <time.h>

#define THREAD_PRODUCERS 4
#define THREAD_CONSUMERS 4
#define ITEMS_PER_PRODUCER 100000
#define ITEM_SIZE 8

mpmc_ring_t *g_ring;
atomic_int g_produce_count;
atomic_int g_consume_count;

void *producer_thread(void *arg) {
    int id = (intptr_t)arg;
    char data[ITEM_SIZE];
    memset(data, 'A' + id, ITEM_SIZE);

    for (int i = 0; i < ITEMS_PER_PRODUCER; ++i) {
        while (!mpmc_ring_enqueue(g_ring, data, ITEM_SIZE)) {
            sched_yield();
        }
        atomic_fetch_add(&g_produce_count, 1);
    }
    return NULL;
}

void *consumer_thread(void *arg) {
    (void)arg;
    char data[ITEM_SIZE];

    for (;;) {
        if (atomic_load(&g_consume_count) >= THREAD_PRODUCERS * ITEMS_PER_PRODUCER)
            break;

        if (mpmc_ring_dequeue(g_ring, data, ITEM_SIZE)) {
            atomic_fetch_add(&g_consume_count, 1);
        } else {
            sched_yield();
        }
    }
    return NULL;
}

int main() {
    g_ring = mpmc_ring_create(1024 * ITEM_SIZE);
    if (!g_ring) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    atomic_init(&g_produce_count, 0);
    atomic_init(&g_consume_count, 0);

    pthread_t producers[THREAD_PRODUCERS];
    pthread_t consumers[THREAD_CONSUMERS];

    clock_t start = clock();

    for (int i = 0; i < THREAD_PRODUCERS; ++i)
        pthread_create(&producers[i], NULL, producer_thread, (void *)(intptr_t)i);

    for (int i = 0; i < THREAD_CONSUMERS; ++i)
        pthread_create(&consumers[i], NULL, consumer_thread, NULL);

    for (int i = 0; i < THREAD_PRODUCERS; ++i)
        pthread_join(producers[i], NULL);
    for (int i = 0; i < THREAD_CONSUMERS; ++i)
        pthread_join(consumers[i], NULL);

    clock_t end = clock();
    double duration = (double)(end - start) / CLOCKS_PER_SEC;

    printf("Produced: %d, Consumed: %d\n", g_produce_count, g_consume_count);
    printf("Time elapsed: %.2f seconds\n", duration);

    mpmc_ring_destroy(g_ring);
    return 0;
}

