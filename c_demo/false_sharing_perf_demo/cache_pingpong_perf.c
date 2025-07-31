#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>
#include "bind_threads.h"

#define ITERATIONS 10000000
#define CACHE_LINE_SIZE 64
#define PING_PONG_ROUNDS 1000000

typedef struct {
    volatile int a;
    volatile int b;
} shared_false_t;

typedef struct {
    volatile int counter;
    volatile int ready;
    volatile int done;
} shared_pingpong_t;

typedef struct {
    volatile int a;
    char padding[CACHE_LINE_SIZE - sizeof(int)];
    volatile int b;
} padded_t;

// Lightweight work to emphasize cache effects
void light_work(volatile int *ptr) {
    (*ptr)++;
}

// False sharing: two threads modify adjacent variables in same cache line
void *false_sharing_thread1(void *arg) {
    bind_thread_to_core(0);
    shared_false_t *s = (shared_false_t *)arg;
    // Wait for both threads to be ready
    while (!s->b) sched_yield();
    for (int i = 0; i < ITERATIONS; i++) {
        light_work(&s->a);
        // Add some memory barriers to ensure visibility
        __sync_synchronize();
    }
    return NULL;
}

void *false_sharing_thread2(void *arg) {
    bind_thread_to_core(1);
    shared_false_t *s = (shared_false_t *)arg;
    s->b = 1; // Signal ready
    for (int i = 0; i < ITERATIONS; i++) {
        light_work(&s->b);
        __sync_synchronize();
    }
    return NULL;
}

// True ping-pong: threads alternate modifying the same variable
void *pingpong_thread1(void *arg) {
    bind_thread_to_core(0);
    shared_pingpong_t *s = (shared_pingpong_t *)arg;
    
    while (!s->ready) sched_yield(); // Wait for thread2 to be ready
    
    for (int i = 0; i < PING_PONG_ROUNDS; i++) {
        // Wait for our turn (counter should be even)
        while (s->counter % 2 != 0 && !s->done) sched_yield();
        if (s->done) break;
        
        s->counter++;
        __sync_synchronize();
    }
    s->done = 1;
    return NULL;
}

void *pingpong_thread2(void *arg) {
    bind_thread_to_core(1);
    shared_pingpong_t *s = (shared_pingpong_t *)arg;
    s->ready = 1; // Signal ready
    
    for (int i = 0; i < PING_PONG_ROUNDS; i++) {
        // Wait for our turn (counter should be odd)
        while (s->counter % 2 != 1 && !s->done) sched_yield();
        if (s->done) break;
        
        s->counter++;
        __sync_synchronize();
    }
    s->done = 1;
    return NULL;
}

// Independent access: each thread works on separate cache lines
void *padded_thread1(void *arg) {
    bind_thread_to_core(0);
    padded_t *s = (padded_t *)arg;
    // Wait for both threads to be ready
    while (!s->b) sched_yield();
    for (int i = 0; i < ITERATIONS; i++) {
        light_work(&s->a);
        __sync_synchronize();
    }
    return NULL;
}

void *padded_thread2(void *arg) {
    bind_thread_to_core(1);
    padded_t *s = (padded_t *)arg;
    s->b = 1; // Signal ready
    for (int i = 0; i < ITERATIONS; i++) {
        light_work(&s->b);
        __sync_synchronize();
    }
    return NULL;
}

void run_test(const char *label, void *(*f1)(void *), void *(*f2)(void *), void *shared) {
    pthread_t t1, t2;
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);
    pthread_create(&t1, NULL, f1, shared);
    pthread_create(&t2, NULL, f2, shared);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed_ms = (end.tv_sec - start.tv_sec) * 1e3 +
                        (end.tv_nsec - start.tv_nsec) / 1e6;
    printf("⏱️  %s time: %.2f ms\n", label, elapsed_ms);
}

int main() {
    shared_false_t *fs = aligned_alloc(CACHE_LINE_SIZE, sizeof(shared_false_t));
    shared_pingpong_t *pp = aligned_alloc(CACHE_LINE_SIZE, sizeof(shared_pingpong_t));
    padded_t *pad = aligned_alloc(CACHE_LINE_SIZE, sizeof(padded_t));
    
    // Initialize structures
    fs->a = fs->b = 0;
    pp->counter = pp->ready = pp->done = 0;
    pad->a = pad->b = 0;

    printf("=== Enhanced Cache Performance Demo ===\n");
    printf("Iterations: %d (False Sharing & Padded), %d (Ping-Pong)\n\n", 
           ITERATIONS, PING_PONG_ROUNDS);
    
    // Test 1: False sharing - two threads modify adjacent variables
    printf("📍 False Sharing Test:\n");
    printf("   Two threads modify adjacent int variables in same cache line\n");
    printf("   Expected: High cache miss rate due to false sharing\n");
    run_test("False Sharing", false_sharing_thread1, false_sharing_thread2, fs);
    
    // Reset for ping-pong test
    pp->counter = pp->ready = pp->done = 0;
    
    // Test 2: True ping-pong - threads alternate on same variable
    printf("\n🏓 Cache Ping-Pong Test:\n");
    printf("   Two threads alternate modifying the same variable\n");
    printf("   Expected: Severe cache bouncing between cores\n");
    run_test("Cache Ping-Pong", pingpong_thread1, pingpong_thread2, pp);
    
    // Test 3: Padded - separated by cache line boundaries
    printf("\n✅ Cache-Line Padded Test:\n");
    printf("   Two threads modify variables in separate cache lines\n");
    printf("   Expected: Minimal cache interference\n");
    run_test("Cache-Line Padded", padded_thread1, padded_thread2, pad);

    printf("\n📊 Performance Analysis:\n");
    printf("   - False Sharing should be slower than Padded\n");
    printf("   - Ping-Pong should be the slowest due to cache bouncing\n");
    printf("   - Padded should be the fastest with minimal cache conflicts\n");

    free(fs); free(pp); free(pad);
    return 0;
}
