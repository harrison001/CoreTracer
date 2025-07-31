#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>
#include <string.h>
#include "bind_threads.h"

#define ITERATIONS 50000000
#define PINGPONG_ITERATIONS 50000000  // Same workload for fair comparison
#define CACHE_LINE_SIZE 64

// Extreme false sharing: pack many variables in one cache line
typedef struct {
    volatile int vars[16];  // 64 bytes = 1 cache line
} extreme_false_sharing_t;

// Properly padded version
typedef struct {
    volatile int var0;
    char pad0[CACHE_LINE_SIZE - sizeof(int)];
    volatile int var1; 
    char pad1[CACHE_LINE_SIZE - sizeof(int)];
} padded_extreme_t;

// Ping-pong with memory barriers
typedef struct {
    volatile int counter;
    volatile int flag;
    char pad[CACHE_LINE_SIZE - 2*sizeof(int)];
} pingpong_t;

void *extreme_false_thread(void *arg) {
    void **args = (void**)arg;
    extreme_false_sharing_t *s = (extreme_false_sharing_t*)args[0];
    int thread_id = *(int*)args[1];
    
    bind_thread_to_core(thread_id);
    
    // Each thread works on different variables in the same cache line
    int start_var = thread_id * 4;
    
    for (int i = 0; i < ITERATIONS; i++) {
        // Access 4 consecutive variables to maximize cache line pollution
        for (int j = 0; j < 4; j++) {
            s->vars[start_var + j]++;
        }
        
        // Memory barrier to ensure visibility
        __sync_synchronize();
        
        // Add some computation to make the effect more visible
        if (i % 10000 == 0) {
            sched_yield();
        }
    }
    return NULL;
}

void *padded_extreme_thread(void *arg) {
    void **args = (void**)arg;
    padded_extreme_t *s = (padded_extreme_t*)args[0];
    int thread_id = *(int*)args[1];
    
    bind_thread_to_core(thread_id);
    
    volatile int *target = (thread_id == 0) ? &s->var0 : &s->var1;
    
    for (int i = 0; i < ITERATIONS; i++) {
        (*target)++;
        __sync_synchronize();
        
        if (i % 10000 == 0) {
            sched_yield();
        }
    }
    return NULL;
}

void *pingpong_producer(void *arg) {
    pingpong_t *s = (pingpong_t*)arg;
    bind_thread_to_core(0);
    
    for (int i = 0; i < PINGPONG_ITERATIONS; i++) {
        // Wait for consumer to be ready (busy wait to maximize cache bouncing)
        while (s->flag != 0) {
            // Busy wait - this causes maximum cache line bouncing
            __sync_synchronize();
        }
        
        // Modify the shared counter (more cache line pollution)
        s->counter++;
        __sync_synchronize();
        s->flag = 1;  // Signal consumer
        
        // Add extra work to make the effect more visible
        if (i % 1000000 == 0) {
            sched_yield();  // Occasional yield to prevent live-lock
        }
    }
    return NULL;
}

void *pingpong_consumer(void *arg) {
    pingpong_t *s = (pingpong_t*)arg;
    bind_thread_to_core(1);
    
    for (int i = 0; i < PINGPONG_ITERATIONS; i++) {
        // Wait for producer (busy wait for maximum cache bouncing)
        while (s->flag != 1) {
            __sync_synchronize();
        }
        
        // Read and modify the counter (more cache operations)
        volatile int tmp = s->counter;
        s->counter = tmp + 1;  // Extra write to increase cache pressure
        __sync_synchronize();
        s->flag = 0;  // Signal producer
        
        if (i % 1000000 == 0) {
            sched_yield();
        }
    }
    return NULL;
}

double run_test(const char *name, void *(*f1)(void*), void *(*f2)(void*), void *arg1, void *arg2) {
    pthread_t t1, t2;
    struct timespec start, end;
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    pthread_create(&t1, NULL, f1, arg1);
    pthread_create(&t2, NULL, f2, arg2);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double elapsed_ms = (end.tv_sec - start.tv_sec) * 1e3 + 
                        (end.tv_nsec - start.tv_nsec) / 1e6;
    printf("⏱️  %-20s: %8.2f ms\n", name, elapsed_ms);
    return elapsed_ms;
}

int main() {
    printf("=== Extreme Cache Performance Demo ===\n");
    printf("False Sharing & Padded: %d iterations per thread\n", ITERATIONS);
    printf("Ping-Pong: %d iterations per thread\n\n", PINGPONG_ITERATIONS);
    
    // Allocate aligned memory
    extreme_false_sharing_t *false_shared = aligned_alloc(CACHE_LINE_SIZE, sizeof(extreme_false_sharing_t));
    padded_extreme_t *padded = aligned_alloc(CACHE_LINE_SIZE, sizeof(padded_extreme_t));
    pingpong_t *pingpong = aligned_alloc(CACHE_LINE_SIZE, sizeof(pingpong_t));
    
    memset(false_shared, 0, sizeof(extreme_false_sharing_t));
    memset(padded, 0, sizeof(padded_extreme_t));
    memset(pingpong, 0, sizeof(pingpong_t));
    
    // Prepare thread arguments
    int thread0 = 0, thread1 = 1;
    void *false_args0[] = {false_shared, &thread0};
    void *false_args1[] = {false_shared, &thread1};
    void *padded_args0[] = {padded, &thread0};
    void *padded_args1[] = {padded, &thread1};
    
    printf("🔥 Test 1: Extreme False Sharing\n");
    printf("   4 threads accessing different variables in same cache line\n");
    double false_time = run_test("Extreme False Sharing", extreme_false_thread, extreme_false_thread, false_args0, false_args1);
    
    printf("\n✅ Test 2: Cache-Line Padded\n");
    printf("   2 threads accessing variables in separate cache lines\n");
    double padded_time = run_test("Cache-Line Padded", padded_extreme_thread, padded_extreme_thread, padded_args0, padded_args1);
    
    printf("\n🏓 Test 3: Cache Ping-Pong\n");
    printf("   Producer-consumer pattern with cache bouncing\n");
    double pingpong_time = run_test("Cache Ping-Pong", pingpong_producer, pingpong_consumer, pingpong, pingpong);
    
    printf("\n📊 Performance Summary:\n");
    printf("   False Sharing: %.2f ms\n", false_time);
    printf("   Padded:       %.2f ms (%.1fx faster)\n", padded_time, false_time/padded_time);
    printf("   Ping-Pong:    %.2f ms (%.1fx slower than padded)\n", pingpong_time, pingpong_time/padded_time);
    
    printf("\n🎯 Key Insights:\n");
    printf("   - False sharing creates cache coherency traffic\n");
    printf("   - Proper padding eliminates false sharing\n");
    printf("   - Ping-pong pattern shows worst-case cache bouncing\n");
    
    free(false_shared);
    free(padded);
    free(pingpong);
    return 0;
}