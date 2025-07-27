// store_buffer_demo.c
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

volatile int x = 0;
volatile int y = 0;

volatile int r1 = 0;
volatile int r2 = 0;

#define LOOP 10000000

void *thread1(void *arg) {
    for (int i = 0; i < LOOP; i++) {
        x = 1;                       // store x
        // 注释掉 fence 看 bug
        // atomic_thread_fence(memory_order_seq_cst);
        r1 = y;                      // load y
        x = 0;                       // reset
    }
    return NULL;
}

void *thread2(void *arg) {
    for (int i = 0; i < LOOP; i++) {
        y = 1;                       // store y
        // 注释掉 fence 看 bug
        // atomic_thread_fence(memory_order_seq_cst);
        r2 = x;                      // load x
        y = 0;                       // reset
    }
    return NULL;
}

int main() {
    pthread_t t1, t2;
    int bug_count = 0;

    for (int run = 0; run < 100; run++) {
        x = y = r1 = r2 = 0;

        pthread_create(&t1, NULL, thread1, NULL);
        pthread_create(&t2, NULL, thread2, NULL);

        pthread_join(t1, NULL);
        pthread_join(t2, NULL);

        if (r1 == 0 && r2 == 0) {
            bug_count++;
            printf("🔥 BUG: saw r1=0 && r2=0 (iteration %d)\n", run);
        } else {
            printf("OK: r1=%d, r2=%d\n", r1, r2);
        }
    }

    printf("Done. BUG count=%d/10\n", bug_count);
    return 0;
}
