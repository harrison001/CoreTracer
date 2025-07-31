#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define N (1024 * 1024 * 256)  // 256M elements (~1GB)
#define REPEAT 1               // Adjustable, repeat access count

static int *arr;           // Large array
static size_t *index_seq;  // Access sequence array (sequential or random)

// Generate random access sequence
void shuffle(size_t *idx, size_t n) {
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = rand() % (i + 1);
        size_t tmp = idx[i];
        idx[i] = idx[j];
        idx[j] = tmp;
    }
}

double timed_access(size_t *seq, size_t n) {
    volatile long long sum = 0;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int r = 0; r < REPEAT; r++) {
        for (size_t i = 0; i < n; i++) {
            sum += arr[seq[i]];
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) * 1e3 +
                     (end.tv_nsec - start.tv_nsec) / 1e6;
    // Prevent compiler from optimizing away access
    if (sum == 42) printf("sum=%lld\n", sum);
    return elapsed;
}

int main() {
    srand(0xC0FFEE);

    size_t elements = N;
    size_t bytes = elements * sizeof(int);

    printf("Allocating %.2f MB...\n", bytes / 1024.0 / 1024.0);
    arr = malloc(bytes);
    if (!arr) { perror("malloc arr"); return 1; }
    index_seq = malloc(elements * sizeof(size_t));
    if (!index_seq) { perror("malloc seq"); return 1; }

    // Initialize array
    for (size_t i = 0; i < elements; i++) {
        arr[i] = (int)i;
        index_seq[i] = i;
    }

    printf("\n=== Sequential Access ===\n");
    double t_seq = timed_access(index_seq, elements);
    printf("Time: %.2f ms\n", t_seq);

    printf("\n=== Random Access ===\n");
    shuffle(index_seq, elements);
    double t_rand = timed_access(index_seq, elements);
    printf("Time: %.2f ms\n", t_rand);

    printf("\nSlowdown (Random vs Sequential): %.2fx\n", t_rand / t_seq);

    free(arr);
    free(index_seq);
    return 0;
}
