// test_mpsc.c
#include <stdio.h>
#include <string.h>
#include "ringbuffer_mpsc.h"

int main() {
    mpsc_ring_t *rb = mpsc_ring_create(1024);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    const char *msg = "Hello MPSC Ring!";
    char buffer[64] = {0};

    if (!mpsc_ring_enqueue(rb, msg, strlen(msg) + 1)) {
        printf("Enqueue failed\n");
    }

    if (!mpsc_ring_dequeue(rb, buffer, strlen(msg) + 1)) {
        printf("Dequeue failed\n");
    }

    printf("Dequeued message: %s\n", buffer);

    mpsc_ring_destroy(rb);
    return 0;
}
