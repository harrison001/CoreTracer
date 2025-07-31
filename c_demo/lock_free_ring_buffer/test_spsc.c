// test_spsc.c
#include "ringbuffer_spsc.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main() {
    const size_t capacity = 1024;
    spsc_ring_t *rb = spsc_ring_create(capacity);
    assert(rb != NULL);

    const char *msg = "hello world";
    size_t len = strlen(msg) + 1;

    bool ok = spsc_ring_enqueue(rb, msg, len);
    assert(ok);

    char recv[64] = {0};
    ok = spsc_ring_dequeue(rb, recv, len);
    assert(ok);

    printf("Received: %s\n", recv);
    assert(strcmp(recv, msg) == 0);

    spsc_ring_destroy(rb);
    printf("SPSC basic test passed.\n");
    return 0;
}
