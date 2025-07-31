// ringbuffer_spsc.c
#include "ringbuffer_spsc.h"
#include <stdlib.h>
#include <string.h>

spsc_ring_t *spsc_ring_create(size_t capacity) {
    spsc_ring_t *rb = malloc(sizeof(spsc_ring_t));
    if (!rb) return NULL;

    rb->buffer = malloc(capacity);
    if (!rb->buffer) {
        free(rb);
        return NULL;
    }

    rb->capacity = capacity;
    atomic_init(&rb->head, 0);
    atomic_init(&rb->tail, 0);
    return rb;
}

void spsc_ring_destroy(spsc_ring_t *rb) {
    if (rb) {
        free(rb->buffer);
        free(rb);
    }
}

bool spsc_ring_enqueue(spsc_ring_t *rb, const void *data, size_t size) {
    if (size > rb->capacity) return false;

    size_t head = atomic_load_explicit(&rb->head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_acquire);

    size_t free_space = (tail + rb->capacity - head - 1) % rb->capacity;
    if (size > free_space) return false; // not enough space

    size_t pos = head % rb->capacity;
    size_t first_copy = rb->capacity - pos;
    if (first_copy > size) first_copy = size;

    memcpy((char *)rb->buffer + pos, data, first_copy);
    if (size > first_copy)
        memcpy(rb->buffer, (char *)data + first_copy, size - first_copy);

    atomic_store_explicit(&rb->head, (head + size) % (2 * rb->capacity), memory_order_release);
    return true;
}

bool spsc_ring_dequeue(spsc_ring_t *rb, void *data, size_t size) {
    if (size > rb->capacity) return false;

    size_t tail = atomic_load_explicit(&rb->tail, memory_order_relaxed);
    size_t head = atomic_load_explicit(&rb->head, memory_order_acquire);

    size_t available = (head + rb->capacity - tail) % rb->capacity;
    if (size > available) return false; // not enough data

    size_t pos = tail % rb->capacity;
    size_t first_copy = rb->capacity - pos;
    if (first_copy > size) first_copy = size;

    memcpy(data, (char *)rb->buffer + pos, first_copy);
    if (size > first_copy)
        memcpy((char *)data + first_copy, rb->buffer, size - first_copy);

    atomic_store_explicit(&rb->tail, (tail + size) % (2 * rb->capacity), memory_order_release);
    return true;
}
