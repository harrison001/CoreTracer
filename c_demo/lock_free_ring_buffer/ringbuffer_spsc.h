// ringbuffer_spsc.h
#pragma once
#include <stdatomic.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    void *buffer;
    size_t capacity;
    atomic_size_t head;
    atomic_size_t tail;
} spsc_ring_t;

spsc_ring_t *spsc_ring_create(size_t capacity);
void spsc_ring_destroy(spsc_ring_t *rb);

bool spsc_ring_enqueue(spsc_ring_t *rb, const void *data, size_t size);
bool spsc_ring_dequeue(spsc_ring_t *rb, void *data, size_t size);
