// ringbuffer_mpsc.h
#ifndef RINGBUFFER_MPSC_H
#define RINGBUFFER_MPSC_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    void *buffer;
    size_t capacity;
    atomic_size_t head;
    atomic_size_t tail;
} mpsc_ring_t;

mpsc_ring_t *mpsc_ring_create(size_t capacity);
void mpsc_ring_destroy(mpsc_ring_t *rb);
bool mpsc_ring_enqueue(mpsc_ring_t *rb, const void *data, size_t size);
bool mpsc_ring_dequeue(mpsc_ring_t *rb, void *data, size_t size);

#endif // RINGBUFFER_MPSC_H
