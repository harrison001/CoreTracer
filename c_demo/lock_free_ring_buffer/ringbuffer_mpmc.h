// ringbuffer_mpmc.h
#ifndef RINGBUFFER_MPMC_H
#define RINGBUFFER_MPMC_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// 单个槽结构体
typedef struct {
    atomic_size_t seq;
    void *data;
} mpmc_slot_t;

typedef struct {
    size_t capacity;
    mpmc_slot_t *buffer;

    atomic_size_t head;
    atomic_size_t tail;
} mpmc_ring_t;

mpmc_ring_t *mpmc_ring_create(size_t capacity);
void mpmc_ring_destroy(mpmc_ring_t *rb);

bool mpmc_ring_enqueue(mpmc_ring_t *rb, void *data);
bool mpmc_ring_dequeue(mpmc_ring_t *rb, void **data);

#endif // RINGBUFFER_MPMC_H
