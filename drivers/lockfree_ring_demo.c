/*
 * Lock-free Ring Buffer Demonstration Kernel Module
 * 
 * This module demonstrates lock-free data structures using atomic operations
 * and memory barriers. It implements a single-producer single-consumer ring
 * buffer to showcase race conditions and synchronization issues.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <linux/time.h>

#define MODULE_NAME "lockfree_ring_demo"
#define PROC_NAME "lockfree_ring"
#define RING_SIZE 4096
#define TEST_DURATION_MS 5000
#define MAX_DATA_VALUE 0xDEADBEEF

struct lockfree_ring {
    volatile u32 *buffer;
    atomic_t head;          // Producer index
    atomic_t tail;          // Consumer index
    u32 size;
    u32 mask;              // size - 1, for fast modulo
};

static struct lockfree_ring *ring;
static struct task_struct *producer_thread;
static struct task_struct *consumer_thread;
static atomic_t test_running;
static atomic_t producer_count;
static atomic_t consumer_count;
static atomic_t race_detected;
static atomic_t overrun_count;
static atomic_t underrun_count;

// Statistics
struct ring_stats {
    u64 total_produced;
    u64 total_consumed;
    u64 max_queue_depth;
    u64 races_detected;
    u64 overruns;
    u64 underruns;
    cycles_t start_time;
    cycles_t end_time;
};

static struct ring_stats stats;

static inline u32 ring_count(struct lockfree_ring *ring)
{
    u32 head = atomic_read(&ring->head);
    u32 tail = atomic_read(&ring->tail);
    return (head - tail) & ring->mask;
}

static inline bool ring_is_full(struct lockfree_ring *ring)
{
    u32 head = atomic_read(&ring->head);
    u32 tail = atomic_read(&ring->tail);
    return ((head + 1) & ring->mask) == (tail & ring->mask);
}

static inline bool ring_is_empty(struct lockfree_ring *ring)
{
    u32 head = atomic_read(&ring->head);
    u32 tail = atomic_read(&ring->tail);
    return (head & ring->mask) == (tail & ring->mask);
}

// Lock-free enqueue (producer)
static int ring_enqueue(struct lockfree_ring *ring, u32 data)
{
    u32 head, next_head;
    
    do {
        head = atomic_read(&ring->head);
        next_head = (head + 1) & ring->mask;
        
        // Check if ring is full
        if (next_head == (atomic_read(&ring->tail) & ring->mask)) {
            atomic_inc(&overrun_count);
            return -ENOSPC;
        }
        
        // Try to reserve the slot
    } while (!atomic_cmpxchg(&ring->head, head, next_head));
    
    // Write data to reserved slot
    ring->buffer[head & ring->mask] = data;
    
    // Memory barrier to ensure data is written before advancing
    smp_wmb();
    
    return 0;
}

// Lock-free dequeue (consumer)
static int ring_dequeue(struct lockfree_ring *ring, u32 *data)
{
    u32 tail, next_tail;
    
    do {
        tail = atomic_read(&ring->tail);
        
        // Check if ring is empty
        if ((tail & ring->mask) == (atomic_read(&ring->head) & ring->mask)) {
            atomic_inc(&underrun_count);
            return -ENODATA;
        }
        
        next_tail = (tail + 1) & ring->mask;
        
        // Try to reserve the slot
    } while (!atomic_cmpxchg(&ring->tail, tail, next_tail));
    
    // Memory barrier to ensure we read after advancing
    smp_rmb();
    
    // Read data from slot
    *data = ring->buffer[tail & ring->mask];
    
    // Detect corruption (simple data integrity check)
    if (*data > MAX_DATA_VALUE) {
        atomic_inc(&race_detected);
        pr_warn("Data corruption detected: 0x%x\n", *data);
    }
    
    return 0;
}

static int producer_func(void *data)
{
    u32 produced = 0;
    u32 value = 1;
    unsigned long start_jiffies = jiffies;
    
    pr_info("Producer thread started\n");
    
    while (!kthread_should_stop() && 
           time_before(jiffies, start_jiffies + msecs_to_jiffies(TEST_DURATION_MS))) {
        
        // Vary the data to detect corruption
        value = (value * 1103515245 + 12345) & 0x7FFFFFFF;
        if (value > MAX_DATA_VALUE) value = value % MAX_DATA_VALUE;
        
        if (ring_enqueue(ring, value) == 0) {
            produced++;
            atomic_inc(&producer_count);
            
            // Update max queue depth
            u32 depth = ring_count(ring);
            if (depth > stats.max_queue_depth)
                stats.max_queue_depth = depth;
        }
        
        // Random delay to create interesting race conditions
        if (produced % 100 == 0) {
            usleep_range(1, 10);
        }
        
        cond_resched();
    }
    
    stats.total_produced = produced;
    pr_info("Producer finished: %u items produced\n", produced);
    return 0;
}

static int consumer_func(void *data)
{
    u32 consumed = 0;
    u32 value;
    u32 expected = 0;
    unsigned long start_jiffies = jiffies;
    
    pr_info("Consumer thread started\n");
    
    while (!kthread_should_stop() && 
           (atomic_read(&test_running) || !ring_is_empty(ring))) {
        
        if (ring_dequeue(ring, &value) == 0) {
            consumed++;
            atomic_inc(&consumer_count);
            
            // Basic sequence checking (optional)
            if (expected > 0 && value != expected + 1) {
                // Note: This might trigger false positives due to random values
                // In a real scenario, you'd use sequence numbers
            }
            expected = value;
        } else {
            // Ring empty, small delay
            usleep_range(1, 5);
        }
        
        // Random delay to create race conditions
        if (consumed % 100 == 0) {
            usleep_range(1, 10);
        }
        
        cond_resched();
    }
    
    stats.total_consumed = consumed;
    pr_info("Consumer finished: %u items consumed\n", consumed);
    return 0;
}

static int start_ring_test(void)
{
    if (atomic_read(&test_running)) {
        pr_warn("Test already running\n");
        return -EBUSY;
    }
    
    // Initialize ring buffer
    ring = kzalloc(sizeof(*ring), GFP_KERNEL);
    if (!ring) {
        pr_err("Failed to allocate ring structure\n");
        return -ENOMEM;
    }
    
    ring->buffer = kzalloc(RING_SIZE * sizeof(u32), GFP_KERNEL);
    if (!ring->buffer) {
        pr_err("Failed to allocate ring buffer\n");
        kfree(ring);
        return -ENOMEM;
    }
    
    ring->size = RING_SIZE;
    ring->mask = RING_SIZE - 1;  // Assumes RING_SIZE is power of 2
    atomic_set(&ring->head, 0);
    atomic_set(&ring->tail, 0);
    
    // Initialize statistics
    memset(&stats, 0, sizeof(stats));
    atomic_set(&producer_count, 0);
    atomic_set(&consumer_count, 0);
    atomic_set(&race_detected, 0);
    atomic_set(&overrun_count, 0);
    atomic_set(&underrun_count, 0);
    
    stats.start_time = get_cycles();
    atomic_set(&test_running, 1);
    
    // Start producer thread
    producer_thread = kthread_create(producer_func, NULL, "ring_producer");
    if (IS_ERR(producer_thread)) {
        pr_err("Failed to create producer thread\n");
        goto cleanup;
    }
    
    // Start consumer thread
    consumer_thread = kthread_create(consumer_func, NULL, "ring_consumer");
    if (IS_ERR(consumer_thread)) {
        pr_err("Failed to create consumer thread\n");
        kthread_stop(producer_thread);
        goto cleanup;
    }
    
    wake_up_process(producer_thread);
    wake_up_process(consumer_thread);
    
    pr_info("Lock-free ring test started\n");
    return 0;

cleanup:
    atomic_set(&test_running, 0);
    if (ring) {
        kfree(ring->buffer);
        kfree(ring);
        ring = NULL;
    }
    return -ENOMEM;
}

static void stop_ring_test(void)
{
    if (!atomic_read(&test_running))
        return;
    
    atomic_set(&test_running, 0);
    stats.end_time = get_cycles();
    
    if (producer_thread) {
        kthread_stop(producer_thread);
        producer_thread = NULL;
    }
    
    if (consumer_thread) {
        kthread_stop(consumer_thread);
        consumer_thread = NULL;
    }
    
    // Collect final statistics
    stats.races_detected = atomic_read(&race_detected);
    stats.overruns = atomic_read(&overrun_count);
    stats.underruns = atomic_read(&underrun_count);
    
    if (ring) {
        kfree(ring->buffer);
        kfree(ring);
        ring = NULL;
    }
    
    pr_info("Lock-free ring test stopped\n");
}

static int lockfree_ring_show(struct seq_file *m, void *v)
{
    u64 duration_cycles;
    u32 current_depth = 0;
    
    seq_printf(m, "=== Lock-free Ring Buffer Demo ===\n\n");
    
    seq_printf(m, "Configuration:\n");
    seq_printf(m, "  Ring Size: %d entries\n", RING_SIZE);
    seq_printf(m, "  Test Duration: %d ms\n", TEST_DURATION_MS);
    seq_printf(m, "  Test Status: %s\n\n", 
               atomic_read(&test_running) ? "RUNNING" : "STOPPED");
    
    if (ring) {
        current_depth = ring_count(ring);
        seq_printf(m, "Current Ring State:\n");
        seq_printf(m, "  Head: %u\n", atomic_read(&ring->head));
        seq_printf(m, "  Tail: %u\n", atomic_read(&ring->tail));
        seq_printf(m, "  Current Depth: %u\n", current_depth);
        seq_printf(m, "  Is Full: %s\n", ring_is_full(ring) ? "Yes" : "No");
        seq_printf(m, "  Is Empty: %s\n\n", ring_is_empty(ring) ? "Yes" : "No");
    }
    
    seq_printf(m, "Live Counters:\n");
    seq_printf(m, "  Items Produced: %d\n", atomic_read(&producer_count));
    seq_printf(m, "  Items Consumed: %d\n", atomic_read(&consumer_count));
    seq_printf(m, "  Overruns: %d\n", atomic_read(&overrun_count));
    seq_printf(m, "  Underruns: %d\n", atomic_read(&underrun_count));
    seq_printf(m, "  Races Detected: %d\n\n", atomic_read(&race_detected));
    
    if (stats.end_time > stats.start_time) {
        duration_cycles = stats.end_time - stats.start_time;
        seq_printf(m, "Final Statistics:\n");
        seq_printf(m, "  Total Produced: %llu\n", stats.total_produced);
        seq_printf(m, "  Total Consumed: %llu\n", stats.total_consumed);
        seq_printf(m, "  Max Queue Depth: %llu\n", stats.max_queue_depth);
        seq_printf(m, "  Duration (cycles): %llu\n", duration_cycles);
        seq_printf(m, "  Throughput: ~%llu items/cycle\n", 
                   duration_cycles > 0 ? stats.total_consumed / duration_cycles : 0);
    }
    
    seq_printf(m, "\nCommands:\n");
    seq_printf(m, "  echo 'start' > /proc/%s  # Start ring test\n", PROC_NAME);
    seq_printf(m, "  echo 'stop'  > /proc/%s  # Stop test\n", PROC_NAME);
    
    seq_printf(m, "\nDebugging Tips:\n");
    seq_printf(m, "  - Use 'perf record -e cache-misses,cache-references' during test\n");
    seq_printf(m, "  - Monitor with 'cat /proc/interrupts' for context switches\n");
    seq_printf(m, "  - Check dmesg for race condition warnings\n");
    seq_printf(m, "  - Use lockdep and KASAN for advanced debugging\n");
    
    return 0;
}

static int lockfree_ring_open(struct inode *inode, struct file *file)
{
    return single_open(file, lockfree_ring_show, NULL);
}

static ssize_t lockfree_ring_write(struct file *file, const char __user *buffer,
                                  size_t count, loff_t *pos)
{
    char cmd[16];
    
    if (count >= sizeof(cmd))
        return -EINVAL;
    
    if (copy_from_user(cmd, buffer, count))
        return -EFAULT;
    
    cmd[count] = '\0';
    
    if (strncmp(cmd, "start", 5) == 0) {
        int ret = start_ring_test();
        if (ret)
            return ret;
        pr_info("Lock-free ring test started\n");
    } else if (strncmp(cmd, "stop", 4) == 0) {
        stop_ring_test();
    } else {
        return -EINVAL;
    }
    
    return count;
}

static const struct proc_ops lockfree_ring_proc_ops = {
    .proc_open = lockfree_ring_open,
    .proc_read = seq_read,
    .proc_write = lockfree_ring_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *proc_entry;

static int __init lockfree_ring_init(void)
{
    // Ensure RING_SIZE is power of 2
    if (RING_SIZE & (RING_SIZE - 1)) {
        pr_err("RING_SIZE must be power of 2\n");
        return -EINVAL;
    }
    
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &lockfree_ring_proc_ops);
    if (!proc_entry) {
        pr_err("Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }
    
    atomic_set(&test_running, 0);
    
    pr_info("Lock-free ring buffer demo module loaded\n");
    pr_info("Access via: cat /proc/%s\n", PROC_NAME);
    
    return 0;
}

static void __exit lockfree_ring_exit(void)
{
    stop_ring_test();
    
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    
    pr_info("Lock-free ring buffer demo module unloaded\n");
}

module_init(lockfree_ring_init);
module_exit(lockfree_ring_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CoreTracer Project");
MODULE_DESCRIPTION("Lock-free ring buffer performance and race condition demonstration");
MODULE_VERSION("1.0");