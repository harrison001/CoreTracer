/*
 * Memory Bank Conflict Demonstration Kernel Module
 * 
 * This module demonstrates memory bank conflicts by creating access patterns
 * that force memory controllers to serialize accesses, reducing memory
 * bandwidth and increasing latency.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/time.h>
#include <linux/random.h>
#include <linux/vmalloc.h>

#define MODULE_NAME "bank_conflict_demo"
#define PROC_NAME "bank_conflict"
#define ARRAY_SIZE_MB 64
#define ARRAY_SIZE (ARRAY_SIZE_MB * 1024 * 1024 / sizeof(u64))
#define NUM_THREADS 4
#define TEST_ITERATIONS 100000

// Typical bank interleaving - many systems use 64-byte or 256-byte granularity
#define BANK_SIZE 4096  // 4KB bank size (common)
#define STRIDE_CONFLICT (BANK_SIZE / sizeof(u64))  // Access same bank
#define STRIDE_SEQUENTIAL 1  // Sequential access
#define STRIDE_RANDOM 0  // Random access

static u64 *test_array;
static struct task_struct *worker_threads[NUM_THREADS];
static bool test_running = false;
static int access_pattern = 0;  // 0=sequential, 1=bank_conflict, 2=random

struct thread_data {
    int thread_id;
    int pattern;
    u64 start_offset;
    cycles_t start_time;
    cycles_t end_time;
    u64 bytes_accessed;
    u64 cache_misses;
};

static struct thread_data thread_results[NUM_THREADS];

// Memory access patterns to demonstrate bank conflicts
static int bank_conflict_worker(void *data)
{
    struct thread_data *tdata = (struct thread_data *)data;
    u64 *array = test_array;
    u64 offset = tdata->start_offset;
    u64 stride;
    u64 sum = 0;
    int i;
    
    if (!array) {
        pr_err("Test array not allocated\n");
        return -ENOMEM;
    }
    
    tdata->start_time = get_cycles();
    
    // Determine access pattern
    switch (tdata->pattern) {
        case 0: // Sequential access - good for prefetching
            stride = STRIDE_SEQUENTIAL;
            pr_info("Thread %d: Sequential access pattern\n", tdata->thread_id);
            break;
        case 1: // Bank conflict pattern - same bank, different rows
            stride = STRIDE_CONFLICT;
            pr_info("Thread %d: Bank conflict access pattern (stride %llu)\n", 
                    tdata->thread_id, stride);
            break;
        case 2: // Random access - worst case for everything
            stride = 0; // Will be calculated randomly
            pr_info("Thread %d: Random access pattern\n", tdata->thread_id);
            break;
        default:
            stride = STRIDE_SEQUENTIAL;
            break;
    }
    
    // Main access loop
    for (i = 0; i < TEST_ITERATIONS && !kthread_should_stop(); i++) {
        if (tdata->pattern == 2) {
            // Random access
            offset = prandom_u32() % (ARRAY_SIZE - 1);
        } else {
            // Strided access
            offset = (offset + stride) % (ARRAY_SIZE - 1);
        }
        
        // Memory access that should stress the memory controller
        // Read-modify-write to ensure memory traffic
        volatile u64 value = array[offset];
        value = value ^ 0xDEADBEEFCAFEBABE;  // Bit manipulation
        array[offset] = value;
        sum += value;  // Accumulate to prevent optimization
        
        tdata->bytes_accessed += sizeof(u64) * 2;  // Read + Write
        
        // Create bank conflicts by accessing multiple locations in same bank
        if (tdata->pattern == 1 && i % 4 == 0) {
            // Access multiple offsets that map to same bank
            u64 bank_offset1 = offset;
            u64 bank_offset2 = (offset + STRIDE_CONFLICT) % (ARRAY_SIZE - 1);
            u64 bank_offset3 = (offset + 2 * STRIDE_CONFLICT) % (ARRAY_SIZE - 1);
            u64 bank_offset4 = (offset + 3 * STRIDE_CONFLICT) % (ARRAY_SIZE - 1);
            
            // These accesses should conflict in the same memory bank
            volatile u64 v1 = array[bank_offset1];
            volatile u64 v2 = array[bank_offset2];
            volatile u64 v3 = array[bank_offset3];
            volatile u64 v4 = array[bank_offset4];
            
            array[bank_offset1] = v1 + 1;
            array[bank_offset2] = v2 + 1;
            array[bank_offset3] = v3 + 1;
            array[bank_offset4] = v4 + 1;
            
            tdata->bytes_accessed += sizeof(u64) * 8;  // 4 reads + 4 writes
        }
        
        // Yield periodically
        if (i % 10000 == 0) {
            cond_resched();
        }
    }
    
    tdata->end_time = get_cycles();
    
    pr_info("Thread %d completed: %llu cycles, %llu bytes, sum=%llu\n",
            tdata->thread_id, tdata->end_time - tdata->start_time, 
            tdata->bytes_accessed, sum);
    
    return 0;
}

static int start_bank_test(int pattern)
{
    int i;
    
    if (test_running) {
        pr_warn("Test already running\n");
        return -EBUSY;
    }
    
    // Allocate large test array
    if (!test_array) {
        test_array = vzalloc(ARRAY_SIZE * sizeof(u64));
        if (!test_array) {
            pr_err("Failed to allocate test array (%lu MB)\n", 
                   ARRAY_SIZE * sizeof(u64) / (1024 * 1024));
            return -ENOMEM;
        }
        
        pr_info("Allocated %lu MB test array at %p\n",
                ARRAY_SIZE * sizeof(u64) / (1024 * 1024), test_array);
    }
    
    // Initialize array with pattern to avoid all-zero optimizations
    for (i = 0; i < ARRAY_SIZE; i++) {
        test_array[i] = i * 0x123456789ABCDEF0ULL;
    }
    
    access_pattern = pattern;
    test_running = true;
    
    // Clear results
    memset(thread_results, 0, sizeof(thread_results));
    
    // Start worker threads with different starting offsets
    for (i = 0; i < NUM_THREADS; i++) {
        thread_results[i].thread_id = i;
        thread_results[i].pattern = pattern;
        thread_results[i].start_offset = i * (ARRAY_SIZE / NUM_THREADS);
        
        worker_threads[i] = kthread_create(bank_conflict_worker, 
                                         &thread_results[i],
                                         "bank_worker_%d", i);
        if (IS_ERR(worker_threads[i])) {
            pr_err("Failed to create thread %d\n", i);
            worker_threads[i] = NULL;
            continue;
        }
        
        // Bind to different CPUs to stress memory controller
        kthread_bind(worker_threads[i], i % num_online_cpus());
        wake_up_process(worker_threads[i]);
    }
    
    pr_info("Bank conflict test started with pattern %d (%s)\n", pattern,
            (pattern == 0) ? "sequential" :
            (pattern == 1) ? "bank_conflict" : "random");
    
    return 0;
}

static void stop_bank_test(void)
{
    int i;
    
    if (!test_running)
        return;
    
    // Stop all threads
    for (i = 0; i < NUM_THREADS; i++) {
        if (worker_threads[i]) {
            kthread_stop(worker_threads[i]);
            worker_threads[i] = NULL;
        }
    }
    
    test_running = false;
    pr_info("Bank conflict test stopped\n");
}

static int bank_conflict_show(struct seq_file *m, void *v)
{
    int i;
    u64 total_cycles = 0;
    u64 total_bytes = 0;
    u64 avg_bandwidth = 0;
    
    seq_printf(m, "=== Memory Bank Conflict Demo ===\n\n");
    
    seq_printf(m, "Configuration:\n");
    seq_printf(m, "  Array Size: %d MB (%lu elements)\n", 
               ARRAY_SIZE_MB, ARRAY_SIZE);
    seq_printf(m, "  Bank Size: %d bytes\n", BANK_SIZE);
    seq_printf(m, "  Conflict Stride: %d elements (%lu bytes)\n", 
               STRIDE_CONFLICT, STRIDE_CONFLICT * sizeof(u64));
    seq_printf(m, "  Number of Threads: %d\n", NUM_THREADS);
    seq_printf(m, "  Test Iterations: %d per thread\n", TEST_ITERATIONS);
    seq_printf(m, "  Test Status: %s\n", test_running ? "RUNNING" : "STOPPED");
    seq_printf(m, "  Last Pattern: %s\n\n",
               (access_pattern == 0) ? "Sequential" :
               (access_pattern == 1) ? "Bank Conflict" : "Random");
    
    if (test_array) {
        seq_printf(m, "Array Information:\n");
        seq_printf(m, "  Base Address: %p\n", test_array);
        seq_printf(m, "  First Element: 0x%llx\n", test_array[0]);
        seq_printf(m, "  Middle Element: 0x%llx\n", test_array[ARRAY_SIZE/2]);
        seq_printf(m, "  Last Element: 0x%llx\n\n", test_array[ARRAY_SIZE-1]);
    }
    
    // Performance results
    seq_printf(m, "Performance Results:\n");
    for (i = 0; i < NUM_THREADS; i++) {
        if (thread_results[i].end_time > thread_results[i].start_time) {
            u64 cycles = thread_results[i].end_time - thread_results[i].start_time;
            u64 bytes = thread_results[i].bytes_accessed;
            u64 bandwidth = 0;
            
            if (cycles > 0) {
                // Rough bandwidth calculation (cycles to time is CPU-specific)
                bandwidth = bytes * 1000000 / cycles;  // Simplified
            }
            
            seq_printf(m, "  Thread %d: %llu cycles, %llu bytes",
                       i, cycles, bytes);
            if (bandwidth > 0) {
                seq_printf(m, " (~%llu bytes/Mcycle)", bandwidth);
            }
            seq_printf(m, "\n");
            
            total_cycles += cycles;
            total_bytes += bytes;
        }
    }
    
    if (total_cycles > 0 && total_bytes > 0) {
        avg_bandwidth = total_bytes * 1000000 / total_cycles;
        seq_printf(m, "  Average Bandwidth: ~%llu bytes/Mcycle\n", avg_bandwidth);
        seq_printf(m, "  Total Data Processed: %llu MB\n", 
                   total_bytes / (1024 * 1024));
    }
    
    seq_printf(m, "\nAccess Pattern Analysis:\n");
    seq_printf(m, "  Sequential: Best prefetching, lowest latency\n");
    seq_printf(m, "  Bank Conflict: Multiple requests to same bank, serialized\n");
    seq_printf(m, "  Random: Poor cache locality, high latency\n");
    
    seq_printf(m, "\nCommands:\n");
    seq_printf(m, "  echo 'sequential' > /proc/%s  # Sequential access\n", PROC_NAME);
    seq_printf(m, "  echo 'conflict' > /proc/%s    # Bank conflict pattern\n", PROC_NAME);
    seq_printf(m, "  echo 'random' > /proc/%s      # Random access\n", PROC_NAME);
    seq_printf(m, "  echo 'stop' > /proc/%s        # Stop test\n", PROC_NAME);
    
    seq_printf(m, "\nAnalysis Tips:\n");
    seq_printf(m, "  - Compare bandwidth between different patterns\n");
    seq_printf(m, "  - Use 'perf stat -e dram_read_commands,dram_write_commands'\n");
    seq_printf(m, "  - Monitor 'perf stat -e uncore_mc_*' for memory controller events\n");
    seq_printf(m, "  - Check 'cat /proc/meminfo' for memory pressure\n");
    seq_printf(m, "  - Use 'numastat' to see NUMA effects\n");
    
    return 0;
}

static int bank_conflict_open(struct inode *inode, struct file *file)
{
    return single_open(file, bank_conflict_show, NULL);
}

static ssize_t bank_conflict_write(struct file *file, const char __user *buffer,
                                  size_t count, loff_t *pos)
{
    char cmd[16];
    int ret;
    
    if (count >= sizeof(cmd))
        return -EINVAL;
    
    if (copy_from_user(cmd, buffer, count))
        return -EFAULT;
    
    cmd[count] = '\0';
    
    if (strncmp(cmd, "sequential", 10) == 0) {
        stop_bank_test();
        ret = start_bank_test(0);
        if (ret)
            return ret;
        pr_info("Sequential access test started\n");
    } else if (strncmp(cmd, "conflict", 8) == 0) {
        stop_bank_test();
        ret = start_bank_test(1);
        if (ret)
            return ret;
        pr_info("Bank conflict test started\n");
    } else if (strncmp(cmd, "random", 6) == 0) {
        stop_bank_test();
        ret = start_bank_test(2);
        if (ret)
            return ret;
        pr_info("Random access test started\n");
    } else if (strncmp(cmd, "stop", 4) == 0) {
        stop_bank_test();
    } else {
        return -EINVAL;
    }
    
    return count;
}

static const struct proc_ops bank_conflict_proc_ops = {
    .proc_open = bank_conflict_open,
    .proc_read = seq_read,
    .proc_write = bank_conflict_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *proc_entry;

static int __init bank_conflict_init(void)
{
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &bank_conflict_proc_ops);
    if (!proc_entry) {
        pr_err("Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }
    
    pr_info("Memory bank conflict demo module loaded\n");
    pr_info("Access via: cat /proc/%s\n", PROC_NAME);
    pr_info("Will allocate %d MB when test starts\n", ARRAY_SIZE_MB);
    
    return 0;
}

static void __exit bank_conflict_exit(void)
{
    stop_bank_test();
    
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    
    if (test_array) {
        vfree(test_array);
        test_array = NULL;
        pr_info("Test array freed\n");
    }
    
    pr_info("Memory bank conflict demo module unloaded\n");
}

module_init(bank_conflict_init);
module_exit(bank_conflict_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CoreTracer Project");
MODULE_DESCRIPTION("Memory bank conflict performance demonstration");
MODULE_VERSION("1.0");