/*
 * Cache Line False Sharing Demonstration Kernel Module
 * 
 * This module demonstrates cache line false sharing effects by creating
 * scenarios where multiple threads access different variables that happen
 * to share the same cache line, causing performance degradation.
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
#include <linux/cache.h>
#include <linux/compiler.h>

#define MODULE_NAME "cacheline_false_demo"
#define PROC_NAME "cacheline_false"
#define NUM_THREADS 4
#define TEST_ITERATIONS 1000000
#define CACHE_LINE_SIZE 64

// Structure demonstrating false sharing - variables in same cache line
struct false_sharing_data {
    volatile u64 counter0;
    volatile u64 counter1;
    volatile u64 counter2;
    volatile u64 counter3;
    volatile u64 dummy[4];  // Fill rest of cache line
} __attribute__((packed));

// Structure avoiding false sharing - each counter on separate cache line
struct aligned_data {
    volatile u64 counter0 ____cacheline_aligned;
    volatile u64 counter1 ____cacheline_aligned;
    volatile u64 counter2 ____cacheline_aligned;
    volatile u64 counter3 ____cacheline_aligned;
};

static struct false_sharing_data *false_share_data;
static struct aligned_data *aligned_data;
static struct task_struct *worker_threads[NUM_THREADS];
static bool test_running = false;
static int test_mode = 0;  // 0 = false sharing, 1 = aligned

struct thread_stats {
    int thread_id;
    cycles_t start_time;
    cycles_t end_time;
    u64 iterations_completed;
    u64 cache_misses;
};

static struct thread_stats thread_results[NUM_THREADS];

// Worker function for false sharing test
static int false_sharing_worker(void *data)
{
    int thread_id = *(int *)data;
    struct thread_stats *stats = &thread_results[thread_id];
    volatile u64 *target_counter;
    u64 local_count = 0;
    int i;
    
    stats->thread_id = thread_id;
    stats->start_time = get_cycles();
    
    // Select target counter based on thread ID and test mode
    if (test_mode == 0) {
        // False sharing mode - all counters in same cache line
        switch (thread_id) {
            case 0: target_counter = &false_share_data->counter0; break;
            case 1: target_counter = &false_share_data->counter1; break;
            case 2: target_counter = &false_share_data->counter2; break;
            case 3: target_counter = &false_share_data->counter3; break;
            default: target_counter = &false_share_data->counter0; break;
        }
    } else {
        // Aligned mode - each counter on separate cache line
        switch (thread_id) {
            case 0: target_counter = &aligned_data->counter0; break;
            case 1: target_counter = &aligned_data->counter1; break;
            case 2: target_counter = &aligned_data->counter2; break;
            case 3: target_counter = &aligned_data->counter3; break;
            default: target_counter = &aligned_data->counter0; break;
        }
    }
    
    pr_info("Thread %d starting %s test\n", thread_id, 
            test_mode ? "aligned" : "false-sharing");
    
    // Main work loop - repeatedly increment counter
    for (i = 0; i < TEST_ITERATIONS && !kthread_should_stop(); i++) {
        // Read-modify-write operation that will cause cache line bouncing
        (*target_counter)++;
        local_count++;
        
        // Add some computation to make cache effects more visible
        if (i % 1000 == 0) {
            volatile u64 temp = *target_counter;
            temp = temp * 31 + 17;  // Dummy computation
            *target_counter = temp;
        }
        
        // Yield occasionally to allow other threads to run
        if (i % 10000 == 0) {
            cond_resched();
        }
    }
    
    stats->end_time = get_cycles();
    stats->iterations_completed = local_count;
    
    pr_info("Thread %d completed: %llu cycles, %llu iterations\n",
            thread_id, stats->end_time - stats->start_time, 
            stats->iterations_completed);
    
    return 0;
}

static int start_cacheline_test(int mode)
{
    int i;
    int *thread_ids;
    
    if (test_running) {
        pr_warn("Test already running\n");
        return -EBUSY;
    }
    
    test_mode = mode;
    test_running = true;
    
    // Allocate thread ID array
    thread_ids = kmalloc(NUM_THREADS * sizeof(int), GFP_KERNEL);
    if (!thread_ids) {
        pr_err("Failed to allocate thread IDs\n");
        test_running = false;
        return -ENOMEM;
    }
    
    // Allocate test data structures
    if (!false_share_data) {
        false_share_data = kzalloc(sizeof(*false_share_data), GFP_KERNEL);
        if (!false_share_data) {
            pr_err("Failed to allocate false sharing data\n");
            kfree(thread_ids);
            test_running = false;
            return -ENOMEM;
        }
    }
    
    if (!aligned_data) {
        aligned_data = kzalloc(sizeof(*aligned_data), GFP_KERNEL);
        if (!aligned_data) {
            pr_err("Failed to allocate aligned data\n");
            kfree(false_share_data);
            kfree(thread_ids);
            test_running = false;
            return -ENOMEM;
        }
    }
    
    // Initialize counters
    if (test_mode == 0) {
        false_share_data->counter0 = 0;
        false_share_data->counter1 = 0;
        false_share_data->counter2 = 0;
        false_share_data->counter3 = 0;
    } else {
        aligned_data->counter0 = 0;
        aligned_data->counter1 = 0;
        aligned_data->counter2 = 0;
        aligned_data->counter3 = 0;
    }
    
    // Clear statistics
    memset(thread_results, 0, sizeof(thread_results));
    
    // Create and start worker threads
    for (i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i;
        worker_threads[i] = kthread_create(false_sharing_worker, &thread_ids[i],
                                          "cacheline_worker_%d", i);
        if (IS_ERR(worker_threads[i])) {
            pr_err("Failed to create thread %d\n", i);
            worker_threads[i] = NULL;
            continue;
        }
        
        // Bind thread to specific CPU to maximize cache conflicts
        kthread_bind(worker_threads[i], i % num_online_cpus());
        wake_up_process(worker_threads[i]);
    }
    
    pr_info("Cache line %s test started with %d threads\n",
            test_mode ? "aligned" : "false-sharing", NUM_THREADS);
    
    return 0;
}

static void stop_cacheline_test(void)
{
    int i;
    
    if (!test_running)
        return;
    
    // Stop all worker threads
    for (i = 0; i < NUM_THREADS; i++) {
        if (worker_threads[i]) {
            kthread_stop(worker_threads[i]);
            worker_threads[i] = NULL;
        }
    }
    
    test_running = false;
    pr_info("Cache line test stopped\n");
}

static int cacheline_false_show(struct seq_file *m, void *v)
{
    int i;
    u64 total_cycles = 0;
    u64 total_iterations = 0;
    u64 avg_cycles_per_iteration = 0;
    
    seq_printf(m, "=== Cache Line False Sharing Demo ===\n\n");
    
    seq_printf(m, "Configuration:\n");
    seq_printf(m, "  Number of Threads: %d\n", NUM_THREADS);
    seq_printf(m, "  Iterations per Thread: %d\n", TEST_ITERATIONS);
    seq_printf(m, "  Cache Line Size: %d bytes\n", CACHE_LINE_SIZE);
    seq_printf(m, "  Test Status: %s\n", test_running ? "RUNNING" : "STOPPED");
    seq_printf(m, "  Last Test Mode: %s\n\n", 
               test_mode ? "Aligned (no false sharing)" : "False Sharing");
    
    // Show memory layout information
    if (false_share_data && aligned_data) {
        seq_printf(m, "Memory Layout:\n");
        seq_printf(m, "  False Sharing Structure:\n");
        seq_printf(m, "    counter0 @ %p\n", &false_share_data->counter0);
        seq_printf(m, "    counter1 @ %p (offset: %ld)\n", 
                   &false_share_data->counter1,
                   (char*)&false_share_data->counter1 - (char*)&false_share_data->counter0);
        seq_printf(m, "    counter2 @ %p (offset: %ld)\n", 
                   &false_share_data->counter2,
                   (char*)&false_share_data->counter2 - (char*)&false_share_data->counter0);
        seq_printf(m, "    counter3 @ %p (offset: %ld)\n", 
                   &false_share_data->counter3,
                   (char*)&false_share_data->counter3 - (char*)&false_share_data->counter0);
        
        seq_printf(m, "  Aligned Structure:\n");
        seq_printf(m, "    counter0 @ %p\n", &aligned_data->counter0);
        seq_printf(m, "    counter1 @ %p (offset: %ld)\n", 
                   &aligned_data->counter1,
                   (char*)&aligned_data->counter1 - (char*)&aligned_data->counter0);
        seq_printf(m, "    counter2 @ %p (offset: %ld)\n", 
                   &aligned_data->counter2,
                   (char*)&aligned_data->counter2 - (char*)&aligned_data->counter0);
        seq_printf(m, "    counter3 @ %p (offset: %ld)\n\n", 
                   &aligned_data->counter3,
                   (char*)&aligned_data->counter3 - (char*)&aligned_data->counter0);
    }
    
    // Show current counter values
    if (false_share_data) {
        seq_printf(m, "False Sharing Counters:\n");
        seq_printf(m, "  counter0: %llu\n", false_share_data->counter0);
        seq_printf(m, "  counter1: %llu\n", false_share_data->counter1);
        seq_printf(m, "  counter2: %llu\n", false_share_data->counter2);
        seq_printf(m, "  counter3: %llu\n\n", false_share_data->counter3);
    }
    
    if (aligned_data) {
        seq_printf(m, "Aligned Counters:\n");
        seq_printf(m, "  counter0: %llu\n", aligned_data->counter0);
        seq_printf(m, "  counter1: %llu\n", aligned_data->counter1);
        seq_printf(m, "  counter2: %llu\n", aligned_data->counter2);
        seq_printf(m, "  counter3: %llu\n\n", aligned_data->counter3);
    }
    
    // Show performance statistics
    seq_printf(m, "Performance Results:\n");
    for (i = 0; i < NUM_THREADS; i++) {
        if (thread_results[i].end_time > thread_results[i].start_time) {
            u64 cycles = thread_results[i].end_time - thread_results[i].start_time;
            u64 iterations = thread_results[i].iterations_completed;
            
            seq_printf(m, "  Thread %d: %llu cycles, %llu iterations",
                       i, cycles, iterations);
            if (iterations > 0) {
                seq_printf(m, " (%llu cycles/iteration)", cycles / iterations);
            }
            seq_printf(m, "\n");
            
            total_cycles += cycles;
            total_iterations += iterations;
        }
    }
    
    if (total_iterations > 0) {
        avg_cycles_per_iteration = total_cycles / total_iterations;
        seq_printf(m, "  Average: %llu cycles/iteration\n", avg_cycles_per_iteration);
    }
    
    seq_printf(m, "\nCommands:\n");
    seq_printf(m, "  echo 'false' > /proc/%s   # Test with false sharing\n", PROC_NAME);
    seq_printf(m, "  echo 'aligned' > /proc/%s # Test with aligned data\n", PROC_NAME);
    seq_printf(m, "  echo 'stop' > /proc/%s    # Stop current test\n", PROC_NAME);
    
    seq_printf(m, "\nAnalysis Tips:\n");
    seq_printf(m, "  - Compare cycles/iteration between false sharing and aligned tests\n");
    seq_printf(m, "  - Use 'perf stat -e cache-misses,cache-references' during test\n");
    seq_printf(m, "  - Monitor 'perf stat -e LLC-load-misses,LLC-loads' for L3 cache\n");
    seq_printf(m, "  - Use perf c2c for cache-to-cache transfer analysis\n");
    seq_printf(m, "  - Check /proc/cpuinfo for cache hierarchy details\n");
    
    return 0;
}

static int cacheline_false_open(struct inode *inode, struct file *file)
{
    return single_open(file, cacheline_false_show, NULL);
}

static ssize_t cacheline_false_write(struct file *file, const char __user *buffer,
                                    size_t count, loff_t *pos)
{
    char cmd[16];
    int ret;
    
    if (count >= sizeof(cmd))
        return -EINVAL;
    
    if (copy_from_user(cmd, buffer, count))
        return -EFAULT;
    
    cmd[count] = '\0';
    
    if (strncmp(cmd, "false", 5) == 0) {
        stop_cacheline_test();  // Stop any running test first
        ret = start_cacheline_test(0);  // Start false sharing test
        if (ret)
            return ret;
        pr_info("False sharing test started\n");
    } else if (strncmp(cmd, "aligned", 7) == 0) {
        stop_cacheline_test();  // Stop any running test first
        ret = start_cacheline_test(1);  // Start aligned test
        if (ret)
            return ret;
        pr_info("Aligned test started\n");
    } else if (strncmp(cmd, "stop", 4) == 0) {
        stop_cacheline_test();
    } else {
        return -EINVAL;
    }
    
    return count;
}

static const struct proc_ops cacheline_false_proc_ops = {
    .proc_open = cacheline_false_open,
    .proc_read = seq_read,
    .proc_write = cacheline_false_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *proc_entry;

static int __init cacheline_false_init(void)
{
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &cacheline_false_proc_ops);
    if (!proc_entry) {
        pr_err("Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }
    
    pr_info("Cache line false sharing demo module loaded\n");
    pr_info("Access via: cat /proc/%s\n", PROC_NAME);
    pr_info("Cache line size: %d bytes\n", CACHE_LINE_SIZE);
    
    return 0;
}

static void __exit cacheline_false_exit(void)
{
    stop_cacheline_test();
    
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    
    if (false_share_data) {
        kfree(false_share_data);
        false_share_data = NULL;
    }
    
    if (aligned_data) {
        kfree(aligned_data);
        aligned_data = NULL;
    }
    
    pr_info("Cache line false sharing demo module unloaded\n");
}

module_init(cacheline_false_init);
module_exit(cacheline_false_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CoreTracer Project");
MODULE_DESCRIPTION("Cache line false sharing performance demonstration");
MODULE_VERSION("1.0");