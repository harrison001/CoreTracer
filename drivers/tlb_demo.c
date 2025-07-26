/*
 * TLB Shootdown and Performance Demonstration
 * 
 * This module demonstrates TLB (Translation Lookaside Buffer) behavior,
 * shootdown effects across cores, and TLB performance characteristics.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/uaccess.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/cpuset.h>
#include <linux/atomic.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>

#define MODULE_NAME "tlb_demo"
#define PROC_NAME "tlb_demo"
#define MAX_TEST_PAGES 1024
#define MAX_CORES 16
#define TLB_TEST_ITERATIONS 1000

static struct proc_dir_entry *proc_entry;

struct tlb_test_data {
    void **test_pages;
    unsigned long *page_addresses;
    int num_pages;
    atomic_t active_threads;
    atomic_t start_flag;
    atomic_t stop_flag;
    unsigned long shootdown_count[MAX_CORES];
    unsigned long access_latency[MAX_CORES];
    unsigned long page_fault_count[MAX_CORES];
    struct task_struct *worker_threads[MAX_CORES];
    bool test_running;
};

struct tlb_worker_context {
    int cpu_id;
    struct tlb_test_data *test_data;
    enum tlb_test_type test_type;
    unsigned long local_shootdowns;
    unsigned long local_accesses;
    unsigned long local_latency;
};

enum tlb_test_type {
    TLB_TEST_SEQUENTIAL,
    TLB_TEST_RANDOM,
    TLB_TEST_SHOOTDOWN,
    TLB_TEST_INTERFERENCE,
    TLB_TEST_CAPACITY
};

static const char *tlb_test_names[] = {
    "Sequential Access",
    "Random Access",
    "TLB Shootdown",
    "Multi-Core Interference",
    "TLB Capacity Estimation"
};

static struct tlb_test_data test_data;

/*
 * External assembly functions (declared here for linking)
 */
extern unsigned long tlb_shootdown_benchmark_asm(unsigned long *addresses, 
                                                 unsigned long count, 
                                                 unsigned long iterations);
extern unsigned long page_walk_timing_asm(unsigned long address, 
                                         unsigned long count);
extern unsigned long tlb_miss_generator_asm(unsigned long base, 
                                           unsigned long stride, 
                                           unsigned long count);

/*
 * Allocate test pages for TLB experiments
 */
static int allocate_test_pages(int num_pages)
{
    int i;
    
    if (num_pages > MAX_TEST_PAGES) {
        pr_warn("Requested pages (%d) exceeds maximum (%d)\n", 
                num_pages, MAX_TEST_PAGES);
        return -EINVAL;
    }
    
    test_data.test_pages = kzalloc(num_pages * sizeof(void *), GFP_KERNEL);
    if (!test_data.test_pages) {
        pr_err("Failed to allocate page pointer array\n");
        return -ENOMEM;
    }
    
    test_data.page_addresses = kzalloc(num_pages * sizeof(unsigned long), GFP_KERNEL);
    if (!test_data.page_addresses) {
        kfree(test_data.test_pages);
        pr_err("Failed to allocate address array\n");
        return -ENOMEM;
    }
    
    for (i = 0; i < num_pages; i++) {
        test_data.test_pages[i] = (void *)__get_free_page(GFP_KERNEL);
        if (!test_data.test_pages[i]) {
            pr_err("Failed to allocate page %d\n", i);
            // Cleanup already allocated pages
            while (--i >= 0) {
                free_page((unsigned long)test_data.test_pages[i]);
            }
            kfree(test_data.test_pages);
            kfree(test_data.page_addresses);
            return -ENOMEM;
        }
        
        test_data.page_addresses[i] = (unsigned long)test_data.test_pages[i];
        
        // Initialize page with some data
        memset(test_data.test_pages[i], i & 0xFF, PAGE_SIZE);
    }
    
    test_data.num_pages = num_pages;
    pr_info("Allocated %d test pages\n", num_pages);
    
    return 0;
}

/*
 * Free allocated test pages
 */
static void free_test_pages(void)
{
    int i;
    
    if (!test_data.test_pages)
        return;
    
    for (i = 0; i < test_data.num_pages; i++) {
        if (test_data.test_pages[i]) {
            free_page((unsigned long)test_data.test_pages[i]);
        }
    }
    
    kfree(test_data.test_pages);
    kfree(test_data.page_addresses);
    test_data.test_pages = NULL;
    test_data.page_addresses = NULL;
    test_data.num_pages = 0;
}

/*
 * TLB sequential access worker thread
 */
static int tlb_sequential_worker(void *data)
{
    struct tlb_worker_context *ctx = (struct tlb_worker_context *)data;
    struct tlb_test_data *td = ctx->test_data;
    int i, iteration;
    unsigned long start_time, end_time;
    volatile unsigned char *page_data;
    
    pr_info("TLB sequential worker starting on CPU %d\n", smp_processor_id());
    
    atomic_inc(&td->active_threads);
    
    // Wait for start signal
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    start_time = get_cycles();
    
    for (iteration = 0; iteration < TLB_TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        // Sequential access through all pages
        for (i = 0; i < td->num_pages; i++) {
            page_data = (volatile unsigned char *)td->test_pages[i];
            // Read first byte of each page (forces TLB lookup)
            ctx->local_accesses += *page_data;
        }
        
        // Periodic yield
        if (iteration % 100 == 0) {
            cond_resched();
        }
    }
    
    end_time = get_cycles();
    ctx->local_latency = end_time - start_time;
    
    atomic_dec(&td->active_threads);
    pr_info("TLB sequential worker completed on CPU %d\n", smp_processor_id());
    
    return 0;
}

/*
 * TLB random access worker thread
 */
static int tlb_random_worker(void *data)
{
    struct tlb_worker_context *ctx = (struct tlb_worker_context *)data;
    struct tlb_test_data *td = ctx->test_data;
    int iteration, page_idx;
    unsigned long start_time, end_time;
    volatile unsigned char *page_data;
    unsigned int random_seed;
    
    pr_info("TLB random worker starting on CPU %d\n", smp_processor_id());
    
    // Initialize random seed based on CPU and time
    random_seed = smp_processor_id() + (unsigned int)get_cycles();
    
    atomic_inc(&td->active_threads);
    
    // Wait for start signal
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    start_time = get_cycles();
    
    for (iteration = 0; iteration < TLB_TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        // Random access pattern
        for (int i = 0; i < td->num_pages; i++) {
            // Simple LCG for pseudo-random numbers
            random_seed = random_seed * 1103515245 + 12345;
            page_idx = random_seed % td->num_pages;
            
            page_data = (volatile unsigned char *)td->test_pages[page_idx];
            ctx->local_accesses += *page_data;
        }
        
        if (iteration % 100 == 0) {
            cond_resched();
        }
    }
    
    end_time = get_cycles();
    ctx->local_latency = end_time - start_time;
    
    atomic_dec(&td->active_threads);
    pr_info("TLB random worker completed on CPU %d\n", smp_processor_id());
    
    return 0;
}

/*
 * TLB shootdown worker thread
 */
static int tlb_shootdown_worker(void *data)
{
    struct tlb_worker_context *ctx = (struct tlb_worker_context *)data;
    struct tlb_test_data *td = ctx->test_data;
    int iteration, i;
    unsigned long start_time, end_time;
    volatile unsigned char *page_data;
    
    pr_info("TLB shootdown worker starting on CPU %d\n", smp_processor_id());
    
    atomic_inc(&td->active_threads);
    
    // Wait for start signal
    while (!atomic_read(&td->start_flag) && !kthread_should_stop()) {
        cpu_relax();
    }
    
    start_time = get_cycles();
    
    for (iteration = 0; iteration < TLB_TEST_ITERATIONS && !kthread_should_stop(); iteration++) {
        // Access pages to populate TLB
        for (i = 0; i < td->num_pages / 4; i++) {
            page_data = (volatile unsigned char *)td->test_pages[i];
            ctx->local_accesses += *page_data;
        }
        
        // Force TLB shootdown by flushing specific pages
        for (i = 0; i < td->num_pages / 8; i++) {
            flush_tlb_page(current->active_mm, td->page_addresses[i]);
            ctx->local_shootdowns++;
        }
        
        // Access flushed pages again (should cause TLB misses)
        for (i = 0; i < td->num_pages / 8; i++) {
            page_data = (volatile unsigned char *)td->test_pages[i];
            ctx->local_accesses += *page_data;
        }
        
        if (iteration % 50 == 0) {
            cond_resched();
        }
    }
    
    end_time = get_cycles();
    ctx->local_latency = end_time - start_time;
    
    atomic_dec(&td->active_threads);
    pr_info("TLB shootdown worker completed on CPU %d, shootdowns: %lu\n", 
            smp_processor_id(), ctx->local_shootdowns);
    
    return 0;
}

/*
 * Start TLB test with specified type
 */
static int start_tlb_test(enum tlb_test_type test_type, int num_threads)
{
    int i, ret;
    int (*worker_func)(void *);
    struct tlb_worker_context *contexts;
    
    if (test_data.test_running) {
        pr_warn("TLB test already running\n");
        return -EBUSY;
    }
    
    if (num_threads > num_online_cpus() || num_threads > MAX_CORES) {
        pr_warn("Too many threads requested: %d (max: %d)\n", 
                num_threads, min(num_online_cpus(), MAX_CORES));
        return -EINVAL;
    }
    
    if (!test_data.test_pages) {
        pr_warn("No test pages allocated\n");
        return -EINVAL;
    }
    
    // Select worker function based on test type
    switch (test_type) {
        case TLB_TEST_SEQUENTIAL:
            worker_func = tlb_sequential_worker;
            break;
        case TLB_TEST_RANDOM:
            worker_func = tlb_random_worker;
            break;
        case TLB_TEST_SHOOTDOWN:
            worker_func = tlb_shootdown_worker;
            break;
        default:
            pr_err("Unsupported test type: %d\n", test_type);
            return -EINVAL;
    }
    
    // Allocate worker contexts
    contexts = kzalloc(num_threads * sizeof(struct tlb_worker_context), GFP_KERNEL);
    if (!contexts) {
        pr_err("Failed to allocate worker contexts\n");
        return -ENOMEM;
    }
    
    // Initialize test state
    memset(&test_data.shootdown_count, 0, sizeof(test_data.shootdown_count));
    memset(&test_data.access_latency, 0, sizeof(test_data.access_latency));
    atomic_set(&test_data.active_threads, 0);
    atomic_set(&test_data.start_flag, 0);
    atomic_set(&test_data.stop_flag, 0);
    test_data.test_running = true;
    
    pr_info("Starting TLB test: %s with %d threads\n", 
            tlb_test_names[test_type], num_threads);
    
    // Create worker threads
    for (i = 0; i < num_threads; i++) {
        contexts[i].cpu_id = i % num_online_cpus();
        contexts[i].test_data = &test_data;
        contexts[i].test_type = test_type;
        contexts[i].local_shootdowns = 0;
        contexts[i].local_accesses = 0;
        contexts[i].local_latency = 0;
        
        test_data.worker_threads[i] = kthread_create(worker_func, &contexts[i],
                                                    "tlb_worker_%d", i);
        if (IS_ERR(test_data.worker_threads[i])) {
            pr_err("Failed to create worker thread %d\n", i);
            ret = PTR_ERR(test_data.worker_threads[i]);
            // Stop already created threads
            for (int j = 0; j < i; j++) {
                if (test_data.worker_threads[j]) {
                    kthread_stop(test_data.worker_threads[j]);
                }
            }
            kfree(contexts);
            test_data.test_running = false;
            return ret;
        }
        
        kthread_bind(test_data.worker_threads[i], contexts[i].cpu_id);
        wake_up_process(test_data.worker_threads[i]);
    }
    
    // Wait for all threads to be ready
    while (atomic_read(&test_data.active_threads) < num_threads) {
        msleep(1);
    }
    
    pr_info("All TLB worker threads ready, starting test\n");
    
    // Start the test
    atomic_set(&test_data.start_flag, 1);
    
    // Store contexts for cleanup (simplified - in real code you'd need better management)
    // For now, we'll let threads complete and clean up in stop function
    
    return 0;
}

/*
 * Stop running TLB test
 */
static void stop_tlb_test(void)
{
    int i;
    
    if (!test_data.test_running)
        return;
    
    pr_info("Stopping TLB test\n");
    
    atomic_set(&test_data.stop_flag, 1);
    
    // Stop all worker threads
    for (i = 0; i < MAX_CORES; i++) {
        if (test_data.worker_threads[i]) {
            kthread_stop(test_data.worker_threads[i]);
            test_data.worker_threads[i] = NULL;
        }
    }
    
    test_data.test_running = false;
    pr_info("TLB test stopped\n");
}

static int tlb_demo_show(struct seq_file *m, void *v)
{
    seq_printf(m, "=== TLB Shootdown & Performance Demo ===\n\n");
    
    seq_printf(m, "System Information:\n");
    seq_printf(m, "  CPUs: %d online\n", num_online_cpus());
    seq_printf(m, "  Test Status: %s\n", test_data.test_running ? "RUNNING" : "STOPPED");
    seq_printf(m, "  Allocated Pages: %d\n", test_data.num_pages);
    seq_printf(m, "  Active Threads: %d\n\n", atomic_read(&test_data.active_threads));
    
    seq_printf(m, "Available TLB Tests:\n");
    for (int i = 0; i < ARRAY_SIZE(tlb_test_names); i++) {
        seq_printf(m, "  %d: %s\n", i, tlb_test_names[i]);
    }
    
    seq_printf(m, "\nCommands:\n");
    seq_printf(m, "  echo 'alloc <pages>' > /proc/%s     # Allocate test pages\n", PROC_NAME);
    seq_printf(m, "  echo 'start <type> <threads>' > /proc/%s  # Start test\n", PROC_NAME);
    seq_printf(m, "  echo 'stop' > /proc/%s             # Stop test\n", PROC_NAME);
    seq_printf(m, "  echo 'free' > /proc/%s             # Free test pages\n", PROC_NAME);
    
    seq_printf(m, "\nTLB Performance Tips:\n");
    seq_printf(m, "  - Use 'perf stat -e dTLB-loads,dTLB-load-misses' during test\n");
    seq_printf(m, "  - Monitor /proc/vmstat for TLB statistics\n");
    seq_printf(m, "  - Compare sequential vs random access patterns\n");
    seq_printf(m, "  - Observe shootdown costs with multiple cores\n");
    
    return 0;
}

static int tlb_demo_open(struct inode *inode, struct file *file)
{
    return single_open(file, tlb_demo_show, NULL);
}

static ssize_t tlb_demo_write(struct file *file, const char __user *buffer,
                             size_t count, loff_t *pos)
{
    char cmd[64];
    int test_type, num_threads, num_pages;
    
    if (count >= sizeof(cmd))
        return -EINVAL;
    
    if (copy_from_user(cmd, buffer, count))
        return -EFAULT;
    
    cmd[count] = '\0';
    
    if (sscanf(cmd, "alloc %d", &num_pages) == 1) {
        if (test_data.test_pages) {
            free_test_pages();
        }
        int ret = allocate_test_pages(num_pages);
        if (ret)
            return ret;
        pr_info("Allocated %d test pages\n", num_pages);
    } else if (sscanf(cmd, "start %d %d", &test_type, &num_threads) == 2) {
        if (test_type >= 0 && test_type < ARRAY_SIZE(tlb_test_names)) {
            int ret = start_tlb_test(test_type, num_threads);
            if (ret)
                return ret;
        } else {
            return -EINVAL;
        }
    } else if (strncmp(cmd, "stop", 4) == 0) {
        stop_tlb_test();
    } else if (strncmp(cmd, "free", 4) == 0) {
        if (test_data.test_running) {
            stop_tlb_test();
        }
        free_test_pages();
        pr_info("Freed test pages\n");
    } else {
        return -EINVAL;
    }
    
    return count;
}

static const struct proc_ops tlb_demo_proc_ops = {
    .proc_open = tlb_demo_open,
    .proc_read = seq_read,
    .proc_write = tlb_demo_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init tlb_demo_init(void)
{
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &tlb_demo_proc_ops);
    if (!proc_entry) {
        pr_err("Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }
    
    // Initialize test data
    memset(&test_data, 0, sizeof(test_data));
    
    pr_info("TLB demo module loaded\n");
    pr_info("Access via: cat /proc/%s\n", PROC_NAME);
    
    return 0;
}

static void __exit tlb_demo_exit(void)
{
    stop_tlb_test();
    free_test_pages();
    
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    
    pr_info("TLB demo module unloaded\n");
}

module_init(tlb_demo_init);
module_exit(tlb_demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CoreTracer Project");
MODULE_DESCRIPTION("TLB shootdown and performance demonstration");
MODULE_VERSION("1.0");