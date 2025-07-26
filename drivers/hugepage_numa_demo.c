/*
 * HugePage and NUMA Cross-Node Allocation Demonstration
 * 
 * This module demonstrates the performance characteristics of large page allocation
 * across NUMA nodes, showing latency differences, fragmentation effects, and 
 * THP (Transparent Huge Pages) behavior under memory pressure.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/hugetlb.h>
#include <linux/uaccess.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/numa.h>
#include <linux/topology.h>
#include <linux/kthread.h>
#include <linux/cpuset.h>

#define MODULE_NAME "hugepage_numa_demo"
#define PROC_NAME "hugepage_numa"
#define MAX_ALLOCATIONS 64
#define HUGEPAGE_SIZE (2 * 1024 * 1024)  // 2MB
#define NORMAL_PAGE_SIZE (4 * 1024)      // 4KB
#define TEST_ITERATIONS 1000

static struct proc_dir_entry *proc_entry;

struct allocation_record {
    void *ptr;
    int order;
    int node;
    gfp_t flags;
    cycles_t alloc_time;
    cycles_t free_time;
    size_t size;
    bool is_hugepage;
};

struct numa_stats {
    unsigned long alloc_count[MAX_NUMNODES];
    unsigned long alloc_latency[MAX_NUMNODES];
    unsigned long free_latency[MAX_NUMNODES];
    unsigned long fragmentation_score[MAX_NUMNODES];
    unsigned long cross_node_count;
    unsigned long local_node_count;
};

static struct allocation_record allocations[MAX_ALLOCATIONS];
static struct numa_stats stats;
static int num_allocations = 0;
static bool test_running = false;
static struct task_struct *test_thread = NULL;

// Different allocation strategies to test
enum alloc_strategy {
    STRATEGY_NORMAL_PAGES,
    STRATEGY_HUGE_PAGES,
    STRATEGY_MIXED_PAGES,
    STRATEGY_CROSS_NUMA,
    STRATEGY_LOCAL_NUMA
};

static const char *strategy_names[] = {
    "Normal 4KB Pages",
    "Huge 2MB Pages", 
    "Mixed Page Sizes",
    "Cross-NUMA Allocation",
    "Local NUMA Allocation"
};

/*
 * Get current NUMA node for the calling thread
 */
static int get_current_numa_node(void)
{
    return numa_node_id();
}

/*
 * Calculate fragmentation score for a NUMA node
 */
static unsigned long calculate_fragmentation_score(int node)
{
    unsigned long free_pages = 0;
    unsigned long total_pages = 0;
    struct zone *zone;
    
    // Simple fragmentation metric based on free page distribution
    for_each_populated_zone(zone) {
        if (zone_to_nid(zone) == node) {
            free_pages += zone_page_state(zone, NR_FREE_PAGES);
            total_pages += zone->managed_pages;
        }
    }
    
    return total_pages > 0 ? (free_pages * 100) / total_pages : 0;
}

/*
 * Allocate memory using different strategies
 */
static void *allocate_memory_strategy(enum alloc_strategy strategy, int preferred_node, 
                                    struct allocation_record *record)
{
    void *ptr = NULL;
    cycles_t start_time = get_cycles();
    gfp_t flags = GFP_KERNEL;
    int order = 0;
    
    record->node = preferred_node;
    record->alloc_time = start_time;
    
    switch (strategy) {
        case STRATEGY_NORMAL_PAGES:
            // Allocate normal 4KB pages
            order = 0;
            flags = GFP_KERNEL;
            if (preferred_node >= 0) {
                ptr = (void *)__get_free_pages_node(preferred_node, flags, order);
            } else {
                ptr = (void *)__get_free_pages(flags, order);
            }
            record->size = PAGE_SIZE << order;
            record->is_hugepage = false;
            break;
            
        case STRATEGY_HUGE_PAGES:
            // Allocate 2MB huge pages
            order = 9; // 2^9 * 4KB = 2MB
            flags = GFP_KERNEL | __GFP_COMP;
            if (preferred_node >= 0) {
                ptr = (void *)__get_free_pages_node(preferred_node, flags, order);
            } else {
                ptr = (void *)__get_free_pages(flags, order);
            }
            record->size = PAGE_SIZE << order;
            record->is_hugepage = true;
            break;
            
        case STRATEGY_MIXED_PAGES:
            // Randomly choose between normal and huge pages
            if (get_random_u32() % 2) {
                order = 0;
                record->is_hugepage = false;
            } else {
                order = 9;
                record->is_hugepage = true;
                flags |= __GFP_COMP;
            }
            if (preferred_node >= 0) {
                ptr = (void *)__get_free_pages_node(preferred_node, flags, order);
            } else {
                ptr = (void *)__get_free_pages(flags, order);
            }
            record->size = PAGE_SIZE << order;
            break;
            
        case STRATEGY_CROSS_NUMA:
            // Deliberately allocate on a different NUMA node
            {
                int current_node = get_current_numa_node();
                int target_node = (current_node + 1) % num_online_nodes();
                order = 0;
                flags = GFP_KERNEL;
                ptr = (void *)__get_free_pages_node(target_node, flags, order);
                record->node = target_node;
                record->size = PAGE_SIZE << order;
                record->is_hugepage = false;
                stats.cross_node_count++;
            }
            break;
            
        case STRATEGY_LOCAL_NUMA:
            // Allocate on local NUMA node
            {
                int current_node = get_current_numa_node();
                order = 0;
                flags = GFP_KERNEL;
                ptr = (void *)__get_free_pages_node(current_node, flags, order);
                record->node = current_node;
                record->size = PAGE_SIZE << order;
                record->is_hugepage = false;
                stats.local_node_count++;
            }
            break;
    }
    
    record->ptr = ptr;
    record->order = order;
    record->flags = flags;
    record->alloc_time = get_cycles() - start_time;
    
    if (ptr && record->node >= 0 && record->node < MAX_NUMNODES) {
        stats.alloc_count[record->node]++;
        stats.alloc_latency[record->node] += record->alloc_time;
        stats.fragmentation_score[record->node] = calculate_fragmentation_score(record->node);
    }
    
    return ptr;
}

/*
 * Free allocated memory and record timing
 */
static void free_memory_record(struct allocation_record *record)
{
    cycles_t start_time;
    
    if (!record->ptr)
        return;
        
    start_time = get_cycles();
    free_pages((unsigned long)record->ptr, record->order);
    record->free_time = get_cycles() - start_time;
    
    if (record->node >= 0 && record->node < MAX_NUMNODES) {
        stats.free_latency[record->node] += record->free_time;
    }
    
    record->ptr = NULL;
}

/*
 * Memory allocation stress test thread
 */
static int hugepage_test_thread(void *data)
{
    enum alloc_strategy strategy = *(enum alloc_strategy *)data;
    int i, j;
    
    pr_info("Starting hugepage test with strategy: %s\n", strategy_names[strategy]);
    
    for (i = 0; i < TEST_ITERATIONS && !kthread_should_stop(); i++) {
        // Allocate memory
        for (j = 0; j < MAX_ALLOCATIONS && num_allocations < MAX_ALLOCATIONS; j++) {
            int preferred_node = -1;
            
            // For some strategies, pick a specific node
            if (strategy == STRATEGY_CROSS_NUMA || strategy == STRATEGY_LOCAL_NUMA) {
                preferred_node = get_current_numa_node();
            }
            
            if (allocate_memory_strategy(strategy, preferred_node, 
                                       &allocations[num_allocations])) {
                num_allocations++;
            }
            
            // Occasionally trigger memory pressure
            if (i % 100 == 0) {
                cond_resched();
            }
        }
        
        // Free some allocations to create fragmentation
        for (j = 0; j < num_allocations / 2; j++) {
            if (allocations[j].ptr) {
                free_memory_record(&allocations[j]);
            }
        }
        
        // Compact remaining allocations
        int write_pos = 0;
        for (j = 0; j < num_allocations; j++) {
            if (allocations[j].ptr) {
                if (write_pos != j) {
                    allocations[write_pos] = allocations[j];
                }
                write_pos++;
            }
        }
        num_allocations = write_pos;
        
        // Small delay to observe allocation patterns
        if (i % 50 == 0) {
            msleep(1);
        }
    }
    
    // Clean up remaining allocations
    for (i = 0; i < num_allocations; i++) {
        if (allocations[i].ptr) {
            free_memory_record(&allocations[i]);
        }
    }
    num_allocations = 0;
    
    pr_info("Hugepage test completed\n");
    test_running = false;
    return 0;
}

/*
 * Start memory allocation test with specified strategy
 */
static int start_hugepage_test(enum alloc_strategy strategy)
{
    if (test_running) {
        pr_warn("Test already running\n");
        return -EBUSY;
    }
    
    // Clear statistics
    memset(&stats, 0, sizeof(stats));
    num_allocations = 0;
    test_running = true;
    
    test_thread = kthread_create(hugepage_test_thread, &strategy, 
                                "hugepage_test");
    if (IS_ERR(test_thread)) {
        pr_err("Failed to create test thread\n");
        test_running = false;
        return PTR_ERR(test_thread);
    }
    
    wake_up_process(test_thread);
    return 0;
}

/*
 * Stop running test
 */
static void stop_hugepage_test(void)
{
    int i;
    
    if (!test_running)
        return;
        
    if (test_thread) {
        kthread_stop(test_thread);
        test_thread = NULL;
    }
    
    // Clean up any remaining allocations
    for (i = 0; i < num_allocations; i++) {
        if (allocations[i].ptr) {
            free_memory_record(&allocations[i]);
        }
    }
    num_allocations = 0;
    test_running = false;
    
    pr_info("Hugepage test stopped\n");
}

static int hugepage_numa_show(struct seq_file *m, void *v)
{
    int node;
    unsigned long total_allocs = 0;
    unsigned long total_latency = 0;
    
    seq_printf(m, "=== HugePage & NUMA Allocation Demo ===\n\n");
    
    seq_printf(m, "System Information:\n");
    seq_printf(m, "  NUMA Nodes: %d\n", num_online_nodes());
    seq_printf(m, "  Current Node: %d\n", get_current_numa_node());
    seq_printf(m, "  Normal Page Size: %lu KB\n", PAGE_SIZE / 1024);
    seq_printf(m, "  Huge Page Size: %d KB\n", HUGEPAGE_SIZE / 1024);
    seq_printf(m, "  Test Status: %s\n\n", test_running ? "RUNNING" : "STOPPED");
    
    seq_printf(m, "Current Allocations: %d/%d\n", num_allocations, MAX_ALLOCATIONS);
    if (num_allocations > 0) {
        seq_printf(m, "Allocation Breakdown:\n");
        for (int i = 0; i < min(10, num_allocations); i++) {
            seq_printf(m, "  [%d] %s %zu KB on node %d (cycles: %llu)\n",
                      i, allocations[i].is_hugepage ? "HUGE" : "NORM",
                      allocations[i].size / 1024, allocations[i].node,
                      allocations[i].alloc_time);
        }
        if (num_allocations > 10) {
            seq_printf(m, "  ... and %d more\n", num_allocations - 10);
        }
    }
    seq_printf(m, "\n");
    
    seq_printf(m, "NUMA Node Statistics:\n");
    for_each_online_node(node) {
        unsigned long avg_alloc_latency = 0;
        unsigned long avg_free_latency = 0;
        
        if (stats.alloc_count[node] > 0) {
            avg_alloc_latency = stats.alloc_latency[node] / stats.alloc_count[node];
            avg_free_latency = stats.free_latency[node] / stats.alloc_count[node];
        }
        
        seq_printf(m, "  Node %d:\n", node);
        seq_printf(m, "    Allocations: %lu\n", stats.alloc_count[node]);
        seq_printf(m, "    Avg Alloc Latency: %lu cycles\n", avg_alloc_latency);
        seq_printf(m, "    Avg Free Latency: %lu cycles\n", avg_free_latency);
        seq_printf(m, "    Fragmentation Score: %lu%%\n", stats.fragmentation_score[node]);
        
        total_allocs += stats.alloc_count[node];
        total_latency += avg_alloc_latency;
    }
    
    seq_printf(m, "\nCross-NUMA Analysis:\n");
    seq_printf(m, "  Local Node Allocations: %lu\n", stats.local_node_count);
    seq_printf(m, "  Cross Node Allocations: %lu\n", stats.cross_node_count);
    if (total_allocs > 0) {
        seq_printf(m, "  Average Latency: %lu cycles\n", total_latency / num_online_nodes());
    }
    
    seq_printf(m, "\nAvailable Strategies:\n");
    for (int i = 0; i < ARRAY_SIZE(strategy_names); i++) {
        seq_printf(m, "  %d: %s\n", i, strategy_names[i]);
    }
    
    seq_printf(m, "\nCommands:\n");
    seq_printf(m, "  echo 'start <strategy>' > /proc/%s  # Start test (0-4)\n", PROC_NAME);
    seq_printf(m, "  echo 'stop' > /proc/%s             # Stop test\n", PROC_NAME);
    
    seq_printf(m, "\nAnalysis Tips:\n");
    seq_printf(m, "  - Compare allocation latency across NUMA nodes\n");
    seq_printf(m, "  - Monitor fragmentation under different strategies\n");
    seq_printf(m, "  - Use 'numastat' to see system-wide NUMA statistics\n");
    seq_printf(m, "  - Check /proc/buddyinfo for memory fragmentation\n");
    seq_printf(m, "  - Use 'perf stat -e node-loads,node-load-misses' during test\n");
    
    return 0;
}

static int hugepage_numa_open(struct inode *inode, struct file *file)
{
    return single_open(file, hugepage_numa_show, NULL);
}

static ssize_t hugepage_numa_write(struct file *file, const char __user *buffer,
                                  size_t count, loff_t *pos)
{
    char cmd[32];
    int strategy;
    
    if (count >= sizeof(cmd))
        return -EINVAL;
    
    if (copy_from_user(cmd, buffer, count))
        return -EFAULT;
    
    cmd[count] = '\0';
    
    if (sscanf(cmd, "start %d", &strategy) == 1) {
        if (strategy >= 0 && strategy < ARRAY_SIZE(strategy_names)) {
            int ret = start_hugepage_test(strategy);
            if (ret)
                return ret;
            pr_info("Started hugepage test with strategy: %s\n", 
                    strategy_names[strategy]);
        } else {
            return -EINVAL;
        }
    } else if (strncmp(cmd, "stop", 4) == 0) {
        stop_hugepage_test();
    } else {
        return -EINVAL;
    }
    
    return count;
}

static const struct proc_ops hugepage_numa_proc_ops = {
    .proc_open = hugepage_numa_open,
    .proc_read = seq_read,
    .proc_write = hugepage_numa_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init hugepage_numa_init(void)
{
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &hugepage_numa_proc_ops);
    if (!proc_entry) {
        pr_err("Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }
    
    pr_info("HugePage NUMA demo module loaded\n");
    pr_info("Access via: cat /proc/%s\n", PROC_NAME);
    
    return 0;
}

static void __exit hugepage_numa_exit(void)
{
    stop_hugepage_test();
    
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    
    pr_info("HugePage NUMA demo module unloaded\n");
}

module_init(hugepage_numa_init);
module_exit(hugepage_numa_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CoreTracer Project");
MODULE_DESCRIPTION("HugePage and NUMA cross-node allocation performance demonstration");
MODULE_VERSION("1.0");