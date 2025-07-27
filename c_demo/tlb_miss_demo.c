#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <string.h>

#define SIZE_GB 1          // Further reduce to 1GB
#define PAGE_SIZE 4096     
#define HUGE_PAGE_SIZE (2*1024*1024)  // 2MB huge pages
#define ITERATIONS 100000             // Much fewer iterations - 100K should be enough

// Pure TLB stress test - designed to maximize TLB misses
double tlb_stress_test(char *arr, size_t size, const char* test_name) {
    volatile char sum = 0;
    struct timespec start, end;
    size_t num_pages = size / PAGE_SIZE;
    
    printf("%s: Testing %zu pages...\n", test_name, num_pages);
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    // Access pattern designed to stress TLB
    for (int iter = 0; iter < ITERATIONS; iter++) {
        // Access every 16th page for good TLB pressure with fewer iterations
        for (size_t page = 0; page < num_pages; page += 16) {
            sum += arr[page * PAGE_SIZE];
        }
        // Progress indicator for long tests
        if (iter % 10000 == 0 && iter > 0) {
            printf("  Progress: %d/%d iterations (%.1f%%)\n", 
                   iter, ITERATIONS, (float)iter/ITERATIONS*100);
        }
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double elapsed = (end.tv_sec - start.tv_sec) * 1e3 + 
                    (end.tv_nsec - start.tv_nsec) / 1e6;
    
    printf("%s: Completed in %.2f ms (sum=%d)\n", test_name, elapsed, sum);
    return elapsed;
}

void check_hugepage_config() {
    FILE *f = fopen("/proc/meminfo", "r");
    char line[256];
    
    printf("=== HugePage Configuration ===\n");
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "HugePages_") || strstr(line, "Hugepagesize")) {
            printf("%s", line);
        }
    }
    fclose(f);
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s [4k|2m]\n", argv[0]);
        return 1;
    }
    
    int use_hugepage = (strcmp(argv[1], "2m") == 0);
    size_t size = SIZE_GB * 1024ULL * 1024ULL * 1024ULL;
    
    printf("=== TLB Test: %s ===\n", use_hugepage ? "2MB Pages" : "4KB Pages");
    printf("Memory size: %zu GB, Iterations: %d\n\n", SIZE_GB, ITERATIONS);
    
    check_hugepage_config();
    
    char *memory = mmap(NULL, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }
    
    if (use_hugepage) {
        // Try explicit huge pages first
        char *huge = mmap(NULL, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE, 
                         -1, 0);
        
        if (huge == MAP_FAILED) {
            printf("HugePage allocation failed, using THP...\n");
            // Force transparent huge pages
            if (madvise(memory, size, MADV_HUGEPAGE) != 0) {
                perror("madvise MADV_HUGEPAGE failed");
            }
        } else {
            printf("Using explicit HugePages\n");
            munmap(memory, size);
            memory = huge;
        }
    } else {
        // Explicitly prevent huge pages
        if (madvise(memory, size, MADV_NOHUGEPAGE) != 0) {
            perror("madvise NOHUGEPAGE failed");
        }
    }
    
    // Initialize memory
    memset(memory, 1, size);
    
    printf("Starting test...\n");
    double elapsed = tlb_stress_test(memory, size, use_hugepage ? "Huge 2MB pages" : "Normal 4KB pages");
    
    printf("\n=== Results ===\n");
    printf("%s: %.2f ms\n", use_hugepage ? "Huge 2MB" : "Normal 4KB", elapsed);
    
    munmap(memory, size);
    return 0;
}
