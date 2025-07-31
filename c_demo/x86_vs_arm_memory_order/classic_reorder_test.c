#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <stdatomic.h>

// Global variables - the classic test setup
volatile int X = 0, Y = 0;
volatile int r1 = -1, r2 = -1;

// Synchronization
sem_t beginSema1, beginSema2, endSema;

// Statistics
int iterations = 1000000;
int reorder_detected = 0;
int use_fence = 0;

// Memory barriers
void memory_barrier() {
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("mfence" ::: "memory");
#elif defined(__aarch64__) || defined(__arm__)
    __asm__ volatile("dsb sy" ::: "memory");
#else
    __sync_synchronize();
#endif
}

void compiler_barrier() {
    __asm__ volatile("" ::: "memory");
}

// Simple random delay to increase reordering probability
void random_delay() {
    volatile int delay = rand() % 8;
    for (volatile int i = 0; i < delay; i++);
}

// Thread 1: X = 1; r1 = Y;
void *thread1_func(void *param) {
    for (int i = 0; i < iterations; i++) {
        // Wait for synchronization
        sem_wait(&beginSema1);
        
        // Random delay to increase collision probability
        random_delay();
        
        // The classic test sequence
        X = 1;
        if (use_fence) memory_barrier();
        else compiler_barrier();  // Prevent compiler reordering only
        r1 = Y;
        
        // Signal completion
        sem_post(&endSema);
    }
    return NULL;
}

// Thread 2: Y = 1; r2 = X;
void *thread2_func(void *param) {
    for (int i = 0; i < iterations; i++) {
        // Wait for synchronization
        sem_wait(&beginSema2);
        
        // Random delay to increase collision probability
        random_delay();
        
        // The classic test sequence
        Y = 1;
        if (use_fence) memory_barrier();
        else compiler_barrier();  // Prevent compiler reordering only
        r2 = X;
        
        // Signal completion
        sem_post(&endSema);
    }
    return NULL;
}

const char* get_architecture() {
#if defined(__x86_64__)
    return "x86_64";
#elif defined(__i386__)
    return "x86";
#elif defined(__aarch64__)
    return "ARM64";
#elif defined(__arm__)  
    return "ARM32";
#else
    return "Unknown";
#endif
}

int run_classic_test(int num_iterations, int with_fence) {
    iterations = num_iterations;
    use_fence = with_fence;
    reorder_detected = 0;
    
    // Initialize semaphores
    sem_init(&beginSema1, 0, 0);
    sem_init(&beginSema2, 0, 0);
    sem_init(&endSema, 0, 0);
    
    // Create threads
    pthread_t thread1, thread2;
    pthread_create(&thread1, NULL, thread1_func, NULL);
    pthread_create(&thread2, NULL, thread2_func, NULL);
    
    // Run the test iterations
    for (int i = 0; i < iterations; i++) {
        // Reset variables
        X = 0; Y = 0; r1 = -1; r2 = -1;
        
        // Start both threads simultaneously
        sem_post(&beginSema1);
        sem_post(&beginSema2);
        
        // Wait for both threads to complete
        sem_wait(&endSema);
        sem_wait(&endSema);
        
        // Check for the classic reordering pattern: r1 == 0 && r2 == 0
        if (r1 == 0 && r2 == 0) {
            reorder_detected++;
        }
        
        // Progress indicator for long runs
        if (i % 10000 == 0 && i > 0) {
            printf(".");
            fflush(stdout);
        }
    }
    
    // Cleanup
    pthread_cancel(thread1);
    pthread_cancel(thread2);
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    
    sem_destroy(&beginSema1);
    sem_destroy(&beginSema2);
    sem_destroy(&endSema);
    
    return reorder_detected;
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        printf("Usage: %s <iterations> [fence 0|1]\n", argv[0]);
        printf("  iterations: number of test iterations\n");
        printf("  fence: 0=no fence, 1=memory fence (default: compare both)\n");
        printf("\nClassic Store→Load reordering test:\n");
        printf("  Thread1: X=1; r1=Y    Thread2: Y=1; r2=X\n");
        printf("  Detects: r1==0 && r2==0 (impossible without reordering)\n");
        return 1;
    }
    
    int num_iterations = atoi(argv[1]);
    int fence_mode = (argc > 2) ? atoi(argv[2]) : -1;
    
    // Seed random number generator
    srand(time(NULL));
    
    printf("🏗️  Architecture: %s\n", get_architecture());
    printf("🧪 Classic Memory Reordering Test (Store→Load)\n");
    printf("📊 %d iterations\n", num_iterations);
    printf("\n🔬 Test Pattern:\n");
    printf("   Thread1: X=1; r1=Y    Thread2: Y=1; r2=X\n");
    printf("   Detection: r1==0 && r2==0 (Store→Load reordering)\n\n");
    
    if (fence_mode == -1) {
        // Compare with and without fence
        printf("🚫 Without memory fence: ");
        fflush(stdout);
        int reorders_no_fence = run_classic_test(num_iterations, 0);
        double rate_no_fence = (double)reorders_no_fence / num_iterations * 100.0;
        printf(" %d reorderings (%.4f%%)\n", reorders_no_fence, rate_no_fence);
        
        printf("🛡️  With memory fence: ");
        fflush(stdout);
        int reorders_with_fence = run_classic_test(num_iterations, 1);
        double rate_with_fence = (double)reorders_with_fence / num_iterations * 100.0;
        printf(" %d reorderings (%.4f%%)\n", reorders_with_fence, rate_with_fence);
        
        printf("\n📈 Results:\n");
        if (reorders_with_fence == 0 && reorders_no_fence > 0) {
            printf("  ✅ Memory fence completely eliminated reordering!\n");
            printf("  🎯 Effectiveness: 100%% reduction\n");
        } else if (reorders_with_fence < reorders_no_fence) {
            double reduction = (1.0 - (double)reorders_with_fence / reorders_no_fence) * 100.0;
            printf("  ⚠️  Memory fence reduced reordering by %.1f%%\n", reduction);
        } else if (reorders_no_fence == 0) {
            printf("  ℹ️  No reordering detected - try more iterations or different CPU\n");
        } else {
            printf("  ❌ Memory fence failed to prevent reordering\n");
        }
        
        // Architecture-specific analysis
        const char* arch = get_architecture();
        printf("\n💡 Architecture Analysis (%s):\n", arch);
        if (strstr(arch, "x86") || strstr(arch, "X86")) {
            printf("  • x86 TSO allows Store→Load reordering due to store buffer\n");
            printf("  • MFENCE should completely prevent this reordering\n");
        } else if (strstr(arch, "ARM") || strstr(arch, "arm")) {
            printf("  • ARM weak memory model allows extensive reordering\n");
            printf("  • DSB SY should completely prevent this reordering\n");
        }
        
    } else {
        // Single test mode
        const char* fence_str = fence_mode ? "with memory fence" : "without memory fence";
        printf("Running %s: ", fence_str);
        fflush(stdout);
        
        int reorders = run_classic_test(num_iterations, fence_mode);
        double rate = (double)reorders / num_iterations * 100.0;
        printf(" %d reorderings (%.4f%%)\n", reorders, rate);
        
        if (fence_mode && reorders > 0) {
            printf("⚠️  Unexpected: Memory fence should prevent all reordering!\n");
        }
    }
    
    return 0;
}