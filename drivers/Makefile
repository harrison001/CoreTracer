# CoreTracer Kernel Drivers Makefile
# High-performance debugging and profiling kernel modules

# Kernel build directory - adjust if needed
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Module names
MODULES = affinity_numa_demo lockfree_ring_demo cacheline_false_demo bank_conflict_demo

# Module objects
obj-m += affinity_numa_demo.o
obj-m += lockfree_ring_demo.o
obj-m += cacheline_false_demo.o
obj-m += bank_conflict_demo.o

# Compiler flags for debugging and optimization
ccflags-y += -DDEBUG
ccflags-y += -g
ccflags-y += -O2
ccflags-y += -Wall
ccflags-y += -Wextra

# Default target
all: modules

# Build kernel modules
modules:
	@echo "Building CoreTracer kernel modules..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	@echo "Build complete!"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.mod *.mod.c .*.cmd *.o *.ko.unsigned *.ko.ur-safe
	rm -rf .tmp_versions/
	@echo "Clean complete!"

# Install modules (requires root)
install: modules
	@echo "Installing CoreTracer modules..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a
	@echo "Installation complete!"

# Load all modules
load: modules
	@echo "Loading CoreTracer modules..."
	@for module in $(MODULES); do \
		if lsmod | grep -q $$module; then \
			echo "Module $$module already loaded"; \
		else \
			echo "Loading $$module..."; \
			sudo insmod $$module.ko || echo "Failed to load $$module"; \
		fi; \
	done
	@echo "Module loading complete!"
	@echo "Available interfaces:"
	@ls -la /proc/affinity_numa /proc/lockfree_ring /proc/cacheline_false /proc/bank_conflict 2>/dev/null || echo "Some proc entries may not be available"

# Unload all modules
unload:
	@echo "Unloading CoreTracer modules..."
	@for module in $(MODULES); do \
		if lsmod | grep -q $$module; then \
			echo "Unloading $$module..."; \
			sudo rmmod $$module || echo "Failed to unload $$module"; \
		else \
			echo "Module $$module not loaded"; \
		fi; \
	done
	@echo "Module unloading complete!"

# Reload all modules (unload then load)
reload: unload load

# Check module status
status:
	@echo "CoreTracer module status:"
	@for module in $(MODULES); do \
		if lsmod | grep -q $$module; then \
			echo "  $$module: LOADED"; \
		else \
			echo "  $$module: NOT LOADED"; \
		fi; \
	done
	@echo ""
	@echo "Available proc interfaces:"
	@ls -la /proc/affinity_numa /proc/lockfree_ring /proc/cacheline_false /proc/bank_conflict 2>/dev/null | sed 's/^/  /' || echo "  No proc entries found"

# Show kernel log messages from modules
dmesg:
	@echo "Recent kernel messages from CoreTracer modules:"
	@dmesg | grep -E "(affinity_numa|lockfree_ring|cacheline_false|bank_conflict)" | tail -20

# Test all modules with basic commands
test: load
	@echo "Running basic tests on all modules..."
	@echo ""
	@echo "=== CPU Affinity/NUMA Demo ==="
	@cat /proc/affinity_numa | head -20
	@echo ""
	@echo "=== Lock-free Ring Demo ==="
	@cat /proc/lockfree_ring | head -20
	@echo ""
	@echo "=== Cacheline False Sharing Demo ==="
	@cat /proc/cacheline_false | head -20
	@echo ""
	@echo "=== Memory Bank Conflict Demo ==="
	@cat /proc/bank_conflict | head -20
	@echo ""
	@echo "Test complete! Use individual module interfaces for detailed testing."

# Help target
help:
	@echo "CoreTracer Kernel Drivers Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all/modules  - Build all kernel modules"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install modules to system (requires root)"
	@echo "  load         - Load all modules"
	@echo "  unload       - Unload all modules"
	@echo "  reload       - Unload then load all modules"
	@echo "  status       - Show module load status"
	@echo "  dmesg        - Show recent kernel messages from modules"
	@echo "  test         - Load modules and run basic tests"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Individual module usage:"
	@echo "  cat /proc/affinity_numa     # CPU affinity and NUMA demo"
	@echo "  cat /proc/lockfree_ring     # Lock-free ring buffer demo"  
	@echo "  cat /proc/cacheline_false   # Cache line false sharing demo"
	@echo "  cat /proc/bank_conflict     # Memory bank conflict demo"
	@echo ""
	@echo "Example workflow:"
	@echo "  make               # Build modules"
	@echo "  make load          # Load modules"
	@echo "  make test          # Basic functionality test"
	@echo "  make status        # Check status"
	@echo "  make unload        # Unload when done"

# Safety check for kernel version compatibility
check-kernel:
	@echo "Checking kernel compatibility..."
	@if [ ! -d "$(KDIR)" ]; then \
		echo "ERROR: Kernel headers not found at $(KDIR)"; \
		echo "Install kernel headers: sudo apt-get install linux-headers-$(shell uname -r)"; \
		exit 1; \
	fi
	@echo "Kernel version: $(shell uname -r)"
	@echo "Kernel build directory: $(KDIR)"
	@echo "Kernel compatibility check passed!"

# Debugging target to show build variables
debug-vars:
	@echo "Build variables:"
	@echo "  KDIR = $(KDIR)"
	@echo "  PWD = $(PWD)"
	@echo "  MODULES = $(MODULES)"
	@echo "  obj-m = $(obj-m)"
	@echo "  ccflags-y = $(ccflags-y)"

.PHONY: all modules clean install load unload reload status dmesg test help check-kernel debug-vars