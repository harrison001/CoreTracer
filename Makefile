# CoreTracer - High-performance kernel & assembly debugging toolkit
# Main project Makefile for building and managing all components

.PHONY: all clean build test install uninstall help
.PHONY: drivers rust asm scripts docs
.PHONY: load-drivers unload-drivers test-drivers
.PHONY: benchmark profile debug

# Project configuration
PROJECT_NAME = CoreTracer
VERSION = 1.0.0
BUILD_DIR = build
INSTALL_PREFIX = /usr/local

# Component directories
DRIVERS_DIR = drivers
RUST_DIR = rust_demo
ASM_DIR = asm
SCRIPTS_DIR = scripts
DOCS_DIR = docs

# Default target
all: build

# Help target - show available commands
help:
	@echo "$(PROJECT_NAME) v$(VERSION) - High-performance kernel & assembly debugging toolkit"
	@echo ""
	@echo "Available targets:"
	@echo "  Build targets:"
	@echo "    all/build    - Build all components"
	@echo "    drivers      - Build kernel driver modules"
	@echo "    rust         - Build Rust demos and benchmarks"
	@echo "    asm          - Assemble assembly demos"
	@echo "    clean        - Clean all build artifacts"
	@echo ""
	@echo "  Testing targets:"
	@echo "    test         - Run all tests and basic functionality checks"
	@echo "    test-drivers - Test kernel drivers"
	@echo "    benchmark    - Run performance benchmarks"
	@echo ""
	@echo "  Driver management:"
	@echo "    load-drivers   - Load all kernel modules"
	@echo "    unload-drivers - Unload all kernel modules"
	@echo ""
	@echo "  Installation:"
	@echo "    install      - Install to system (requires root)"
	@echo "    uninstall    - Remove from system (requires root)"
	@echo ""
	@echo "  Analysis:"
	@echo "    profile      - Run profiling scripts"
	@echo "    debug        - Set up debugging environment"
	@echo ""
	@echo "  Utilities:"
	@echo "    docs         - Generate documentation"
	@echo "    help         - Show this help message"

# Build all components
build: drivers rust asm
	@echo "Building $(PROJECT_NAME) v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	@echo "Build complete!"

# Build kernel drivers
drivers:
	@echo "Building kernel drivers..."
	$(MAKE) -C $(DRIVERS_DIR)
	@echo "Kernel drivers built successfully!"

# Build Rust components
rust:
	@echo "Building Rust demos..."
	cd $(RUST_DIR) && cargo build --release
	@echo "Rust demos built successfully!"

# Assemble assembly demos
asm:
	@echo "Assembling demo files..."
	@mkdir -p $(BUILD_DIR)/asm
	# x86-64 Intel syntax assembly
	gcc -c $(ASM_DIR)/lockfree_asm.S -o $(BUILD_DIR)/asm/lockfree_asm.o
	gcc -c $(ASM_DIR)/cacheline_asm.S -o $(BUILD_DIR)/asm/cacheline_asm.o
	# ARM64 assembly (conditional compilation based on architecture)
	@if [ "$(shell uname -m)" = "aarch64" ]; then \
		gcc -c $(ASM_DIR)/lockfree_asm_arm.S -o $(BUILD_DIR)/asm/lockfree_asm_arm.o; \
		gcc -c $(ASM_DIR)/cacheline_asm_arm.S -o $(BUILD_DIR)/asm/cacheline_asm_arm.o; \
		echo "ARM64 assembly compiled"; \
	else \
		echo "Skipping ARM64 assembly (not on ARM64 platform)"; \
	fi
	@echo "Assembly demos assembled successfully!"

# Clean all build artifacts
clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C $(DRIVERS_DIR) clean || true
	cd $(RUST_DIR) && cargo clean || true
	rm -rf $(BUILD_DIR)
	@echo "Clean complete!"

# Load all kernel driver modules
load-drivers: drivers
	@echo "Loading CoreTracer kernel modules..."
	$(MAKE) -C $(DRIVERS_DIR) load
	@echo "Modules loaded! Check with: make status-drivers"

# Unload all kernel driver modules
unload-drivers:
	@echo "Unloading CoreTracer kernel modules..."
	$(MAKE) -C $(DRIVERS_DIR) unload

# Check driver status
status-drivers:
	@echo "Checking driver status..."
	$(MAKE) -C $(DRIVERS_DIR) status

# Test all components
test: test-drivers test-rust
	@echo "Running comprehensive tests..."
	@echo "All tests completed!"

# Test kernel drivers
test-drivers: load-drivers
	@echo "Testing kernel drivers..."
	$(MAKE) -C $(DRIVERS_DIR) test
	@echo "Driver tests completed!"

# Test Rust components
test-rust: rust
	@echo "Testing Rust components..."
	cd $(RUST_DIR) && cargo test
	@echo "Rust tests completed!"

# Run performance benchmarks
benchmark: rust
	@echo "Running performance benchmarks..."
	cd $(RUST_DIR) && cargo bench
	@echo "Benchmarks completed! Check target/criterion/ for reports"

# Run profiling scripts
profile: load-drivers
	@echo "Running profiling analysis..."
	@if [ -f $(SCRIPTS_DIR)/run_perf_affinity.sh ]; then \
		bash $(SCRIPTS_DIR)/run_perf_affinity.sh; \
	fi
	@if [ -f $(SCRIPTS_DIR)/run_bpftrace_cacheline.sh ]; then \
		bash $(SCRIPTS_DIR)/run_bpftrace_cacheline.sh; \
	fi
	@echo "Profiling complete!"

# Set up debugging environment
debug: load-drivers
	@echo "Setting up debugging environment..."
	@echo "Kernel modules loaded and ready for debugging"
	@echo "Available interfaces:"
	@ls -la /proc/affinity_numa /proc/lockfree_ring /proc/cacheline_false /proc/bank_conflict 2>/dev/null || echo "Some interfaces may not be available"
	@echo ""
	@echo "Debugging tips:"
	@echo "  - Use 'dmesg | tail' to see kernel module messages"
	@echo "  - Use 'cat /proc/<module_name>' to interact with modules"
	@echo "  - Use scripts in $(SCRIPTS_DIR)/ for automated analysis"
	@echo "  - Check docs/ for debugging guides"

# Generate documentation
docs:
	@echo "Generating documentation..."
	cd $(RUST_DIR) && cargo doc --no-deps
	@echo "Documentation generated! Check:"
	@echo "  - Rust docs: $(RUST_DIR)/target/doc/"
	@echo "  - Guides: $(DOCS_DIR)/"

# Install to system (requires root)
install: build
	@echo "Installing $(PROJECT_NAME) to $(INSTALL_PREFIX)..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Installation requires root privileges. Use: sudo make install"; \
		exit 1; \
	fi
	mkdir -p $(INSTALL_PREFIX)/bin
	mkdir -p $(INSTALL_PREFIX)/lib/coretracer
	mkdir -p $(INSTALL_PREFIX)/share/coretracer
	# Install kernel modules
	$(MAKE) -C $(DRIVERS_DIR) install
	# Install Rust binaries
	cp $(RUST_DIR)/target/release/affinity_demo $(INSTALL_PREFIX)/bin/ || true
	cp $(RUST_DIR)/target/release/lockfree_demo $(INSTALL_PREFIX)/bin/ || true
	cp $(RUST_DIR)/target/release/cacheline_demo $(INSTALL_PREFIX)/bin/ || true
	cp $(RUST_DIR)/target/release/bank_conflict_demo $(INSTALL_PREFIX)/bin/ || true
	cp $(RUST_DIR)/target/release/perf_benchmark $(INSTALL_PREFIX)/bin/ || true
	# Install scripts
	cp -r $(SCRIPTS_DIR)/* $(INSTALL_PREFIX)/share/coretracer/ || true
	# Install documentation
	cp -r $(DOCS_DIR)/* $(INSTALL_PREFIX)/share/coretracer/ || true
	@echo "Installation complete!"

# Uninstall from system (requires root)
uninstall:
	@echo "Uninstalling $(PROJECT_NAME)..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Uninstallation requires root privileges. Use: sudo make uninstall"; \
		exit 1; \
	fi
	# Unload modules first
	$(MAKE) unload-drivers || true
	# Remove installed files
	rm -f $(INSTALL_PREFIX)/bin/affinity_demo
	rm -f $(INSTALL_PREFIX)/bin/lockfree_demo
	rm -f $(INSTALL_PREFIX)/bin/cacheline_demo
	rm -f $(INSTALL_PREFIX)/bin/bank_conflict_demo
	rm -f $(INSTALL_PREFIX)/bin/perf_benchmark
	rm -rf $(INSTALL_PREFIX)/lib/coretracer
	rm -rf $(INSTALL_PREFIX)/share/coretracer
	@echo "Uninstallation complete!"

# Quick demo - load drivers and show basic functionality
demo: load-drivers
	@echo "=== CoreTracer Demo ==="
	@echo ""
	@echo "1. CPU Affinity & NUMA Demo:"
	@timeout 3 cat /proc/affinity_numa | head -15 || echo "  (Demo timed out)"
	@echo ""
	@echo "2. Lock-free Ring Demo:"
	@timeout 3 cat /proc/lockfree_ring | head -15 || echo "  (Demo timed out)"
	@echo ""
	@echo "3. Cache Line False Sharing Demo:"
	@timeout 3 cat /proc/cacheline_false | head -15 || echo "  (Demo timed out)"
	@echo ""
	@echo "4. Memory Bank Conflict Demo:"
	@timeout 3 cat /proc/bank_conflict | head -15 || echo "  (Demo timed out)"
	@echo ""
	@echo "Demo complete! Use individual module interfaces for detailed testing."
	@echo "Example: echo 'start' > /proc/affinity_numa"

# Development utilities
dev-setup:
	@echo "Setting up development environment..."
	@echo "Checking dependencies..."
	@which gcc >/dev/null || echo "WARNING: gcc not found"
	@which make >/dev/null || echo "WARNING: make not found"
	@which cargo >/dev/null || echo "WARNING: cargo not found"
	@[ -d /lib/modules/$(shell uname -r)/build ] || echo "WARNING: kernel headers not found"
	@which perf >/dev/null || echo "WARNING: perf not found"
	@which gdb >/dev/null || echo "WARNING: gdb not found"
	@echo "Development environment check complete!"

# Safety checks
check-system:
	@echo "Performing system compatibility checks..."
	@echo "Kernel version: $(shell uname -r)"
	@echo "Architecture: $(shell uname -m)"
	@echo "Available CPUs: $(shell nproc)"
	@echo "Memory: $(shell free -h | grep Mem | awk '{print $$2}')"
	@echo "Kernel headers: $$(ls -d /lib/modules/$(shell uname -r)/build 2>/dev/null || echo 'NOT FOUND')"
	@echo "System compatibility check complete!"

# Show kernel messages from our modules
dmesg:
	@echo "Recent kernel messages from CoreTracer modules:"
	@dmesg | grep -E "(affinity_numa|lockfree_ring|cacheline_false|bank_conflict)" | tail -20 || echo "No recent messages found"

# Show project status
status:
	@echo "$(PROJECT_NAME) v$(VERSION) Status:"
	@echo ""
	@echo "Build status:"
	@echo "  Drivers: $$([ -f $(DRIVERS_DIR)/*.ko 2>/dev/null ] && echo 'Built' || echo 'Not built')"
	@echo "  Rust: $$([ -d $(RUST_DIR)/target/release 2>/dev/null ] && echo 'Built' || echo 'Not built')"
	@echo "  Assembly: $$([ -d $(BUILD_DIR)/asm 2>/dev/null ] && echo 'Built' || echo 'Not built')"
	@echo ""
	@echo "Available assembly files:"
	@echo "  x86-64 Intel syntax: lockfree_asm.S, cacheline_asm.S"
	@echo "  ARM64 AArch64: lockfree_asm_arm.S, cacheline_asm_arm.S"
	@echo "  Architecture: $(shell uname -m)"
	@echo ""
	@$(MAKE) -C $(DRIVERS_DIR) status 2>/dev/null || echo "Driver status unavailable"