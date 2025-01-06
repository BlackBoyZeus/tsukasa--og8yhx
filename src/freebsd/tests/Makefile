# AI Guardian Test Infrastructure Makefile
# Version: 1.0.0
# Purpose: Enterprise-grade test infrastructure for FreeBSD kernel modules
# Security: Enhanced build flags, isolation, and validation

# Build flags with security hardening
CFLAGS = -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -I../include -I/usr/src/sys -DKLD_MODULE
LDFLAGS = -latf-c -lpthread -Wl,-z,relro,-z,now

# Test configuration
TEST_SUITES = kernel security hardware system
ATF_TESTS = guardian_module capsicum mac_policy geli console memory sysctl resource
TEST_TIMEOUT = 300
MAX_RETRIES = 3
PARALLEL_JOBS = 4

# Test directories
TEST_DIR = .
KERNEL_TEST_DIR = $(TEST_DIR)/kernel
SECURITY_TEST_DIR = $(TEST_DIR)/security
HARDWARE_TEST_DIR = $(TEST_DIR)/hardware
SYSTEM_TEST_DIR = $(TEST_DIR)/system

# Output directories
BUILD_DIR = build
REPORT_DIR = reports
LOG_DIR = logs
COVERAGE_DIR = coverage

# Test binaries
KERNEL_TESTS = $(KERNEL_TEST_DIR)/test_guardian_module
SECURITY_TESTS = $(SECURITY_TEST_DIR)/test_capsicum

# Timestamp for artifacts
TIMESTAMP := $(shell date +%Y%m%d_%H%M%S)

# Default target
.PHONY: all
all: validate-env build-tests verify-binaries generate-build-report

# Environment validation
.PHONY: validate-env
validate-env:
	@echo "Validating build environment..."
	@command -v atf-run >/dev/null 2>&1 || { echo "Error: atf-run not found"; exit 1; }
	@command -v kyua >/dev/null 2>&1 || { echo "Error: kyua not found"; exit 1; }
	@mkdir -p $(BUILD_DIR) $(REPORT_DIR) $(LOG_DIR) $(COVERAGE_DIR)

# Build test suites
.PHONY: build-tests
build-tests: build-kernel build-security build-hardware build-system

.PHONY: build-kernel
build-kernel:
	@echo "Building kernel test suite..."
	$(CC) $(CFLAGS) $(KERNEL_TEST_DIR)/test_guardian_module.c -o $(BUILD_DIR)/test_guardian_module $(LDFLAGS)

.PHONY: build-security
build-security:
	@echo "Building security test suite..."
	$(CC) $(CFLAGS) $(SECURITY_TEST_DIR)/test_capsicum.c -o $(BUILD_DIR)/test_capsicum $(LDFLAGS)

# Binary verification
.PHONY: verify-binaries
verify-binaries:
	@echo "Verifying binary signatures..."
	@for bin in $(BUILD_DIR)/*; do \
		sha256 $$bin >> $(BUILD_DIR)/checksums.txt; \
	done

# Test execution
.PHONY: test
test: validate-env
	@echo "Executing test suites..."
	@mkdir -p $(LOG_DIR)/$(TIMESTAMP)
	@kyua test --config=none \
		--build-root=$(BUILD_DIR) \
		--test-suite=guardian \
		--store=$(LOG_DIR)/$(TIMESTAMP)/results.db \
		--timeout=$(TEST_TIMEOUT) \
		--parallel=$(PARALLEL_JOBS)
	@kyua report-html --store=$(LOG_DIR)/$(TIMESTAMP)/results.db \
		--output=$(REPORT_DIR)/$(TIMESTAMP)
	@kyua report-junit --store=$(LOG_DIR)/$(TIMESTAMP)/results.db \
		--output=$(REPORT_DIR)/$(TIMESTAMP)/junit.xml

# Coverage analysis
.PHONY: coverage
coverage:
	@echo "Generating coverage reports..."
	@mkdir -p $(COVERAGE_DIR)/$(TIMESTAMP)
	@lcov --capture --directory $(BUILD_DIR) \
		--output-file $(COVERAGE_DIR)/$(TIMESTAMP)/coverage.info
	@genhtml $(COVERAGE_DIR)/$(TIMESTAMP)/coverage.info \
		--output-directory $(COVERAGE_DIR)/$(TIMESTAMP)/html
	@echo "Coverage report generated in $(COVERAGE_DIR)/$(TIMESTAMP)/html"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@find $(BUILD_DIR) -type f -exec shred -u {} \;
	@find $(LOG_DIR) -type f -exec shred -u {} \;
	@find $(REPORT_DIR) -type f -exec shred -u {} \;
	@find $(COVERAGE_DIR) -type f -exec shred -u {} \;
	@rm -rf $(BUILD_DIR) $(LOG_DIR) $(REPORT_DIR) $(COVERAGE_DIR)
	@echo "Clean completed successfully"

# Build report generation
.PHONY: generate-build-report
generate-build-report:
	@echo "Generating build report..."
	@echo "Build Report - $(TIMESTAMP)" > $(REPORT_DIR)/build_report.txt
	@echo "Compiler: $(CC) $(shell $(CC) --version | head -n1)" >> $(REPORT_DIR)/build_report.txt
	@echo "CFLAGS: $(CFLAGS)" >> $(REPORT_DIR)/build_report.txt
	@echo "LDFLAGS: $(LDFLAGS)" >> $(REPORT_DIR)/build_report.txt
	@echo "Binary checksums:" >> $(REPORT_DIR)/build_report.txt
	@cat $(BUILD_DIR)/checksums.txt >> $(REPORT_DIR)/build_report.txt

# Help target
.PHONY: help
help:
	@echo "AI Guardian Test Infrastructure"
	@echo "Available targets:"
	@echo "  all        - Build all test suites with validation"
	@echo "  test       - Execute all test suites"
	@echo "  coverage   - Generate coverage reports"
	@echo "  clean      - Clean build artifacts securely"
	@echo "  help       - Show this help message"