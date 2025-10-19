# Compiler
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -g
LDFLAGS = 

# Coverage flags
CFLAGS_COVERAGE = -Wall -Wextra -Iinclude -g -O0 -fprofile-arcs -ftest-coverage
LDFLAGS_COVERAGE = -fprofile-arcs -ftest-coverage

# Debug toggle
ifeq ($(DEBUG),1)
    CFLAGS += -DCCM_DEBUG
endif

# Directories
SRC_DIR = src
INCLUDE_DIR = include
APP_DIR = apps
TEST_DIR = tests
OBJ_DIR = obj
BIN_DIR = bin

# Sources and objects
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

APP_SRCS = $(wildcard $(APP_DIR)/*.c)
TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)

APPS = $(patsubst $(APP_DIR)/%.c, $(BIN_DIR)/%, $(APP_SRCS))
TESTS = $(patsubst $(TEST_DIR)/%.c, $(BIN_DIR)/%, $(TEST_SRCS))

# Default target
all: $(OBJ_DIR) $(BIN_DIR) apps tests

# Build apps and tests separately
apps: $(APPS)
tests: $(TESTS)

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile apps
$(BIN_DIR)/%: $(APP_DIR)/%.c $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@

# Compile tests
$(BIN_DIR)/%: $(TEST_DIR)/%.c $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@

# Create directories
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Run all tests dynamically
test: tests
	@echo "Running all tests..."
	@failed=0; \
	for t in $(TESTS); do \
		echo "===== Running $$t ====="; \
		$$t; \
		ret=$$?; \
		if [ $$ret -ne 0 ]; then \
			echo ">>> TEST FAILED: $$t <<<"; \
			failed=1; \
		fi; \
		echo ""; \
	done; \
	if [ $$failed -ne 0 ]; then \
		echo "Some tests FAILED!"; \
		exit 1; \
	else \
		echo "All tests PASSED."; \
	fi

# Coverage targets
coverage: clean_coverage
	@echo "Building tests with coverage flags..."
	$(MAKE) clean
	$(MAKE) CFLAGS="$(CFLAGS_COVERAGE)" LDFLAGS="$(LDFLAGS_COVERAGE)" all
	@echo "Running tests for coverage..."
	$(MAKE) test
	@echo "Capturing coverage..."
	lcov --capture --directory . --output-file coverage.info --ignore-errors unsupported,unused
	genhtml coverage.info --output-directory coverage-report
	@echo "Coverage report generated: coverage-report/index.html"

clean_coverage:
	rm -f *.gcda *.gcno coverage.info
	rm -rf coverage-report

# Optional: quick badge
badge:
	@coverage=$(shell lcov --summary coverage.info 2>/dev/null | awk '/lines/ {val=$$3; gsub("%","",val); print int(val)}'); \
	if [ -z "$$coverage" ]; then coverage=0; fi; \
	echo "![Coverage](https://img.shields.io/badge/coverage-$$coverage%25-brightgreen)"

# Clean
clean:
	rm -rf $(OBJ_DIR)/*.o $(BIN_DIR)/*
