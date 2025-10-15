# Compiler
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -g

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
all: $(OBJ_DIR) $(BIN_DIR) $(APPS) $(TESTS)

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
test: $(TESTS)
	@echo "Running all tests..."
	@for t in $(TESTS); do \
		echo "===== Running $$t ====="; \
		$$t; \
		echo ""; \
	done
	@echo "All tests completed."

# Clean
clean:
	rm -rf $(OBJ_DIR)/*.o $(BIN_DIR)/*

.PHONY: all clean test
