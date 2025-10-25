# Makefile — fb shim + relay (no scaffolding)
# Expects existing files:
#   fbshim.c        (shim)
#   touchshim.c    (touch shim)
#   server.go      (UI server)
#
# Quickstart:
#   make armhf          # cross-build libfbshim.so for ARM (optional, edit if your kindle differs)
#   make goserver       # build server, open the sockets, and start the UI
#   make clean			# deletes everything in build/ - careful

SHELL := /bin/zsh
UNAME := $(shell uname)
BUILD := build
PY    := python3

# --- files ---
SHIM_SRC   := fbshim.c
SHIM_TOUCH_SRC   := touchshim.c
TEST_SRC   := fbtest.c
MAC_DYLIB  := $(BUILD)/libfbshim.dylib
# LINUX_SO   := $(BUILD)/libfbshim.so
ARMHF_SO   := $(BUILD)/libfbshim.armhf.so
ARMHF_TOUCH_SO   := $(BUILD)/libtouchshim.armhf.so
TEST_BIN   := $(BUILD)/fbtest

# --- common flags ---
CFLAGS_COMMON := -O2 -fPIC -Wall -Wextra -Wno-unused-parameter
LDFLAGS_COMMON :=
DLFLAGS_LINUX := -ldl
DLFLAGS_MAC   :=                 # dlopen is in libSystem on macOS

# --- toolchains (override if needed) ---
CC        ?= cc
# CC_LINUX  ?= gcc
CC_ARMHF  ?= arm-kindlehf-linux-gnueabihf-gcc

# --- dirs ---
$(BUILD):
	@mkdir -p $@

# =========================
# Build targets
# =========================

.PHONY: all
all: $(UNAME)
	@echo "Built for $(UNAME)"

.PHONY: mac
mac: $(BUILD) $(MAC_DYLIB) $(TEST_BIN)
	@echo "OK: $(MAC_DYLIB)"

$(MAC_DYLIB): $(SHIM_SRC) | $(BUILD)
	$(CC) $(CFLAGS_COMMON) -dynamiclib -o $@ $^ $(LDFLAGS_COMMON) $(DLFLAGS_MAC)

# .PHONY: linux
# linux: $(BUILD) $(LINUX_SO) $(TEST_BIN)
# 	@echo "OK: $(LINUX_SO)"

# $(LINUX_SO): $(SHIM_SRC) | $(BUILD)
# 	$(CC_LINUX) $(CFLAGS_COMMON) -shared -o $@ $^ $(LDFLAGS_COMMON) $(DLFLAGS_LINUX)

# Optional: cross-compile shim for ARMhf (useful for qemu-user)
.PHONY: armhf
armhf: $(BUILD) $(ARMHF_SO) $(ARMHF_TOUCH_SO)
	@echo "OK: $(ARMHF_SO)"
	@echo "OK: $(ARMHF_TOUCH_SO)"

$(ARMHF_SO): $(SHIM_SRC) | $(BUILD)
	$(CC_ARMHF) $(CFLAGS_COMMON) -shared -o $@ $^ $(LDFLAGS_COMMON) -ldl -pthread
	cp $(ARMHF_SO) ~/code/qemu-kindle/build/libfbshim.so  # also copy to generic name for convenience

$(ARMHF_TOUCH_SO): $(SHIM_TOUCH_SRC) | $(BUILD)
	$(CC_ARMHF) $(CFLAGS_COMMON) -shared -o $@ $^ $(LDFLAGS_COMMON) -ldl -pthread
	cp $(ARMHF_TOUCH_SO) ~/code/qemu-kindle/build/libtouchshim.so  # also copy to generic name for convenience

# Tiny test app that does: open("/dev/fb0"), mmap, draw, ioctl("flush")
$(TEST_BIN): $(TEST_SRC) | $(BUILD)
	$(CC) -O2 -Wall -Wextra -o $@ $^

# =========================
# Housekeeping
# =========================
.PHONY: clean
clean:
	rm -rf $(BUILD)

goserver:
	go build -o server server.go
	TOUCH_LOG=1 TOUCH_STREAM_SOCK=/tmp/touchstream.sock FB_STREAM_SOCK=/tmp/fbstream.sock ./server