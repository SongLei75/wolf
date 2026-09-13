SHELL := /bin/bash

ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
META_BUILD_DIR := $(ROOT_DIR)/out/build/meta
CMAKE ?= cmake

.PHONY: linux windows wrapper-linux wrapper-windows all clean

all: linux windows wrapper-linux wrapper-windows

$(META_BUILD_DIR)/CMakeCache.txt: $(ROOT_DIR)/CMakeLists.txt
	mkdir -p $(META_BUILD_DIR)
	$(CMAKE) -S $(ROOT_DIR) -B $(META_BUILD_DIR)

linux: $(META_BUILD_DIR)/CMakeCache.txt
	$(CMAKE) --build $(META_BUILD_DIR) --target linux

windows:
	$(CMAKE) --build $(META_BUILD_DIR) --target windows

wrapper-linux: linux
	mkdir -p $(ROOT_DIR)/wrapper/build
	cd $(ROOT_DIR)/wrapper/build && $(CMAKE) .. -DCMAKE_BUILD_TYPE=Release && $(MAKE) -j$$(nproc)

wrapper-windows: windows
	mkdir -p $(ROOT_DIR)/wrapper/build-win
	cd $(ROOT_DIR)/wrapper/build-win && \
		$(CMAKE) .. -DCMAKE_BUILD_TYPE=Release && \
		$(MAKE) -j$$(nproc)

clean:
	rm -rf $(ROOT_DIR)/out $(ROOT_DIR)/wrapper/build $(ROOT_DIR)/wrapper/build-win
