# Wieen — build rules
#
#   make agent        the agent that runs inside the Roblox client
#   make compile      the host side Luau compiler
#   make symbols      regenerate src/agent/luau_symbols.h for the current client

CC      ?= gcc
CXX     ?= g++
CFLAGS  ?= -O2 -fPIC -fno-stack-protector -Wall -Wextra -Wno-unused-parameter
LDFLAGS ?= -shared -Wl,--build-id=none

AGENT_DIR := src/agent
BUILD_DIR := build
AGENT     := $(BUILD_DIR)/wieen_agent.so
COMPILER  := $(BUILD_DIR)/wieen-compile

LUAU_DIR  := work/luau-src
LUAU_LIB  := $(LUAU_DIR)/build-rel

.PHONY: all agent compile symbols clean

all: agent compile

agent: $(AGENT)

$(AGENT): $(AGENT_DIR)/wieen_agent.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	@echo "built $@"

compile: $(COMPILER)

$(COMPILER): tools/wieen_compile.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) -O2 -o $@ $< \
	    -I $(LUAU_DIR)/Compiler/include -I $(LUAU_DIR)/Common/include -I $(LUAU_DIR)/VM/include \
	    $(LUAU_LIB)/libLuau.Compiler.a $(LUAU_LIB)/libLuau.Bytecode.a \
	    $(LUAU_LIB)/libLuau.Ast.a $(LUAU_LIB)/libLuau.Common.a
	@echo "built $@"

# regenerate the Luau symbol table for the current Roblox client build
symbols:
	python3 tools/scan_symbols.py

clean:
	rm -rf $(BUILD_DIR)
