# Wieen — build rules
#
#   make agent        the agent that runs inside the Roblox client
#   make compile      the host side Luau compiler
#   make deploy       build the agent and put it where Sober picks it up
#   make install      the same, and register the agent in the runtime
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

# where the agent lives inside the flatpak sandbox
SOBER_DATA := $(HOME)/.var/app/org.vinegarhq.Sober/data/wieen

.PHONY: all agent compile deploy install symbols clean

all: agent compile

agent: $(AGENT)

$(AGENT): $(AGENT_DIR)/wieen_agent.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	@echo "built $@"

compile: $(COMPILER)

$(COMPILER): tools/wieen_compile.cpp tools/opcode_map.h
	@mkdir -p $(BUILD_DIR)
	$(CXX) -O2 -o $@ $< \
	    -I $(LUAU_DIR)/Compiler/include -I $(LUAU_DIR)/Common/include -I $(LUAU_DIR)/VM/include \
	    $(LUAU_LIB)/libLuau.Compiler.a $(LUAU_LIB)/libLuau.Bytecode.a \
	    $(LUAU_LIB)/libLuau.Ast.a $(LUAU_LIB)/libLuau.Common.a
	@echo "built $@"

# the agent is loaded when the client starts, so it has to be in place
# before Sober is started again
deploy: agent
	@mkdir -p $(SOBER_DATA)
	cp $(AGENT) $(SOBER_DATA)/wieen_agent.so
	@echo "agent deployed to $(SOBER_DATA)/wieen_agent.so"
	@echo "restart Sober for it to take effect"

# the same, and register the agent in the runtime (needs root)
install: deploy
	sudo tools/install_preload.sh

# regenerate the Luau symbol table for the current Roblox client build
symbols:
	python3 tools/scan_symbols.py

clean:
	rm -rf $(BUILD_DIR)
