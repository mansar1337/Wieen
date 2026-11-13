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

# the probe of the agent is compiled here: the client has the VM, but not
# the compiler, so the bytes are put into the agent before it is built
PROBE_SRC := tools/probe.luau
PROBE_BIN := $(BUILD_DIR)/probe.bin
PROBE_HDR := $(BUILD_DIR)/probe_bytecode.h

LUAU_DIR  := work/luau-src
LUAU_LIB  := $(LUAU_DIR)/build-rel

# where the agent lives inside the flatpak sandbox
SOBER_DATA := $(HOME)/.var/app/org.vinegarhq.Sober/data/wieen

.PHONY: all agent compile deploy install symbols clean

all: agent compile

agent: $(AGENT)

$(AGENT): $(AGENT_DIR)/wieen_agent.c $(PROBE_HDR)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -I $(BUILD_DIR) -o $@ $<
	@echo "built $@"

$(PROBE_HDR): $(PROBE_SRC) $(COMPILER) tools/bin2h.py
	@mkdir -p $(BUILD_DIR)
	$(COMPILER) $(PROBE_SRC) > $(PROBE_BIN)
	python3 tools/bin2h.py $(PROBE_BIN) wieen_probe > $@

compile: $(COMPILER)

$(COMPILER): tools/wieen_compile.cpp tools/opcode_map.h
	@mkdir -p $(BUILD_DIR)
	$(CXX) -O2 -o $@ $< \
	    -I $(LUAU_DIR)/Compiler/include -I $(LUAU_DIR)/Common/include -I $(LUAU_DIR)/VM/include \
	    -I $(LUAU_DIR)/Ast/include \
	    $(LUAU_LIB)/libLuau.Compiler.a $(LUAU_LIB)/libLuau.Bytecode.a \
	    $(LUAU_LIB)/libLuau.Ast.a $(LUAU_LIB)/libLuau.Common.a
	@echo "built $@"

# the agent is loaded when the client starts, so it has to be in place
# before Sober is started again
deploy: agent
	@mkdir -p $(SOBER_DATA)
	@# a copy over the running file kills the client with SIGBUS: the old
	@# library is mapped, and rewriting it in place breaks the mapping.  A
	@# new file and a rename leave the running process alone.
	cp $(AGENT) $(SOBER_DATA)/wieen_agent.so.new
	mv $(SOBER_DATA)/wieen_agent.so.new $(SOBER_DATA)/wieen_agent.so
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
