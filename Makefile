# Wieen — build rules
#
#   make agent    the agent that runs inside the Roblox client
#   make shim     the loader shim that injects the agent into the client
#   make symbols  regenerate src/agent/luau_symbols.h for the current client

CC      ?= gcc
CFLAGS  ?= -O2 -fPIC -fno-stack-protector -Wall -Wextra -Wno-unused-parameter
LDFLAGS ?= -shared -Wl,--build-id=none

AGENT_DIR := src/agent
BUILD_DIR := build
AGENT     := $(BUILD_DIR)/wieen_agent.so
SHIM      := $(BUILD_DIR)/libbadcpu.so

.PHONY: all agent shim clean symbols

all: agent

agent: $(AGENT)

$(AGENT): $(AGENT_DIR)/wieen_agent.c $(AGENT_DIR)/wieen.h $(AGENT_DIR)/luau_symbols.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(AGENT_DIR)/wieen_agent.c
	@echo "built $@"

shim: $(SHIM)

$(SHIM): $(AGENT_DIR)/badcpu_shim.c
	@mkdir -p $(BUILD_DIR)
	$(CC) -O2 -fPIC -shared -o $@ $<
	@echo "built $@"

# regenerate the Luau symbol table for the current Roblox client build
symbols:
	python3 tools/scan_symbols.py

clean:
	rm -rf $(BUILD_DIR)
