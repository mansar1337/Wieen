# Wieen — build rules
#
# The agent is a freestanding x86-64 shared object: no libc, no loader
# dependencies, so it can be LD_PRELOADed into Sober's client process
# regardless of which runtime the flatpak ships.

CC      ?= gcc
CFLAGS  ?= -O2 -fPIC -fno-stack-protector -Wall -Wextra -Wno-unused-parameter
LDFLAGS ?= -shared -Wl,--build-id=none

AGENT_DIR := src/agent
BUILD_DIR := build
AGENT     := $(BUILD_DIR)/wieen_agent.so

.PHONY: all agent clean symbols install

all: agent

agent: $(AGENT)

$(AGENT): $(AGENT_DIR)/wieen_agent.c $(AGENT_DIR)/wieen.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(AGENT_DIR)/wieen_agent.c
	@echo "built $@"
	@echo "verify: no dynamic dependencies expected ->"
	@readelf -d $@ | grep -E "NEEDED|SONAME" || echo "  (none - good)"

# regenerate the Luau symbol table for the current Roblox client build
symbols:
	python3 tools/scan_symbols.py

clean:
	rm -rf $(BUILD_DIR)

# the shim that replaces Sober's libbadcpu.so
SHIM := $(BUILD_DIR)/libbadcpu.so

$(SHIM): $(AGENT_DIR)/badcpu_shim.c
	@mkdir -p $(BUILD_DIR)
	$(CC) -O2 -fPIC -shared -o $@ $<
	@echo "built $@"

shim: $(SHIM)


# the shim that replaces Sober's libbadcpu.so
SHIM := $(BUILD_DIR)/libbadcpu.so

$(SHIM): $(AGENT_DIR)/badcpu_shim.c
	@mkdir -p $(BUILD_DIR)
	$(CC) -O2 -fPIC -shared -o $@ $<
	@echo "built $@"

shim: $(SHIM)
