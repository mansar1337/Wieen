/*
 * Wieen agent — the part that runs inside the Roblox client process.
 *
 * Sober's runtime strips LD_PRELOAD from the environment it hands to the
 * client, but the flatpak runtime's ld.so also reads /etc/ld.so.preload, so
 * the agent is injected that way (see tools/install_preload.sh).
 *
 * The agent
 *   - finds the Roblox client image inside its own address space,
 *   - hooks the Luau interpreter so every script run passes through it,
 *   - executes Luau that the host writes into a mailbox in the client image.
 *
 * Everything runs on Roblox's own script thread: injected code has to run
 * where the game runs, otherwise the Luau state is not reachable.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "wieen.h"

/* ------------------------------------------------------------------ */
/* configuration, filled by the host                                  */
/* ------------------------------------------------------------------ */

#include "luau_symbols.h"

struct wieen_mbox
{
    volatile unsigned long cmd_len;
    volatile unsigned long status;
    volatile unsigned long result_len;
    volatile unsigned long seq;
    char cmd[WEIEN_MAX_MESSAGE];
    char result[WEIEN_MAX_MESSAGE];
};

/* the mailbox lives in the agent's .data so the host can find it */
__attribute__((visibility("default"))) struct wieen_mbox wieen_mbox;
static struct wieen_mbox* wieen_mbox_ptr;
__attribute__((visibility("default"))) void* wieen_current_state;
__attribute__((visibility("default"))) volatile int wieen_in_tick;

/* Luau entry points inside the client image */
typedef char* (*fn_compile)(const char* src, unsigned long size, void* options, unsigned long* outsize);
typedef int (*fn_load)(void* L, const char* chunkname, const char* data, unsigned long size, int env);
typedef int (*fn_pcall)(void* L, int nargs, int nresults, int errfunc);
typedef int (*fn_gettop)(void* L);
typedef void (*fn_settop)(void* L, int idx);
typedef const char* (*fn_tolstring)(void* L, int idx, unsigned long* len);
typedef int (*fn_type)(void* L, int idx);

static unsigned char g_orig[16];
static void* g_interp;

static void wieen_log(const char* msg)
{
    const char* path = "/home/xendr4x/.var/app/org.vinegarhq.Sober/data/wieen/agent.log";
    FILE* f = fopen(path, "a");
    if (!f)
        return;
    fprintf(f, "%s\n", msg);
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* finding the client image                                            */
/* ------------------------------------------------------------------ */

static unsigned long g_base;

static int looks_like_client(unsigned char* base)
{
    /* luau_load and the interpreter both start with a standard prologue */
    static const unsigned char sig[] = {0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56};
    if (memcmp(base + API_LUA_LOAD, sig, sizeof(sig)) != 0)
        return 0;
    if (memcmp(base + API_LUA_INTERPRETER, sig, 4) != 0)
        return 0;
    return 1;
}

static unsigned long find_client_base(void)
{
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f)
        return 0;
    char line[1024];
    unsigned long base = 0;
    while (fgets(line, sizeof(line), f))
    {
        unsigned long lo, hi;
        char perms[8];
        unsigned long off;
        if (sscanf(line, "%lx-%lx %7s %lx", &lo, &hi, perms, &off) != 4)
            continue;
        if (strchr(perms, 'x') == NULL)
            continue;
        if (hi - lo < 0x4000000)
            continue;
        unsigned long cand = lo - off;
        if (looks_like_client((unsigned char*)cand))
        {
            base = cand;
            break;
        }
    }
    fclose(f);
    return base;
}

/* ------------------------------------------------------------------ */
/* the detour                                                          */
/* ------------------------------------------------------------------ */

__attribute__((naked)) static void wieen_hook(void)
{
    __asm__ volatile(
        "push %rax\n"
        "push %rdi\n"
        "push %rsi\n"
        "push %rdx\n"
        "push %rcx\n"
        "push %r8\n"
        "push %r9\n"
        "push %rbx\n"
        "push %rbp\n"
        "push %r12\n"
        "push %r13\n"
        "push %r14\n"
        "push %r15\n"
        "mov %rdi, %rsi\n"
        "call wieen_tick\n"
        "pop %r15\n"
        "pop %r14\n"
        "pop %r13\n"
        "pop %r12\n"
        "pop %rbp\n"
        "pop %rbx\n"
        "pop %r9\n"
        "pop %r8\n"
        "pop %rcx\n"
        "pop %rdx\n"
        "pop %rsi\n"
        "pop %rdi\n"
        "pop %rax\n"
        "sub $8, %rsp\n"
        "mov wieen_orig(%rip), %rax\n"
        "call *%rax\n"
        "add $8, %rsp\n"
        "ret\n");
}

__attribute__((visibility("hidden"))) void* wieen_orig;

/* ------------------------------------------------------------------ */
/* running Luau                                                       */
/* ------------------------------------------------------------------ */

static void run_source(const char* src, unsigned long len, char* out, unsigned long outcap, unsigned long* outlen)
{
    unsigned long base = g_base;
    fn_compile compile = (fn_compile)(base + API_LUA_COMPILE);
    fn_load load = (fn_load)(base + API_LUA_LOAD);
    fn_pcall pcall = (fn_pcall)(base + API_LUA_PCALL);
    fn_gettop gettop = (fn_gettop)(base + API_LUA_GETTOP);
    fn_settop settop = (fn_settop)(base + API_LUA_SETTOP);
    fn_tolstring tolstring = (fn_tolstring)(base + API_LUA_TOLSTRING);
    fn_type type = (fn_type)(base + API_LUA_TYPE);

    void* state = wieen_current_state;
    if (!state)
    {
        const char* msg = "wieen: no luau state yet";
        *outlen = strlen(msg);
        memcpy(out, msg, *outlen);
        return;
    }

    unsigned long bclen = 0;
    char* bc = compile(src, len, 0, &bclen);
    if (!bc || !bclen)
    {
        const char* msg = "wieen: compilation failed";
        *outlen = strlen(msg);
        memcpy(out, msg, *outlen);
        return;
    }

    int baseidx = gettop(state);
    int rc = load(state, "=wieen", bc, bclen, 0 /* the global table */);
    if (rc != 0)
    {
        const char* msg = "wieen: luau_load failed";
        *outlen = strlen(msg);
        memcpy(out, msg, *outlen);
        settop(state, baseidx);
        return;
    }

    int status = pcall(state, 0, -1 /* LUA_MULTRET */, 0);
    int nres = gettop(state) - baseidx;

    if (status != 0)
    {
        const char* msg = "error: ";
        *outlen = 0;
        memcpy(out, msg, *outlen);
        unsigned long elen = 0;
        const char* err = tolstring(state, -1, &elen);
        if (err)
        {
            if (elen > outcap - *outlen)
                elen = outcap - *outlen;
            memcpy(out + *outlen, err, elen);
            *outlen += elen;
        }
        settop(state, baseidx);
        return;
    }

    *outlen = 0;
    if (nres <= 0)
    {
        const char* ok = "ok";
        *outlen = strlen(ok);
        memcpy(out, ok, *outlen);
    }
    else
    {
        for (int i = 1; i <= nres; i++)
        {
            if (i > 1 && *outlen < outcap)
                out[(*outlen)++] = '\t';
            unsigned long elen = 0;
            const char* v = tolstring(state, -(nres - i + 1), &elen);
            if (v)
            {
                if (elen > outcap - *outlen)
                    elen = outcap - *outlen;
                memcpy(out + *outlen, v, elen);
                *outlen += elen;
            }
            else
            {
                int t = type(state, -(nres - i + 1));
                char num[24];
                int k = 0;
                unsigned long n = (unsigned long)t;
                if (!n)
                    num[k++] = '0';
                while (n)
                {
                    num[k++] = (char)('0' + (n % 10));
                    n /= 10;
                }
                while (k-- && *outlen < outcap)
                    out[(*outlen)++] = num[k];
                if (*outlen < outcap)
                    out[(*outlen)++] = '>';
            }
        }
    }
    settop(state, baseidx);
}

/* ------------------------------------------------------------------ */
/* the tick: runs on Roblox's script thread                            */
/* ------------------------------------------------------------------ */

void wieen_tick(void* L)
{
    if (L)
        wieen_current_state = L;
    if (wieen_in_tick)
        return;
    wieen_in_tick = 1;

    struct wieen_mbox* mb = wieen_mbox_ptr;
    if (mb && mb->cmd_len && mb->cmd_len <= WEIEN_MAX_MESSAGE)
    {
        unsigned long len = mb->cmd_len;
        mb->cmd_len = 0;
        unsigned long rlen = 0;
        run_source(mb->cmd, len, mb->result, WEIEN_MAX_MESSAGE, &rlen);
        mb->result_len = rlen;
        mb->status = 1;
    }

    wieen_in_tick = 0;
}

/* ------------------------------------------------------------------ */
/* bootstrap                                                           */
/* ------------------------------------------------------------------ */

static int install_hook(unsigned char* target)
{
    memcpy(g_orig, target, 16);

    /* the trampoline re-runs the displaced prologue and continues */
    unsigned char* tramp = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED)
        return -1;

    unsigned char* p = tramp;
    /* mov rax,[rsp]; push rax  -> reproduce the state of a normal call */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0x04; *p++ = 0x24;
    *p++ = 0x50;
    memcpy(p, g_orig, 16);
    p += 16;
    /* movabs rax, target+16 ; jmp rax */
    *p++ = 0x48; *p++ = 0xB8;
    unsigned long cont = (unsigned long)(target + 16);
    for (int i = 0; i < 8; i++)
        *p++ = (unsigned char)(cont >> (i * 8));
    *p++ = 0xFF; *p++ = 0xE0;

    wieen_orig = tramp;

    long page = ((long)target) & ~0xFFFUL;
    if (mprotect((void*)page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return -1;

    /* jmp rel32 -> the hook */
    unsigned char* hook = (unsigned char*)wieen_hook;
    int delta = (int)((long)hook - (long)(target + 5));
    target[0] = 0xE9;
    target[1] = (unsigned char)(delta & 0xff);
    target[2] = (unsigned char)((delta >> 8) & 0xff);
    target[3] = (unsigned char)((delta >> 16) & 0xff);
    target[4] = (unsigned char)((delta >> 24) & 0xff);
    __builtin___clear_cache((char*)target, (char*)target + 5);
    return 0;
}

/*
 * Sober's sandbox loads libraries through ld.so's audit interface, so the
 * agent has to look like an audit module: la_version is the first symbol
 * ld.so asks for.
 */
unsigned int la_version(unsigned int version)
{
    (void)version;
    return 1; /* LAV_CURRENT */
}

__attribute__((constructor)) static void wieen_init(void)
{
    wieen_log("wieen: agent loaded");

    g_base = find_client_base();
    if (!g_base)
    {
        wieen_log("wieen: client image not found (not the client process?)");
        return;
    }

    wieen_mbox_ptr = &wieen_mbox;

    g_interp = (void*)(g_base + API_LUA_INTERPRETER);
    if (install_hook((unsigned char*)g_interp) != 0)
    {
        wieen_log("wieen: hook failed");
        return;
    }
    wieen_log("wieen: interpreter hooked");
}
