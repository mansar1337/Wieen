/*
 * Wieen agent - the part that runs inside the Roblox client process.
 *
 * How it gets in: the flatpak runtime's dynamic linker reads
 * /etc/ld.so.preload, which Sober does not control, so the agent is
 * preloaded into every process of the runtime - including the Roblox
 * client, whose image Sober maps from the APK.
 *
 * What it does:
 *   - finds the client image in its own address space,
 *   - locates the Luau VM's entry points by their code signature, so the
 *     agent keeps working when the client is updated,
 *   - hooks lua_resume, which hands us the game's own lua_State whenever
 *     the game runs a script,
 *   - serves a UNIX socket: the host sends a compiled Luau chunk, the
 *     agent runs it inside the game's VM and returns the result.
 *
 * The code always runs on the game's script thread, inside the hook of
 * lua_resume, because a Luau state must not be touched from another
 * thread.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define SOCKET_PATH "/home/xendr4x/.var/app/org.vinegarhq.Sober/data/wieen/wieen.sock"
#define LOG_PATH "/home/xendr4x/.var/app/org.vinegarhq.Sober/data/wieen/agent.log"

#define MAX_MESSAGE (64 * 1024)

/* ------------------------------------------------------------------ */
/* the Luau API we drive inside the client                            */
/* ------------------------------------------------------------------ */

typedef int (*fn_load)(void* L, const char* chunkname, const char* data,
                        unsigned long size, int env);
typedef int (*fn_resume)(void* L, void* from, int nargs);
typedef void* (*fn_newthread)(void* L);
typedef const char* (*fn_tolstring)(void* L, int idx, unsigned long* len);

/*
 * The client's Luau is compiled by a compiler we do not have, but the
 * prologue of each function is still a fingerprint: the sequence of
 * pushes and register moves at the start of a function is what the
 * compiler emits for it.  We look the functions up by that fingerprint,
 * which survives a client update as long as the build flags do not
 * change.
 */
struct signature
{
    const char* name;
    const unsigned char* bytes;
    int length;
    unsigned long offset;  /* where the function was found */
};

static const unsigned char SIG_RESUME[] = {
    0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x50,
    0x41, 0x89, 0xd6, 0x48, 0x89, 0xfb,
};
static const unsigned char SIG_LOAD[] = {
    0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55,
    0x41, 0x54, 0x53, 0x48, 0x83, 0xec, 0x68, 0x49, 0x89, 0xd5,
    0x49, 0x89, 0xf7,
};
static const unsigned char SIG_TOLSTRING[] = {
    0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x50,
    0x48, 0x89, 0xd3, 0x41, 0x89, 0xf7, 0x49, 0x89, 0xfe, 0x85,
    0xf6, 0x7e, 0x23,
};

/*
 * The offsets are the ones the client was found at; the signatures are
 * what the functions look like there.  A signature on its own is not
 * enough - it is not unique in the image - so the offset is checked
 * first, and only if the client moved do we look for the closest match.
 */
static const unsigned char SIG_NEWTHREAD[] = {
    0x55, 0x48, 0x89, 0xe5, 0x41, 0x56, 0x53, 0x48, 0x89, 0xfb,
    0x48, 0x8b, 0x47, 0x38, 0x48, 0x8b, 0x48, 0x50, 0x48, 0x3b,
    0x48, 0x48,
};

static const struct signature SIGNATURES[] = {
    {"lua_resume", SIG_RESUME, (int)sizeof(SIG_RESUME), 0x22e9432UL},
    {"luau_load", SIG_LOAD, (int)sizeof(SIG_LOAD), 0x22e4b72UL},
    {"lua_tolstring", SIG_TOLSTRING, (int)sizeof(SIG_TOLSTRING), 0x22e5f48UL},
    {"lua_newthread", SIG_NEWTHREAD, (int)sizeof(SIG_NEWTHREAD), 0x22e24d7UL},
};
#define WIEEN_NSIG (int)(sizeof(SIGNATURES) / sizeof(SIGNATURES[0]))

static fn_load g_load;
static fn_resume g_resume;
static fn_newthread g_newthread;
static fn_tolstring g_tolstring;
static void* g_resume_addr;
static unsigned long g_base;

/* the offsets of the stack in a lua_State, taken from the client's code */
/*
 * The layout of the state in this client, taken from the code:
 *   lua_tolstring (0x22e5f48) computes the value of a positive index as
 *   [L+0x50] + (index-1)*16 and compares it against [L+0x48], so +0x50 is
 *   the base of the stack and +0x48 is its top;
 *   the hooked call (0x22e9432) takes the callee from
 *   [L+0x48] - nargs*16 - 16;
 *   luau_load (0x22e4b72) reads the global state from [L+0x38];
 *   +0x40 holds the first slot of the stack array, +0x30 the current
 *   call info, +0x08/+0x0a the C call counters and +0x03 the status.
 */
#define LSTATE_GLOBAL 0x38
#define LSTATE_STACK 0x40
#define LSTATE_TOP 0x48
#define LSTATE_BASE 0x50
#define LSTATE_CI 0x30
#define LSTATE_NCCALLS 0x08
#define LSTATE_BASECALLS 0x0a
#define LSTATE_STATUS 0x03
#define LSTATE_ACTIVE 0x06
/* the debugstep hook of the global state (the client runs in single step) */
#define LSTATE_DEBUGSTEP 0x680

/* ------------------------------------------------------------------ */
/* logging                                                            */
/* ------------------------------------------------------------------ */

static void wieen_log(const char* fmt, ...)
{
    FILE* f = fopen(LOG_PATH, "a");
    if (!f)
        return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* the state of the running command                                   */
/* ------------------------------------------------------------------ */

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_done = PTHREAD_COND_INITIALIZER;

static unsigned char g_pending[MAX_MESSAGE];
static size_t g_pending_len;
static int g_pending_ready;
static int g_finished;
static char g_result[MAX_MESSAGE];
static size_t g_result_len;
static volatile int g_in_hook;

/* ------------------------------------------------------------------ */
/* the hook                                                           */
/* ------------------------------------------------------------------ */

static void* g_trampoline;
static void wieen_on_resume(void* L, void* from, long nargs);
static void (*g_handler)(void*, void*, long) = wieen_on_resume;

/* ------------------------------------------------------------------ */
/* a small view of the memory map                                     */
/* ------------------------------------------------------------------ */

struct maprange
{
    unsigned long lo;
    unsigned long hi;
};

static struct maprange g_maps[1024];
static int g_mapcount;

static void refresh_maps(void)
{
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f)
        return;
    g_mapcount = 0;
    char line[512];
    while (g_mapcount < (int)(sizeof(g_maps) / sizeof(g_maps[0])) &&
           fgets(line, sizeof(line), f))
    {
        unsigned long lo, hi;
        if (sscanf(line, "%lx-%lx", &lo, &hi) != 2)
            continue;
        g_maps[g_mapcount].lo = lo;
        g_maps[g_mapcount].hi = hi;
        g_mapcount++;
    }
    fclose(f);
}

static int map_contains(void* p)
{
    unsigned long a = (unsigned long)p;
    for (int i = 0; i < g_mapcount; i++)
        if (a >= g_maps[i].lo && a < g_maps[i].hi)
            return 1;
    return 0;
}

static int is_mapped(void* p)
{
    if (map_contains(p))
        return 1;

    /*
     * The map is a snapshot, and the client keeps growing its heap, so
     * regions that came up after the snapshot was taken are unknown.
     * Reading the map again is cheap, but it is done only every now and
     * then: the hook fires thousands of times a second.
     */
    static int misses;
    if (++misses < 64)
        return 0;

    misses = 0;
    refresh_maps();
    return map_contains(p);
}

/*
 * The client runs more than one Luau VM, and they do not necessarily
 * have the same layout, so a state is only used when it really looks
 * like one: the state itself is mapped, it points at a global state, and
 * the stack of the state is a pair of pointers into the same array.
 */
static int state_is_usable(void* L)
{
    if (!L || ((unsigned long)L & 7) != 0)
        return 0;
    if (!is_mapped(L))
        return 0;

    void* global = *(void**)((char*)L + LSTATE_GLOBAL);
    if (!global || !is_mapped(global))
        return 0;
    if (!is_mapped((char*)global + 0x48) || !is_mapped((char*)global + 0x50))
        return 0;

    char* base = *(char**)((char*)L + LSTATE_BASE);
    char* top = *(char**)((char*)L + LSTATE_TOP);
    if (!base || !top || !is_mapped(base) || !is_mapped(top))
        return 0;
    if (top < base)
        return 0;
    if (((top - base) % 16) != 0)
        return 0;
    if ((top - base) / 16 > 100000)
        return 0;
    return 1;
}

/* the same check, but it says why it said no */
static const char* state_problem(void* L)
{
    if (!L || ((unsigned long)L & 7) != 0)
        return "the state is not aligned";
    if (!is_mapped(L))
        return "the state is not mapped";

    void* global = *(void**)((char*)L + LSTATE_GLOBAL);
    if (!global || !is_mapped(global))
        return "no global state";
    if (!is_mapped((char*)global + 0x48) || !is_mapped((char*)global + 0x50))
        return "the global state is not mapped";

    char* base = *(char**)((char*)L + LSTATE_BASE);
    char* top = *(char**)((char*)L + LSTATE_TOP);
    if (!base || !top || !is_mapped(base) || !is_mapped(top))
        return "the stack is not mapped";
    if (top < base)
        return "the stack is upside down";
    if (((top - base) % 16) != 0)
        return "the stack is not a multiple of a slot";
    if ((top - base) / 16 > 100000)
        return "the stack is too big";
    return 0;
}

/* ------------------------------------------------------------------ */
/* running a chunk inside the game's VM                               */
/* ------------------------------------------------------------------ */

static void copy_result(char* out, size_t cap, size_t* outlen, const char* text,
                        size_t len)
{
    if (len > cap - 1)
        len = cap - 1;
    if (text)
        memcpy(out, text, len);
    out[len] = 0;
    *outlen = len;
}

/*
 * Runs the pending chunk in the given state.  The stack of the state is
 * restored afterwards, so the game does not notice that we were here.
 */
static void run_pending(void* parent)
{
    size_t bclen;

    pthread_mutex_lock(&g_lock);
    if (!g_pending_ready || !parent)
    {
        pthread_mutex_unlock(&g_lock);
        return;
    }
    g_pending_ready = 0;
    bclen = g_pending_len;
    pthread_mutex_unlock(&g_lock);

    static unsigned char chunk[MAX_MESSAGE];
    memcpy(chunk, g_pending, bclen);

    /* The thread object on the parent stack roots our coroutine against GC. */
    char* saved_top = *(char**)((char*)parent + LSTATE_TOP);
    const char* message = 0;
    size_t messagelen = 0;
    int status = -1;
    wieen_log("wieen: creating thread for %lu bytes in parent %p\n",
              (unsigned long)bclen, parent);
    void* thread = g_newthread(parent);

    wieen_log("wieen: created thread %p\n", thread);

    if (!thread)
        message = "lua_newthread returned NULL";
    else
    {
        status = g_load(thread, "=wieen", (const char*)chunk, bclen, 0);
        wieen_log("wieen: luau_load returned %d\n", status);
        char* top = *(char**)((char*)thread + LSTATE_TOP);
        wieen_log("wieen: loaded %lu bytes, the function is at %p\n",
                  (unsigned long)bclen, top - 16);
        if (status == 0)
        {
            /*
             * The thread now has the loaded function on its stack, so
             * resuming it without arguments runs it.  lua_resume does the
             * whole job: it sets up the call frame, runs the interpreter
             * and restores the state afterwards.
             */
            wieen_log("wieen: resuming thread %p, status=%d active=%d ci=%p baseci=%p\n",
                      thread,
                      *(unsigned char*)((char*)thread + LSTATE_STATUS),
                      *(unsigned char*)((char*)thread + LSTATE_ACTIVE),
                      *(void**)((char*)thread + LSTATE_CI),
                      *(void**)((char*)thread + 0x18));

            /*
             * The client runs its interpreter in single step mode: it calls
             * the debugstep hook of the global state before every single
             * instruction.  The hook belongs to the game, so it is taken
             * off while our chunk runs and put back afterwards.
             */
            void* global = *(void**)((char*)thread + LSTATE_GLOBAL);
            void* hook = *(void**)((char*)global + LSTATE_DEBUGSTEP);
            *(void**)((char*)global + LSTATE_DEBUGSTEP) = 0;
            wieen_log("wieen: debugstep hook was %p\n", hook);

            /*
             * A script that yields (wait(), task.wait()) is resumed right
             * away: the game has no scheduler for a thread of ours, and a
             * script that waits for a moment is what we want to run to
             * the end anyway.
             */
            int resumes = 0;
            for (;;)
            {
                status = g_resume(thread, 0, 0);
                if (status != 1)
                    break;
                if (++resumes > 10000)
                {
                    status = -1;
                    message = "the script yields over and over";
                    break;
                }
            }

            *(void**)((char*)global + LSTATE_DEBUGSTEP) = hook;
            wieen_log("wieen: lua_resume returned %d, status=%d, resumes=%d\n",
                      status, *(unsigned char*)((char*)thread + LSTATE_STATUS),
                      resumes);
        }
        wieen_log("wieen: reading result\n");
        message = g_tolstring(thread, -1, &messagelen);
        if (!message)
        {
            /*
             * lua_tolstring only knows strings and numbers; for the
             * other types the tag of the value is read from the stack.
             */
            char* top = *(char**)((char*)thread + LSTATE_TOP);
            if (is_mapped(top) && is_mapped(top - 16))
            {
                char* value = top - 16;
                int tag = *(int*)(value + 12);
                static char other[64];
                if (tag == 0)
                {
                    message = "nil";
                }
                else if (tag == 1)
                {
                    message = (*(int*)value) ? "true" : "false";
                }
                else if (tag == 5)
                {
                    message = "table";
                }
                else if (tag == 6)
                {
                    message = "function";
                }
                else
                {
                    snprintf(other, sizeof(other), "a value of type %d", tag);
                    message = other;
                }
                messagelen = strlen(message);
            }
        }
    }

    if (status == 1)
    {
        message = "coroutine yielded; yielding scripts are not supported yet";
        messagelen = strlen(message);
        status = -1;
    }

    /* Copy while the Luau string is alive, then remove the thread reference. */
    pthread_mutex_lock(&g_lock);
    if (status == 0)
        copy_result(g_result, sizeof(g_result), &g_result_len, message, messagelen);
    else
    {
        static const char prefix[] = "error: ";
        size_t n = sizeof(prefix) - 1;
        memcpy(g_result, prefix, n);
        if (message)
        {
            if (!messagelen)
                messagelen = strlen(message);
            if (messagelen > sizeof(g_result) - n - 1)
                messagelen = sizeof(g_result) - n - 1;
            memcpy(g_result + n, message, messagelen);
            n += messagelen;
        }
        g_result[n] = 0;
        g_result_len = n;
    }
    g_finished = 1;
    pthread_cond_signal(&g_done);
    pthread_mutex_unlock(&g_lock);

    *(char**)((char*)parent + LSTATE_TOP) = saved_top;
}

static volatile int g_hits;

static void wieen_on_resume(void* L, void* from, long nargs)
{
    if (g_in_hook)
        return;
    g_in_hook = 1;
    g_hits++;
    if (g_hits <= 8 || (g_hits % 200) == 0)
        wieen_log("wieen: lua_resume hit %d, L=%p from=%p nargs=%ld\n",
                  g_hits, L, from, nargs);
    if (state_is_usable(L))
        run_pending(L);
    else if (g_hits <= 8)
        wieen_log("wieen: that state does not look like a Luau state (%s), skipping\n",
                  state_problem(L));
    g_in_hook = 0;
}

/* ------------------------------------------------------------------ */
/* a crash handler, so a fault inside the game says where it happened */
/* ------------------------------------------------------------------ */

static void (*g_old_segv)(int, siginfo_t*, void*);
static int g_crashed;

static void wieen_crash(int sig, siginfo_t* info, void* uc)
{
    if (g_crashed)
        _exit(128 + sig);
    g_crashed = 1;
    unsigned long rip = 0;
    unsigned long rsp = 0;
    if (uc)
    {
        ucontext_t* c = (ucontext_t*)uc;
        rip = (unsigned long)c->uc_mcontext.gregs[REG_RIP];
        rsp = (unsigned long)c->uc_mcontext.gregs[REG_RSP];
    }
    wieen_log("wieen: signal %d at %p (rip %#lx rsp %#lx, client base %#lx)\n",
              sig, info ? info->si_addr : 0, rip, rsp, g_base);
    if (uc)
    {
        ucontext_t* c = (ucontext_t*)uc;
        wieen_log("wieen: regs rax=%#lx rbx=%#lx rcx=%#lx rdx=%#lx rsi=%#lx rdi=%#lx rbp=%#lx r12=%#lx r14=%#lx r15=%#lx\n",
                  (unsigned long)c->uc_mcontext.gregs[REG_RAX],
                  (unsigned long)c->uc_mcontext.gregs[REG_RBX],
                  (unsigned long)c->uc_mcontext.gregs[REG_RCX],
                  (unsigned long)c->uc_mcontext.gregs[REG_RDX],
                  (unsigned long)c->uc_mcontext.gregs[REG_RSI],
                  (unsigned long)c->uc_mcontext.gregs[REG_RDI],
                  (unsigned long)c->uc_mcontext.gregs[REG_RBP],
                  (unsigned long)c->uc_mcontext.gregs[REG_R12],
                  (unsigned long)c->uc_mcontext.gregs[REG_R14],
                  (unsigned long)c->uc_mcontext.gregs[REG_R15]);
        wieen_log("wieen: more regs r8=%#lx r9=%#lx r10=%#lx r11=%#lx r13=%#lx\n",
                  (unsigned long)c->uc_mcontext.gregs[REG_R8],
                  (unsigned long)c->uc_mcontext.gregs[REG_R9],
                  (unsigned long)c->uc_mcontext.gregs[REG_R10],
                  (unsigned long)c->uc_mcontext.gregs[REG_R11],
                  (unsigned long)c->uc_mcontext.gregs[REG_R13]);
        if (is_mapped((void*)rsp))
        {
            for (int i = 0; i < 8 && is_mapped((void*)(rsp + i * 8)); i++)
                wieen_log("wieen: stack[%d] @ %#lx = %#lx (client %#lx)\n",
                          i, rsp + i * 8, *(unsigned long*)(rsp + i * 8),
                          *(unsigned long*)(rsp + i * 8) - g_base);
        }
        unsigned long frame = (unsigned long)c->uc_mcontext.gregs[REG_RBP];
        for (int i = 0; i < 16 && is_mapped((void*)frame) &&
             is_mapped((void*)(frame + 8)); i++)
        {
            unsigned long next = *(unsigned long*)frame;
            unsigned long ret = *(unsigned long*)(frame + 8);
            wieen_log("wieen: frame[%d] rbp=%#lx ret=%#lx (client %#lx)\n",
                      i, frame, ret, ret - g_base);
            if (next <= frame || next - frame > 0x100000)
                break;
            frame = next;
        }
    }
    if (g_base)
        wieen_log("wieen: rip is at client offset %#lx\n", rip - g_base);
    /* the bytes around the fault, and the mapping it belongs to */
    {
        char code[64];
        int n = 0;
        if (is_mapped((void*)rip))
        {
            for (int i = 0; i < 32; i++)
            {
                unsigned char b = ((unsigned char*)rip)[i];
                n += snprintf(code + n, sizeof(code) - n, "%02x", b);
            }
            wieen_log("wieen: code at rip: %s\n", code);
        }
    }
    {
        FILE* f = fopen("/proc/self/maps", "r");
        char line[512];
        while (f && fgets(line, sizeof(line), f))
            if (strstr(line, "r-xp") || strstr(line, "sober") || strstr(line, "libroblox"))
                wieen_log("wieen: MAP %s", line);
        if (f)
            fclose(f);
    }
    if (g_old_segv)
        g_old_segv(sig, info, uc);
    else
        _exit(139);
}

static void install_crash_handler(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = wieen_crash;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGBUS, &sa, 0);
    sigaction(SIGILL, &sa, 0);
    sigaction(SIGFPE, &sa, 0);
    g_old_segv = 0;
}

/* ------------------------------------------------------------------ */
/* finding the client image and the VM                                */
/* ------------------------------------------------------------------ */

static unsigned long find_client_base(void)
{
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f)
        return 0;
    char line[1024];
    unsigned long best = 0, bestsize = 0;
    while (fgets(line, sizeof(line), f))
    {
        unsigned long lo, hi, off;
        char perms[8], path[256];
        path[0] = 0;
        if (sscanf(line, "%lx-%lx %7s %lx %255s", &lo, &hi, perms, &off, path) < 4)
            continue;
        if (perms[2] != 'x')
            continue;
        if (hi - lo < 0x4000000)
            continue; /* the client image is a hundred megabytes */
        if (hi - lo <= bestsize)
            continue;
        bestsize = hi - lo;
        best = lo - off;
    }
    fclose(f);
    if (!best)
        return 0;
    if (memcmp((void*)best, "\177ELF", 4) != 0)
        return 0;
    return best;
}

/* the executable range of the client image */
static int find_text_range(unsigned long* lo, unsigned long* hi)
{
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f)
        return 0;
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), f))
    {
        unsigned long l, h, off;
        char perms[8], path[256];
        path[0] = 0;
        if (sscanf(line, "%lx-%lx %7s %lx %255s", &l, &h, perms, &off, path) < 4)
            continue;
        if (perms[2] != 'x')
            continue;
        if (!(l <= g_base && g_base < h))
            continue;
        *lo = l;
        *hi = h;
        found = 1;
        break;
    }
    fclose(f);
    return found;
}

static unsigned char* find_signature(unsigned char* lo, unsigned char* hi,
                                     const unsigned char* pattern, int len)
{
    unsigned char* p = lo;
    unsigned char* last = hi - len;
    while (p <= last)
    {
        if (memcmp(p, pattern, len) == 0)
            return p;
        p++;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* installing the hook                                                */
/* ------------------------------------------------------------------ */

/*
 * The stub is reached with an absolute jump, because a relative jump only
 * reaches two gigabytes and the client's image is usually much further
 * away from the mmap area than that.
 *
 * The patch is therefore ten bytes long:
 *
 *     49 BB <address of the stub>   mov r11, stub
 *     41 FF E3                       jmp r11
 *
 * and the trampoline replays the thirteen bytes of the prologue that were
 * overwritten, then continues in the original function.
 */
#define PROLOGUE_LEN 13

static void* alloc_exec(size_t len)
{
    void* p = mmap(0, len, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? 0 : p;
}

static int install_hook(unsigned char* target, const unsigned char* prologue, int plen)
{
    long page = ((long)target) & ~0xFFFUL;
    if (mprotect((void*)page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    {
        wieen_log("wieen: mprotect failed: %s\n", strerror(errno));
        return -1;
    }
    if (getenv("WIEEN_MPROTECT_ONLY"))
    {
        wieen_log("wieen: mprotect only, no patch\n");
        mprotect((void*)page, 4096, PROT_READ | PROT_EXEC);
        return 0;
    }

    unsigned char* tramp = alloc_exec(4096);
    if (!tramp)
        return -1;
    memcpy(tramp, target, PROLOGUE_LEN);
    unsigned char* p = tramp + PROLOGUE_LEN;
    *p++ = 0x48; /* mov rax, target + PROLOGUE_LEN */
    *p++ = 0xB8;
    unsigned long cont = (unsigned long)(target + PROLOGUE_LEN);
    for (int i = 0; i < 8; i++)
        *p++ = (unsigned char)(cont >> (i * 8));
    *p++ = 0xFF; /* jmp rax */
    *p++ = 0xE0;
    g_trampoline = tramp;

    unsigned char* stub = alloc_exec(4096);
    if (!stub)
        return -1;
    unsigned char* s = stub;
    /* sub rsp, 0x80 - the immediate has to be 32 bit, 0x80 would sign extend */
    *s++ = 0x48; *s++ = 0x81; *s++ = 0xEC;
    *s++ = 0x80; *s++ = 0x00; *s++ = 0x00; *s++ = 0x00;
    *s++ = 0x50;                                          /* push rax */
    *s++ = 0x57;                                          /* push rdi */
    *s++ = 0x56;                                          /* push rsi */
    *s++ = 0x52;                                          /* push rdx */
    *s++ = 0x51;                                          /* push rcx */
    *s++ = 0x41; *s++ = 0x50;                             /* push r8 */
    *s++ = 0x41; *s++ = 0x51;                             /* push r9 */
    *s++ = 0x53;                                          /* push rbx */
    *s++ = 0x55;                                          /* push rbp */
    *s++ = 0x41; *s++ = 0x54;                             /* push r12 */
    *s++ = 0x41; *s++ = 0x55;                             /* push r13 */
    *s++ = 0x41; *s++ = 0x56;                             /* push r14 */
    *s++ = 0x41; *s++ = 0x57;                             /* push r15 */
    /*
     * The registers were pushed in this order: rax, rdi, rsi, rdx, rcx,
     * r8, r9, rbx, rbp, r12, r13, r14, r15.  The state is in the saved
     * rdi, which is 11 slots below the top of the stack: r15 at +0, r14
     * at +8, r13 at +16, r12 at +24, rbp at +32, rbx at +40, r9 at +48,
     * r8 at +56, rcx at +64, rdx at +72, rsi at +80, rdi at +88.  Reload
     * all three arguments after the handler: its C call clobbers rsi/rdx.
     */
    *s++ = 0x48; *s++ = 0x8B; *s++ = 0x7C; *s++ = 0x24; *s++ = 0x58; /* mov rdi,[rsp+0x58] */
    *s++ = 0x48; *s++ = 0x8B; *s++ = 0x74; *s++ = 0x24; *s++ = 0x50; /* mov rsi,[rsp+0x50] */
    *s++ = 0x48; *s++ = 0x8B; *s++ = 0x54; *s++ = 0x24; *s++ = 0x48; /* mov rdx,[rsp+0x48] */
    *s++ = 0x48; *s++ = 0xB8;                             /* mov rax, handler */
    {
        unsigned long v = (unsigned long)(void*)g_handler;
        for (int i = 0; i < 8; i++)
            s[i] = (unsigned char)(v >> (i * 8));
        s += 8;
    }
    *s++ = 0xFF; *s++ = 0xD0;                             /* call rax */
    *s++ = 0x48; *s++ = 0x8B; *s++ = 0x7C; *s++ = 0x24; *s++ = 0x58;
    *s++ = 0x48; *s++ = 0x8B; *s++ = 0x74; *s++ = 0x24; *s++ = 0x50;
    *s++ = 0x48; *s++ = 0x8B; *s++ = 0x54; *s++ = 0x24; *s++ = 0x48;
    *s++ = 0x41; *s++ = 0x5F;                             /* pop r15 */
    *s++ = 0x41; *s++ = 0x5E;                             /* pop r14 */
    *s++ = 0x41; *s++ = 0x5D;                             /* pop r13 */
    *s++ = 0x41; *s++ = 0x5C;                             /* pop r12 */
    *s++ = 0x5D;                                          /* pop rbp */
    *s++ = 0x5B;                                          /* pop rbx */
    *s++ = 0x41; *s++ = 0x59;                             /* pop r9 */
    *s++ = 0x41; *s++ = 0x58;                             /* pop r8 */
    *s++ = 0x59;                                          /* pop rcx */
    *s++ = 0x5A;                                          /* pop rdx */
    *s++ = 0x5E;                                          /* pop rsi */
    *s++ = 0x5F;                                          /* pop rdi */
    *s++ = 0x58;                                          /* pop rax */
    /* add rsp, 0x80 */
    *s++ = 0x48; *s++ = 0x81; *s++ = 0xC4;
    *s++ = 0x80; *s++ = 0x00; *s++ = 0x00; *s++ = 0x00;
    *s++ = 0x48; *s++ = 0xB8;                             /* mov rax, trampoline */
    {
        unsigned long v = (unsigned long)tramp;
        for (int i = 0; i < 8; i++)
            s[i] = (unsigned char)(v >> (i * 8));
        s += 8;
    }
    *s++ = 0xFF; *s++ = 0xE0;                             /* jmp rax */

    /* the patch: mov r11, stub; jmp r11 */
    target[0] = 0x49;
    target[1] = 0xBB;
    unsigned long stubaddr = (unsigned long)stub;
    for (int i = 0; i < 8; i++)
        target[2 + i] = (unsigned char)(stubaddr >> (i * 8));
    target[10] = 0x41;
    target[11] = 0xFF;
    target[12] = 0xE3;

    /*
     * Sober checks the memory map of the client and does not like pages
     * that are writable and executable, so the page goes back to what it
     * was - the same for our own stub pages.
     */
    mprotect((void*)page, 4096, PROT_READ | PROT_EXEC);
    mprotect(stub, 4096, PROT_READ | PROT_EXEC);
    mprotect(tramp, 4096, PROT_READ | PROT_EXEC);
    (void)prologue;
    (void)plen;
    return 0;
}

/* ------------------------------------------------------------------ */
/* the socket server                                                  */
/* ------------------------------------------------------------------ */

static int read_exact(int fd, void* buf, size_t len)
{
    size_t got = 0;
    while (got < len)
    {
        ssize_t n = read(fd, (char*)buf + got, len - got);
        if (n <= 0)
            return -1;
        got += (size_t)n;
    }
    return 0;
}

static int write_exact(int fd, const void* buf, size_t len)
{
    size_t put = 0;
    while (put < len)
    {
        ssize_t n = write(fd, (const char*)buf + put, len - put);
        if (n <= 0)
            return -1;
        put += (size_t)n;
    }
    return 0;
}

static void serve(int fd)
{
    for (;;)
    {
        uint32_t len = 0;
        if (read_exact(fd, &len, sizeof(len)) != 0)
            return;
        if (len > MAX_MESSAGE)
            len = MAX_MESSAGE;

        pthread_mutex_lock(&g_lock);
        g_pending_len = 0;
        g_pending_ready = 0;
        g_finished = 0;
        g_result_len = 0;
        pthread_mutex_unlock(&g_lock);

        if (len && read_exact(fd, g_pending, len) != 0)
            return;

        wieen_log("wieen: command of %u bytes received\n", len);
        pthread_mutex_lock(&g_lock);
        g_pending_len = len;
        g_pending_ready = 1;
        pthread_cond_broadcast(&g_done);
        pthread_mutex_unlock(&g_lock);

        /* wait for the game to run it */
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += 10;
        pthread_mutex_lock(&g_lock);
        while (!g_finished)
        {
            if (pthread_cond_timedwait(&g_done, &g_lock, &deadline) != 0)
                break;
        }
        if (!g_finished)
        {
            snprintf(g_result, sizeof(g_result),
                     "the game did not run the script - no Luau state is active");
            g_result_len = strlen(g_result);
        }
        uint32_t outlen = (uint32_t)g_result_len;
        pthread_mutex_unlock(&g_lock);

        if (write_exact(fd, &outlen, sizeof(outlen)) != 0)
            return;
        if (outlen && write_exact(fd, g_result, outlen) != 0)
            return;
    }
}

static void* server_thread(void* arg)
{
    (void)arg;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SOCKET_PATH);
    unlink(SOCKET_PATH);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(fd, 4) != 0)
    {
        wieen_log("wieen: cannot listen on %s: %s\n", SOCKET_PATH, strerror(errno));
        close(fd);
        return 0;
    }
    wieen_log("wieen: listening on %s\n", SOCKET_PATH);

    for (;;)
    {
        int c = accept(fd, 0, 0);
        if (c < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }
        serve(c);
        close(c);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* bootstrap                                                          */
/* ------------------------------------------------------------------ */

static void* setup_thread(void* arg)
{
    (void)arg;
    for (int tries = 0; tries < 600; tries++)
    {
        g_base = find_client_base();
        if (g_base)
            break;
        usleep(100000);
    }
    if (!g_base)
        return 0;

    install_crash_handler();
    refresh_maps();

    unsigned long lo = 0, hi = 0;
    if (!find_text_range(&lo, &hi))
        return 0;

    unsigned char* text = (unsigned char*)lo;
    unsigned char* end = (unsigned char*)hi;

    for (int i = 0; i < WIEEN_NSIG; i++)
    {
        const struct signature* sig = &SIGNATURES[i];
        unsigned char* at = 0;

        /* the place the function was found when the client was analysed */
        unsigned char* expected = (unsigned char*)(g_base + sig->offset);
        if (expected >= text && expected + sig->length <= end &&
            memcmp(expected, sig->bytes, sig->length) == 0)
        {
            at = expected;
        }
        else
        {
            /* the client moved: take the signature closest to where the
               function used to be */
            unsigned char* best = 0;
            long bestdistance = 0;
            for (unsigned char* p = find_signature(text, end, sig->bytes, sig->length);
                 p; p = find_signature(p + 1, end, sig->bytes, sig->length))
            {
                long distance = (long)(p - expected);
                if (distance < 0)
                    distance = -distance;
                if (!best || distance < bestdistance)
                {
                    best = p;
                    bestdistance = distance;
                }
            }
            if (best && bestdistance < 0x200000)
                at = best;
        }

        if (!at)
        {
            wieen_log("wieen: %s not found in the client\n", sig->name);
            continue;
        }
        wieen_log("wieen: %s at %p (offset %#lx)\n", sig->name, at,
                  (unsigned long)(at - (unsigned char*)g_base));
        if (i == 0)
        {
            g_resume_addr = at;
            g_resume = (fn_resume)at;
        }
        else if (i == 1)
            g_load = (fn_load)at;
        else if (i == 2)
            g_tolstring = (fn_tolstring)at;
        else
            g_newthread = (fn_newthread)at;
    }

    if (!g_resume_addr || !g_load || !g_tolstring || !g_newthread)
        return 0;

    if (getenv("WIEEN_NOHOOK"))
    {
        wieen_log("wieen: hook disabled by WIEEN_NOHOOK\n");
    }
    else if (install_hook((unsigned char*)g_resume_addr, SIG_RESUME,
                          (int)sizeof(SIG_RESUME)) != 0)
        return 0;
    else
    {
        wieen_log("wieen: hooked lua_resume at %p\n", g_resume_addr);
    }

    pthread_t thread;
    if (pthread_create(&thread, 0, server_thread, 0) == 0)
        pthread_detach(thread);
    return 0;
}

__attribute__((constructor)) static void wieen_init(void)
{
    wieen_log("\n=== wieen agent (pid %d) ===\n", (int)getpid());
    pthread_t thread;
    if (pthread_create(&thread, 0, setup_thread, 0) == 0)
        pthread_detach(thread);
}
