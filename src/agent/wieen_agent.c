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

#define LOG_DIR_SUFFIX "/.var/app/org.vinegarhq.Sober/data/wieen"
#define LOG_FILE_NAME "agent.log"
#define SOCKET_FILE_NAME "wieen.sock"

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

/* the first 16 MiB of the client the tables were made for */
#define WIEEN_KNOWN_HASH 0x18d8af04a276288dULL

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

/* ------------------------------------------------------------------ */
/* logging                                                            */
/* ------------------------------------------------------------------ */

/*
 * The agent runs inside the sandbox of Sober, and HOME there is the home
 * of the user, so the paths of the socket and the log are written down
 * once, from HOME.
 */
static void wieen_path(char* out, size_t cap, const char* name)
{
    const char* home = getenv("HOME");
    snprintf(out, cap, "%s%s/%s", home && *home ? home : "/tmp", LOG_DIR_SUFFIX, name);
}

static void wieen_log(const char* fmt, ...)
{
    char path[512];
    wieen_path(path, sizeof(path), LOG_FILE_NAME);
    FILE* f = fopen(path, "a");
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
static __thread int g_in_hook;

/* ------------------------------------------------------------------ */
/* the hook                                                           */
/* ------------------------------------------------------------------ */

/*
 * An environment variable counts as a request only when it says something:
 * an empty value, which a flatpak override leaves behind, means nothing.
 */
static int env_flag(const char* name)
{
    const char* v = getenv(name);
    return v && *v && strcmp(v, "0") != 0;
}

static unsigned long g_hits;
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
    {
        wieen_log("wieen: cannot read the map of memory\n");
        return;
    }
    int count = 0;
    char line[512];
    while (count < (int)(sizeof(g_maps) / sizeof(g_maps[0])) && fgets(line, sizeof(line), f))
    {
        unsigned long lo, hi;
        if (sscanf(line, "%lx-%lx", &lo, &hi) != 2)
            continue;
        g_maps[count].lo = lo;
        g_maps[count].hi = hi;
        count++;
    }
    fclose(f);

    /*
     * A short read means the map was taken while the client was mapping
     * something; the old one is kept in that case, because a map with
     * holes in it would throw away the regions we already know.
     */
    if (count < g_mapcount / 2)
    {
        wieen_log("wieen: the map of memory came back short (%d regions), keeping the old one\n",
                  count);
        return;
    }

    g_mapcount = count;
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
    if (++misses < 4)
        return 0;

    misses = 0;
    refresh_maps();
    return map_contains(p);
}

/*
 * The state comes from lua_resume, so it is a real one.  The checks below
 * are the ones that cost nothing and still catch a state of another VM
 * with another layout: the pointers have to be there, aligned, and the
 * stack has to be a sane list of slots.
 */
static int state_is_usable(void* L)
{
    if (!L || ((unsigned long)L & 7) != 0)
        return 0;

    void* global = *(void**)((char*)L + LSTATE_GLOBAL);
    if (!global || ((unsigned long)global & 7) != 0)
        return 0;

    char* base = *(char**)((char*)L + LSTATE_BASE);
    char* top = *(char**)((char*)L + LSTATE_TOP);
    if (!base || !top)
        return 0;
    if ((unsigned long)base < 0x10000 || (unsigned long)top < 0x10000)
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
        return "the state is not in the map of memory";

    void* global = *(void**)((char*)L + LSTATE_GLOBAL);
    if (!global)
        return "no global state";
    if (!is_mapped(global))
        return "the global state is not mapped";

    char* base = *(char**)((char*)L + LSTATE_BASE);
    char* top = *(char**)((char*)L + LSTATE_TOP);
    if (!base || !top)
        return "the stack is not there";
    if (!is_mapped(base) || !is_mapped(top))
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
    const char* message = 0;
    size_t messagelen = 0;
    int status = -1;
    wieen_log("wieen: running a script after %lu calls of lua_resume\n", g_hits);
    wieen_log("wieen: creating thread for %lu bytes in parent %p\n",
              (unsigned long)bclen, parent);
    void* thread = g_newthread(parent);
    int pushed = thread != 0;

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
             * A script that yields (wait(), task.wait()) is resumed right
             * away: the game has no scheduler for a thread of ours, and a
             * script that waits for a moment is what we want to run to
             * the end anyway.
             */
            int resumes = 0;
            for (;;)
            {
                /*
                 * The parent is the state that called lua_resume, so it is
                 * the one the depth of the C stack is read from: a script
                 * that recurses deeply must not walk past the stack of the
                 * game.
                 */
                status = g_resume(thread, parent, 0);
                if (status != 1)
                    break;
                if (++resumes > 10000)
                {
                    status = -1;
                    message = "the script yields over and over";
                    break;
                }
            }

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

    /*
     * Drop the thread from the parent's stack.  The pointer saved before
     * lua_newthread cannot be used here: the call may grow the stack of
     * the parent, which reallocates it, and writing the old pointer back
     * would leave L->top pointing into memory that no longer belongs to
     * the state - the client then dies some frames later, far from here.
     * The slot is taken from the top as it is now instead.
     */
    if (pushed)
    {
        char** top = (char**)((char*)parent + LSTATE_TOP);
        if (*top && *top - 16 >= *(char**)((char*)parent + LSTATE_STACK))
            *top -= 16;
    }
}

/*
 * The hook fires thousands of times a second, so a call that finds nothing
 * to run has to cost almost nothing: no lock, no reading of the state, no
 * file.  Everything that is expensive happens only when a script waits.
 */
static void wieen_on_resume(void* L, void* from, long nargs)
{
    /*
     * One counter, so the log says how busy the hook is: a fault that
     * arrives after a fixed number of calls and one that arrives after a
     * fixed time are two different things.
     */
    if ((__atomic_add_fetch(&g_hits, 1, __ATOMIC_RELAXED) & 0x3FFFF) == 0)
        wieen_log("wieen: lua_resume hit %lu\n", g_hits);

    if (!__atomic_load_n(&g_pending_ready, __ATOMIC_RELAXED))
        return;
    if (g_in_hook)
        return;
    g_in_hook = 1;
    if (state_is_usable(L))
        run_pending(L);
    else
        wieen_log("wieen: that state does not look like a Luau state (%s), skipping\n",
                  state_problem(L));
    g_in_hook = 0;
}

/* ------------------------------------------------------------------ */
/* a crash handler, so a fault inside the game says where it happened */
/* ------------------------------------------------------------------ */

static const int g_fault_signal[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE};
#define WIEEN_FAULTS ((int)(sizeof(g_fault_signal) / sizeof(g_fault_signal[0])))
static int g_crashed;

static void wieen_crash(int sig, siginfo_t* info, void* uc);
static struct sigaction g_old_action[WIEEN_FAULTS];

static void wieen_crash(int sig, siginfo_t* info, void* uc)
{
    /*
     * The fault is not ours to swallow, and this handler runs on whatever
     * thread the signal landed on, possibly in the middle of malloc: the
     * very first thing is therefore to give the signal back to whoever
     * asked for it, without touching anything.
     */
    for (int i = 0; i < WIEEN_FAULTS; i++)
    {
        if (g_fault_signal[i] != sig)
            continue;
        struct sigaction* old = &g_old_action[i];
        if (old->sa_flags & SA_SIGINFO)
        {
            old->sa_sigaction(sig, info, uc);
            return;
        }
        if (old->sa_handler != SIG_DFL && old->sa_handler != SIG_IGN)
        {
            old->sa_handler(sig);
            return;
        }
        break;
    }

    /*
     * Nobody asked for it, so the game is going down anyway.  This is the
     * only case where the log is written, and a record of what happened
     * is worth more than the speed of dying.
     */
    if (g_crashed)
    {
        signal(sig, SIG_DFL);
        raise(sig);
        _exit(128 + sig);
    }
    g_crashed = 1;

    /* the snapshot of the map is old by now, and the stack has to be read */
    refresh_maps();

    unsigned long rip = 0;
    unsigned long rsp = 0;
    if (uc)
    {
        ucontext_t* c = (ucontext_t*)uc;
        rip = (unsigned long)c->uc_mcontext.gregs[REG_RIP];
        rsp = (unsigned long)c->uc_mcontext.gregs[REG_RSP];
    }
    /*
     * si_code tells whether the processor faulted or somebody sent the
     * signal; si_addr is only the faulting address in the first case.
     */
    wieen_log("wieen: signal %d at %p (rip %#lx rsp %#lx, client base %#lx, "
              "code %d, from pid %d uid %d)\n",
              sig, info ? info->si_addr : 0, rip, rsp, g_base,
              info ? info->si_code : 0, info ? info->si_pid : 0,
              info ? info->si_uid : 0);
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
        /*
         * A raw scan of the stack: every slot that points into code is a
         * return address of somebody, and the module it belongs to says
         * who.  This is what makes a fault readable without a debugger.
         */
        {
            struct { unsigned long lo, hi; char name[64]; } mods[64];
            int modcount = 0;
            FILE* m = fopen("/proc/self/maps", "r");
            char mline[512];
            while (m && modcount < 64 && fgets(mline, sizeof(mline), m))
            {
                unsigned long ml, mh, moff;
                char perms[8], mpath[256];
                mpath[0] = 0;
                if (sscanf(mline, "%lx-%lx %7s %lx %*s %*s %255s", &ml, &mh, perms,
                           &moff, mpath) < 4)
                    continue;
                if (perms[2] != 'x')
                    continue;
                mods[modcount].lo = ml - moff;
                mods[modcount].hi = mh;
                snprintf(mods[modcount].name, sizeof(mods[modcount].name), "%s",
                         mpath[0] ? mpath : "[anonymous]");
                modcount++;
            }
            if (m)
                fclose(m);

            for (int i = 0; i < 128; i++)
            {
                unsigned long slot = rsp + i * 8;
                if (!map_contains((void*)slot))
                    break;
                unsigned long value = *(unsigned long*)slot;
                for (int k = 0; k < modcount; k++)
                {
                    if (value < mods[k].lo || value >= mods[k].hi)
                        continue;
                    wieen_log("wieen: stack[%d] %#lx -> %s+%#lx\n", i, value,
                              mods[k].name, value - mods[k].lo);
                    break;
                }
            }
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

    signal(sig, SIG_DFL);
    raise(sig);
    _exit(128 + sig);
}

static void install_crash_handler(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = wieen_crash;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    for (int i = 0; i < WIEEN_FAULTS; i++)
        sigaction(g_fault_signal[i], &sa, &g_old_action[i]);
}

/* ------------------------------------------------------------------ */
/* finding the client image and the VM                                */
/* ------------------------------------------------------------------ */

/*
 * A hash of the image of the client, so it is possible to tell whether it
 * is the build the tables in tools/ were made for: Roblox ships a new
 * client every now and then, and the numbering of the opcodes can change
 * with it.
 */
static unsigned long long hash_image(unsigned long base, unsigned long size)
{
    unsigned long long h = 1469598103934665603ULL;
    const unsigned char* p = (const unsigned char*)base;
    for (unsigned long i = 0; i < size; i++)
    {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/*
 * How far from the base a mapping may start and still belong to the
 * client image.  The image is around a hundred megabytes, so a quarter of
 * a gigabyte is safely outside of any other library.
 */
#define IMAGE_SPAN 0x10000000UL
#define MAX_TEXT_RANGES 8

/*
 * The client is not mapped as one readable blob: the loader keeps the ELF
 * header on a read-only page and starts the text a page or two later, and
 * the client itself calls mprotect on the parts it patches at runtime.
 * Looking for one "executable range that contains the base" therefore
 * works only by luck, and it stopped working when the client moved from
 * 4 KiB to 16 KiB pages.  So the agent keeps every executable mapping of
 * the image and looks the signatures up in all of them.
 */
static unsigned long g_text_lo[MAX_TEXT_RANGES];
static unsigned long g_text_hi[MAX_TEXT_RANGES];
static int g_text_count;

static int executable_mappings_of(unsigned long base, unsigned long* lo,
                                  unsigned long* hi, int max)
{
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f)
        return 0;
    char line[1024];
    int count = 0;
    while (fgets(line, sizeof(line), f))
    {
        unsigned long l, h, off;
        char perms[8], path[256];
        path[0] = 0;
        if (sscanf(line, "%lx-%lx %7s %lx %255s", &l, &h, perms, &off, path) < 4)
            continue;
        if (perms[2] != 'x')
            continue;
        if (l < base || l - base >= IMAGE_SPAN)
            continue;
        if (count == max)
            break;
        lo[count] = l;
        hi[count] = h;
        count++;
    }
    fclose(f);
    return count;
}

/*
 * The client image among everything the process has mapped: the biggest
 * executable mapping that starts with an ELF header, and - when there is
 * more than one candidate - the one that carries the code we are after.
 * The second test is what keeps the agent from latching onto an unrelated
 * large library after the client moves.
 */
static unsigned long find_client_base(void)
{
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f)
        return 0;
    char line[1024];
    unsigned long candidate[8];
    unsigned long size[8];
    int count = 0;
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
        unsigned long base = lo - off;
        if (memcmp((void*)base, "\177ELF", 4) != 0)
            continue;
        if (count == (int)(sizeof(candidate) / sizeof(candidate[0])))
            continue;
        candidate[count] = base;
        size[count] = hi - lo;
        count++;
    }
    fclose(f);
    if (!count)
        return 0;

    /* a candidate that has lua_resume where we last saw it wins */
    for (int i = 0; i < count; i++)
    {
        unsigned long at = candidate[i] + SIGNATURES[0].offset;
        if (at + sizeof(SIG_RESUME) > candidate[i] + size[i])
            continue; /* the offset falls outside of this image */
        if (memcmp((void*)at, SIG_RESUME, sizeof(SIG_RESUME)) == 0)
            return candidate[i];
    }

    /* otherwise the biggest one, which is what the client always is */
    int pick = 0;
    for (int i = 1; i < count; i++)
        if (size[i] > size[pick])
            pick = i;
    if (count > 1)
        wieen_log("wieen: %d candidate images, picked the largest at %p\n", count,
                  (void*)candidate[pick]);
    return candidate[pick];
}

/* the executable ranges of the client image */
static int find_text_ranges(void)
{
    g_text_count = executable_mappings_of(g_base, g_text_lo, g_text_hi,
                                          MAX_TEXT_RANGES);
    if (!g_text_count)
        return 0;
    for (int i = 0; i < g_text_count; i++)
        wieen_log("wieen: text %#lx-%#lx (%lu KiB)\n", g_text_lo[i], g_text_hi[i],
                  (g_text_hi[i] - g_text_lo[i]) / 1024);
    return 1;
}

static unsigned char* find_signature(unsigned char* lo, unsigned char* hi,
                                     const unsigned char* pattern, int len)
{
    if (!lo || !hi || hi - lo < len)
        return 0;
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
 * The first bytes of the function are replaced by a jump to a stub of
 * ours, and the bytes that were there are replayed by a trampoline, so the
 * function runs as if nothing happened:
 *
 *     the function:  49 BB <stub>   41 FF E3        mov r11, stub; jmp r11
 *     the stub:      saves the registers, calls the handler, restores them,
 *                    and jumps into the trampoline
 *     the trampoline: the bytes of the prologue, then the rest of the
 *                    function
 *
 * The bytes that are replaced are exactly one prologue of this client,
 * thirteen bytes: push rbp; mov rbp, rsp; push r15; push r14; push rbx;
 * push rax; mov r14d, edx.  They end on an instruction boundary, which is
 * why the trampoline can replay them; the length is checked against the
 * bytes of the client before the patch is written.
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
    /*
     * The prologue that is about to be overwritten has to be the one the
     * trampoline replays.  A client built from other sources would have
     * other bytes here, and patching it would break the function.
     */
    if (memcmp(target, prologue, PROLOGUE_LEN) != 0)
    {
        wieen_log("wieen: the function does not start the way it did, not touching it\n");
        return -1;
    }
    (void)plen;

    long page = ((long)target) & ~0xFFFUL;
    if (mprotect((void*)page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    {
        wieen_log("wieen: mprotect failed: %s\n", strerror(errno));
        return -1;
    }
    if (env_flag("WIEEN_MPROTECT_ONLY"))
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
    if (env_flag("WIEEN_NOPATCH"))
    {
        wieen_log("wieen: stub built, not patching %p (WIEEN_NOPATCH)\n", target);
        mprotect((void*)page, 4096, PROT_READ | PROT_EXEC);
        mprotect(stub, 4096, PROT_READ | PROT_EXEC);
        mprotect(tramp, 4096, PROT_READ | PROT_EXEC);
        return 0;
    }
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
        {
            if (env_flag("WIEEN_SOCKET_LOG"))
                wieen_log("wieen: write on %d failed after %lu bytes: %s\n", fd,
                          (unsigned long)put, strerror(errno));
            return -1;
        }
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
        {
            /*
             * The script does not fit, and the bytes still have to leave
             * the socket, or the next message would start in the middle
             * of this one.
             */
            static char sink[4096];
            uint32_t left = len;
            while (left)
            {
                size_t want = left < sizeof(sink) ? left : sizeof(sink);
                if (read_exact(fd, sink, want) != 0)
                    return;
                left -= (uint32_t)want;
            }
            const char too_big[] = "the script is too big";
            uint32_t outlen = (uint32_t)(sizeof(too_big) - 1);
            if (write_exact(fd, &outlen, sizeof(outlen)) != 0)
                return;
            if (write_exact(fd, too_big, outlen) != 0)
                return;
            continue;
        }

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
            /*
             * The script is dropped: the game may still run it much
             * later, and a script of a finished command must not run
             * behind the back of the next one.
             */
            g_pending_ready = 0;
            g_pending_len = 0;
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
    char sock[512];
    wieen_path(sock, sizeof(sock), SOCKET_FILE_NAME);
    size_t socklen = strlen(sock);
    if (socklen + 1 > sizeof(addr.sun_path))
        socklen = sizeof(addr.sun_path) - 1;
    memcpy(addr.sun_path, sock, socklen);
    addr.sun_path[socklen] = 0;
    unlink(sock);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;
    if (env_flag("WIEEN_SOCKET_LOG"))
        wieen_log("wieen: unix socket fd %d\n", fd);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(fd, 4) != 0)
    {
        wieen_log("wieen: cannot listen on %s: %s\n", sock, strerror(errno));
        close(fd);
        return 0;
    }
    wieen_log("wieen: listening on %s\n", sock);

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
        if (env_flag("WIEEN_SOCKET_LOG"))
            wieen_log("wieen: connection on fd %d closed\n", c);
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
    {
        wieen_log("wieen: no client image in this process, nothing to do\n");
        return 0;
    }

    /*
     * The handlers of the game are only watched when somebody asks for
     * it: taking over a fault the game handles itself would turn a
     * recoverable trap of the client into a dead process.
     */
    if (env_flag("WIEEN_FAULTLOG"))
        install_crash_handler();
    refresh_maps();

    unsigned long long hash = hash_image(g_base, 16 * 1024 * 1024);
    wieen_log("wieen: image of the client at %p, hash %016llx\n", (void*)g_base,
              hash);
    if (hash != WIEEN_KNOWN_HASH)
        wieen_log("wieen: this is not the build the tables were made for "
                  "(known %016llx), falling back to the signatures\n",
                  (unsigned long long)WIEEN_KNOWN_HASH);

    if (!find_text_ranges())
    {
        wieen_log("wieen: no executable mapping in the image of the client\n");
        return 0;
    }

    /*
     * WIEEN_SCAN logs every place a signature is found, not only the one
     * the agent settles on.  It is how the offsets in
     * tools/opcode_map.* are re-derived after the client moves.
     */
    int scan = env_flag("WIEEN_SCAN");

    for (int i = 0; i < WIEEN_NSIG; i++)
    {
        const struct signature* sig = &SIGNATURES[i];
        unsigned char* at = 0;
        unsigned char* expected = (unsigned char*)(g_base + sig->offset);
        long bestdistance = -1;

        /* the place the function was found when the client was analysed */
        for (int r = 0; r < g_text_count; r++)
        {
            unsigned char* lo = (unsigned char*)g_text_lo[r];
            unsigned char* hi = (unsigned char*)g_text_hi[r];
            if (expected >= lo && expected + sig->length <= hi &&
                memcmp(expected, sig->bytes, sig->length) == 0)
                at = expected;
        }

        /* the client moved: take the signature closest to where the
           function used to be */
        if (!at)
        {
            unsigned char* best = 0;
            for (int r = 0; r < g_text_count; r++)
            {
                unsigned char* lo = (unsigned char*)g_text_lo[r];
                unsigned char* hi = (unsigned char*)g_text_hi[r];
                for (unsigned char* p = find_signature(lo, hi, sig->bytes, sig->length);
                     p; p = find_signature(p + 1, hi, sig->bytes, sig->length))
                {
                    long distance = (long)(p - expected);
                    if (distance < 0)
                        distance = -distance;
                    if (scan)
                        wieen_log("wieen: %s candidate at %#lx (distance %ld)\n",
                                  sig->name,
                                  (unsigned long)(p - (unsigned char*)g_base),
                                  distance);
                    if (!best || distance < bestdistance)
                    {
                        best = p;
                        bestdistance = distance;
                    }
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
    {
        wieen_log("wieen: not installing, missing lua_resume=%d luau_load=%d "
                  "lua_tolstring=%d lua_newthread=%d\n",
                  g_resume_addr != 0, g_load != 0, g_tolstring != 0,
                  g_newthread != 0);
        return 0;
    }

    if (env_flag("WIEEN_NOHOOK"))
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
    /*
     * WIEEN_OFF keeps the agent out of the way of a process entirely: the
     * library is still preloaded, but nothing of it runs.  It is the only
     * honest way to tell a fault of the game from a fault of ours.
     */
    if (env_flag("WIEEN_OFF"))
        return;
    wieen_log("\n=== wieen agent (pid %d) ===\n", (int)getpid());
    pthread_t thread;
    if (pthread_create(&thread, 0, setup_thread, 0) == 0)
        pthread_detach(thread);
}
