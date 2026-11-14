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
 *   - finds the state of the game's Luau VM (global_State) and puts its own
 *     handler into the pre-resume slot of that state, which the VM calls
 *     before every script the game runs,
 *   - serves a UNIX socket: the host sends a compiled Luau chunk, the
 *     agent runs it inside the game's VM and returns the result.
 *
 * The code of the client is never touched: the client checks the bytes of
 * its own text about a minute after the start and leaves when they do not
 * match, so a hook in the code is not an option.  The handler lives in the
 * writable memory of the state of Luau, which that check does not see.
 *
 * The code always runs on the game's script thread, inside that handler,
 * because a Luau state must not be touched from another thread.
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
#include <setjmp.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* the bytecode of the probe, compiled by tools/probe.luau */
#include "probe_bytecode.h"

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
typedef void (*fn_dcall)(void* L, void* func, int nresults, int preparereentry);
typedef int (*fn_raw_pcall)(void* L, void (*func)(void*, void*), void* ud,
                            long oldtop, long errfunc);
/* the compiler of Luau as it is in the client: char* f(const char* source,
 * size_t size, void* options, size_t* outsize) */
typedef char* (*fn_compile)(const char* source, unsigned long size,
                            void* options, unsigned long* outsize);
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

/*
 * The client has no standalone lua_pcall: its lapi call was inlined, and only
 * luaD_pcall and luaD_call remain.  Both addresses are fixed RVAs of the game
 * VM copy, validated against the known client image.  A pcall is rebuilt from
 * them exactly as upstream lapi.cpp does it.
 */
#define LUA_RVA_D_PCALL 0x22e5729UL
#define LUA_RVA_D_CALL 0x22e5b93UL

static fn_load g_load;
static fn_compile g_compile;
static fn_raw_pcall g_pcall;
static fn_dcall g_dcall;
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
/* the set of capabilities of Roblox for the thread */
#define LSTATE_CAPS 0x0c
/* the sandbox context of a thread: its capability mask is a u64 at +0x80 */
#define LSTATE_CTX 0x20
#define WIEEN_CTX_CAPS 0x80

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

static void run_pending(void* parent);
static void run_probe(void* L);
static void wieen_log_frames(void* L, void* fnval);
static int wieen_pcall(void* L, int nargs, int nresults, int errfunc);

/*
 * The state of the game and the callback that is put into it.  The
 * callback lives in the writable memory of the client, so the check of
 * the integrity of the code does not see it.
 */
static void* g_global_state;         /* the state of the VM we settled on */
static unsigned char* g_installed_g;  /* where our callback is installed */
static void* g_installed_original;    /* the callback that was there */
static unsigned long g_preresume_hits;
static int g_in_preresume;            /* a script of ours is running */
static int g_probe_wanted;            /* the next hit has to be probed */
static int g_probe_done;
static char g_probe_result[160];

/* the union of the sets of the capabilities of the states of the VM */
static unsigned int g_rich_caps;

/* set while the fallback runs a script outside the thread of the game */
static int g_inthread_off;

/* the capability mask a script can be given through its environment table */
static unsigned long long g_env_mask;

/* the mask a thread of the game must have for the script to run in it */
static unsigned int g_want_caps;
static unsigned long g_caps_skipped;

/* the socket of the host: it compiles the sources the script asks for */
static int g_conn_fd = -1;

/* the masks of the capabilities of the states of the VM */
#define CAP_MASKS 32

/*
 * The search for the state of the VM reads the memory of the client, and
 * the game frees it while it runs: a page can be gone between the moment
 * it is looked at and the moment it is read.  A fault of our own during
 * the search is therefore not fatal: the search is given up and started
 * again.
 */
static sigjmp_buf g_scan_jmp;
static volatile int g_scan_active;
static volatile pid_t g_scan_tid;


/*
 * The state of the VM keeps a pointer to the set of the capabilities of a
 * thread in the field +0x0c.  The thread of the game that calls us is a
 * script thread, and its rights are not always enough; the main thread of
 * the VM has all of them, so its set is used.
 */

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
 * Runs one chunk of the script in the given state.  The stack of the state
 * is restored afterwards, so the game does not notice that we were here.
 */
static int run_one(void* parent, const unsigned char* chunk, size_t bclen,
                   const char** message, size_t* messagelen)
{
    /* The thread object on the parent stack roots our coroutine against GC. */
    int status = -1;
    int loadstatus = -1;
    ptrdiff_t savedoffset = 0;
    char* savedtop = 0;
    int fallback = 0;
    wieen_log("wieen: running a script after %lu resumes of the game\n",
              g_preresume_hits);
    wieen_log("wieen: creating thread for %lu bytes in parent %p\n",
              (unsigned long)bclen, parent);
    void* userthread = 0;
    void* thread = 0;
    if (!env_flag("WIEEN_NOTHREAD"))
    {
        if (env_flag("WIEEN_NOUSERTHREAD"))
        {
            void** cb = (void**)((char*)*(void**)((char*)parent + LSTATE_GLOBAL) + 0x6a0);
            userthread = *cb;
            *cb = 0;
        }
        thread = g_newthread(parent);
        if (env_flag("WIEEN_NOUSERTHREAD"))
            *(void**)((char*)*(void**)((char*)parent + LSTATE_GLOBAL) + 0x6a0) = userthread;
    }
    int pushed = thread != 0;

    if (thread && env_flag("WIEEN_CAPDIFF"))
    {
        /* The capabilities of a thread live somewhere in its state: the
         * bytes that differ between the thread of the game and ours are
         * printed, so the field can be found. */
        wieen_log("wieen: the bytes that differ between the parent and the "
                  "thread:\n");
        for (int off = 0; off < 0x20; off++)
        {
            unsigned char a = ((unsigned char*)parent)[off];
            unsigned char b = ((unsigned char*)thread)[off];
            if (a != b)
                wieen_log("wieen:   +%#x: parent=%#x thread=%#x\n", off, a, b);
        }
    }

    if (thread)
    {
        /*
         * Roblox keeps a set of capabilities for every thread: a thread
         * without them is not allowed to touch an instance, and the
         * sandbox says "lacking capability Basic".  A thread that the
         * agent makes has none, so the set of the thread of the game is
         * copied into it: the mask lives at +0x0c of the state.
         */
        unsigned int caps =
            *(unsigned int*)((const unsigned char*)parent + LSTATE_CAPS);
        if (env_flag("WIEEN_RICHCAPS"))
            caps |= g_rich_caps;
        *(unsigned int*)((unsigned char*)thread + LSTATE_CAPS) = caps;
        wieen_log("wieen: the capabilities of the thread are %#x\n", caps);

        if (env_flag("WIEEN_CTXSCAN"))
        {
            /*
             * The context of a script is a chain: every node has the next
             * one at +0x60, and a flag at +0x8f4.  The thread of the game
             * has such a chain, ours has none, so the field that holds it
             * is looked for in the state of the thread of the game.
             */
            for (int off = 0; off < 0x80; off += 8)
            {
                unsigned long v = *(unsigned long*)((char*)parent + off);
                if (!v || !is_mapped((void*)v))
                    continue;
                unsigned long next = *(unsigned long*)((char*)v + 0x60);
                unsigned int flag = *(unsigned int*)((char*)v + 0x8f4);
                wieen_log("wieen:   +%#x -> %p, the next is %p, the flag is "
                          "%#x\n", off, (void*)v, (void*)next, flag);
            }
        }

        const char* copy = getenv("WIEEN_COPYOFF");
        if (copy && *copy)
        {
            /* a field of the thread of the game: the sandbox, the context
             * and the rights of a script live in one of them */
            unsigned long off = strtoul(copy, 0, 0);
            *(unsigned long*)((char*)thread + off) =
                *(unsigned long*)((char*)parent + off);
            wieen_log("wieen: the field +%#lx is copied: %p\n", off,
                      *(void**)((char*)thread + off));
        }
    }

    if (thread && env_flag("WIEEN_CAPSCAN"))
    {
        /* Every state of the VM has its own set of capabilities: the main
         * one of the game is richer than the thread of a script. */
        unsigned char* g =
            *(unsigned char**)((char*)parent + LSTATE_GLOBAL);
        wieen_log("wieen: the states of the VM at %p:\n", g);
        for (unsigned long off = 0; off + 8 <= 0x720; off += 8)
        {
            unsigned long p = *(unsigned long*)(g + off);
            if (!p || !is_mapped((void*)p))
                continue;
            if (*(unsigned long*)((char*)p + LSTATE_GLOBAL) != (unsigned long)g)
                continue;
            wieen_log("wieen:   state %p at +%#lx has the capabilities %#.x\n",
                      (void*)p, off,
                      *(unsigned int*)((char*)p + LSTATE_CAPS));
        }
    }

    wieen_log("wieen: created thread %p\n", thread);

    if (!thread)
        *message = "lua_newthread returned NULL";
    else if (env_flag("WIEEN_NOLOAD"))
    {
        *message = "thread created; load skipped";
        *messagelen = strlen(*message);
    }
    else
    {
        /*
         * The script can run in the thread of the game itself: then it has
         * the sandbox and the context of the game, and its print goes to
         * the console of the game and not only to the log.
         */
        int inthread = env_flag("WIEEN_INTHREAD") && g_pcall && g_dcall &&
                       !g_inthread_off;
        void* rt = inthread ? parent : thread;
        if (inthread)
        {
            char** top = (char**)((char*)parent + LSTATE_TOP);
            char** stack = (char**)((char*)parent + LSTATE_STACK);
            savedtop = *top;
            savedoffset = savedtop - *stack;
            wieen_log("wieen: the script runs in the thread of the game %p\n",
                      parent);
        }

        status = g_load(rt, "=wieen", (const char*)chunk, bclen, 0);
        loadstatus = status;
        wieen_log("wieen: luau_load returned %d\n", status);
        if (status != 0)
        {
            /* The compiler left its complaint on the stack: read it. */
            size_t errlen = 0;
            const char* err = g_tolstring(rt, -1, &errlen);
            wieen_log("wieen: the compiler says: %s\n",
                      err ? err : "(nothing on the stack)");
        }
        char* top = *(char**)((char*)rt + LSTATE_TOP);
        wieen_log("wieen: loaded %lu bytes, the function is at %p\n",
                  (unsigned long)bclen, top - 16);
        if (env_flag("WIEEN_FRAMELOG"))
            wieen_log_frames(rt, top - 16);
        if (status == 0 && env_flag("WIEEN_NORESUME"))
        {
            wieen_log("wieen: resume disabled by WIEEN_NORESUME\n");
            *message = "thread created and chunk loaded; resume skipped";
            *messagelen = strlen(*message);
        }
        else if (status == 0 && inthread)
        {
            /*
             * The function is on the stack of the thread of the game, so it
             * is called right there: the script runs with the sandbox of
             * the game.
             */
            char** ptop = (char**)((char*)parent + LSTATE_TOP);
            char** pbase = (char**)((char*)parent + LSTATE_BASE);
            wieen_log("wieen: the stack of the game: base %p top %p\n",
                      (void*)*pbase, (void*)*ptop);

            /*
             * The thread of the game runs our chunk with the rights it has
             * at that moment, and they are not the rights of a script.  The
             * mask is data of the state, so a wider mask can be lent for the
             * call and given back afterwards.  WIEEN_GAMECAPS=<mask> says
             * which mask to lend.
             */
            unsigned int* caps =
                (unsigned int*)((unsigned char*)parent + LSTATE_CAPS);
            unsigned int savedcaps = *caps;
            const char* gcaps = getenv("WIEEN_GAMECAPS");
            int lent = 0;
            if (gcaps && *gcaps)
            {
                *caps = (unsigned int)strtoul(gcaps, 0, 0);
                lent = 1;
                wieen_log("wieen: the mask of the game is lent as %#x (was "
                          "%#x)\n", *caps, savedcaps);
            }
            else
            {
                /*
                 * A sweep of the masks has to be done without restarting the
                 * client: the value is read from a file before every call.
                 */
                const char* capfile = getenv("WIEEN_CAPSFILE");
                if (capfile && *capfile)
                {
                    FILE* f = fopen(capfile, "r");
                    if (f)
                    {
                        unsigned long v = 0;
                        if (fscanf(f, "%lx", &v) == 1)
                        {
                            *caps = (unsigned int)v;
                            lent = 1;
                            wieen_log("wieen: the mask of the game is lent as "
                                      "%#lx (was %#x)\n", v, savedcaps);
                        }
                        fclose(f);
                    }
                }
            }

            /*
             * The sandbox does not read the mask at +0x0c.  Its check
             * (0x22ea744, "The current thread cannot access 'X' (lacking
             * capability Y)") reads a u64 at [[context]+0x190], and the
             * accessor at 0x22ea488 builds the mask of a thread out of
             * [[L+0x20]+0x80] intersected with a global limit.  The context
             * and the offset are data as well, so they can be lent for the
             * call and given back afterwards.
             */
            void** pctx = (void**)((char*)parent + LSTATE_CTX);
            void* ctx = (*pctx && is_mapped(*pctx)) ? *pctx : 0;
            unsigned long long savedcaps64 = 0;
            int lent64 = 0;
            unsigned long capsoff = WIEEN_CTX_CAPS;
            const char* atenv = getenv("WIEEN_SANDBOXAT");
            if (atenv && *atenv)
                capsoff = strtoul(atenv, 0, 0);
            unsigned long long* caps64 = 0;
            if (ctx && is_mapped((char*)ctx + capsoff))
                caps64 = (unsigned long long*)((char*)ctx + capsoff);
            if (env_flag("WIEEN_SANDBOXLOG"))
                wieen_log("wieen: the sandbox: L=%p ctx=%p caps@%#lx = "
                          "%#llx\n", parent, ctx, capsoff,
                          caps64 ? *caps64 : 0ULL);
            const char* tcaps = getenv("WIEEN_THREADCAPS");
            if (!tcaps || !*tcaps)
            {
                const char* tfile = getenv("WIEEN_THREADCAPSFILE");
                static char tbuf[64];
                if (tfile && *tfile)
                {
                    FILE* tf = fopen(tfile, "r");
                    if (tf)
                    {
                        if (fgets(tbuf, sizeof(tbuf), tf))
                            tcaps = tbuf;
                        fclose(tf);
                    }
                }
            }
            if (caps64 && tcaps && *tcaps)
            {
                savedcaps64 = *caps64;
                *caps64 = strtoull(tcaps, 0, 0);
                lent64 = 1;
                wieen_log("wieen: the caps of the sandbox are lent as %#llx "
                          "(was %#llx)\n", *caps64, savedcaps64);
            }

            if (env_flag("WIEEN_DUMPSTATE"))
            {
                for (int q = 0; q < 0x60; q += 8)
                    wieen_log("wieen: L+%02x = %p\n", q,
                              *(void**)((char*)parent + q));
                for (int q = 0x18; q <= 0x28; q += 8)
                {
                    void* p = *(void**)((char*)parent + q);
                    if (p && is_mapped(p))
                        wieen_log("wieen: [L+%02x]+0x190 = %#llx, +0x80 = "
                                  "%#llx\n", q,
                                  is_mapped((char*)p + 0x190)
                                      ? *(unsigned long long*)((char*)p + 0x190)
                                      : 0ULL,
                                  is_mapped((char*)p + 0x80)
                                      ? *(unsigned long long*)((char*)p + 0x80)
                                      : 0ULL);
                }
                void* c0 = *(void**)((char*)parent + LSTATE_CTX);
                if (c0 && is_mapped(c0))
                    for (int q = 0; q < 0x200; q += 8)
                        wieen_log("wieen: ctx+%03x = %#llx\n", q,
                                  is_mapped((char*)c0 + q)
                                      ? *(unsigned long long*)((char*)c0 + q)
                                      : 0ULL);
            }
            if (env_flag("WIEEN_CHECKERLOG"))
            {
                typedef void* (*fn_single)(void*, int);
                fn_single single = (fn_single)(g_base + 0x2992ee0UL);
                void* chk = single((void*)(g_base + 0x6f85d50UL), 0);
                wieen_log("wieen: checker %p\n", chk);
                if (chk && is_mapped(chk))
                    for (int q = 0; q < 0x80; q += 8)
                        wieen_log("wieen: chk+%02x = %#llx\n", q,
                                  *(unsigned long long*)((char*)chk + q));
            }
            void* fval = top - 16;
            void* closure = (fval && is_mapped(fval)) ? *(void**)fval : 0;
            void* env = (closure && is_mapped(closure))
                            ? *(void**)((char*)closure + 0x18)
                            : 0;
            void** penv = (env && is_mapped((char*)env + 0x70))
                              ? (void**)((char*)env + 0x70)
                              : 0;
            void* savedenv = penv ? *penv : 0;
            int lenved = 0;
            if (env_flag("WIEEN_ENVLOG"))
                wieen_log("wieen: the env of the chunk: closure %p env %p "
                          "mask %p\n", closure, env, penv ? *penv : 0);
            const char* ecaps = getenv("WIEEN_ENVCAPS");
            if (penv)
            {
                /*
                 * In the thread of the game the script is a chunk of ours,
                 * so no sandbox context of the client points at it.  Lend it
                 * the full set by default; WIEEN_ENVCAPS=0 turns that off and
                 * any other value picks a mask explicitly.
                 */
                g_env_mask = (ecaps && *ecaps) ? strtoull(ecaps, 0, 0)
                                               : ~0ULL;
                *penv = &g_env_mask;
                lenved = 1;
                wieen_log("wieen: the caps of the env are lent as %#llx "
                          "(was %p)\n", g_env_mask, savedenv);
            }

            unsigned long long* pchk = 0;
            unsigned long long savedchk = 0;
            const char* ckcaps = getenv("WIEEN_CHECKERCAPS");
            if (ckcaps && *ckcaps)
            {
                typedef void* (*fn_single)(void*, int);
                fn_single single = (fn_single)(g_base + 0x2992ee0UL);
                void* chk = single((void*)(g_base + 0x6f85d50UL), 0);
                if (chk && is_mapped((char*)chk + 0x38))
                {
                    pchk = (unsigned long long*)((char*)chk + 0x30);
                    savedchk = *pchk;
                    *pchk = strtoull(ckcaps, 0, 0);
                    *(void**)((char*)chk + 0x38) = 0;
                    wieen_log("wieen: the caps of the checker are lent as "
                              "%#llx (was %#llx)\n", *pchk, savedchk);
                }
            }

            int rc = wieen_pcall(parent, 0, 1, 0);

            if (pchk)
            {
                *pchk = savedchk;
                wieen_log("wieen: the caps of the checker are %#llx again\n",
                          savedchk);
            }
            if (lenved)
            {
                *penv = savedenv;
                wieen_log("wieen: the caps of the env are %p again\n",
                          savedenv);
            }

            if (lent64)
            {
                *caps64 = savedcaps64;
                wieen_log("wieen: the caps of the sandbox are %#llx again\n",
                          *caps64);
            }
            if (lent)
            {
                *caps = savedcaps;
                wieen_log("wieen: the mask of the game is %#x again\n", *caps);
            }
            wieen_log("wieen: lua_pcall returned %d, the stack of the game: "
                      "base %p top %p\n", rc, (void*)*pbase, (void*)*ptop);
            for (int k = 1; k <= 3; k++)
            {
                char* v = *ptop - 16 * k;
                wieen_log("wieen:   the value at -%d: %p tag %d\n", k, v,
                          is_mapped(v) ? *(int*)(v + 12) : -1);
            }
            status = rc;
            if (rc != 0)
            {
                /*
                 * A script that yields cannot be continued from here: the
                 * call is not yieldable, so the yield of the game refuses it.
                 * Such a script is run outside the thread of the game, in a
                 * thread of its own, where the resume loop handles waiting.
                 */
                size_t whylen = 0;
                const char* why = g_tolstring(parent, -1, &whylen);
                wieen_log("wieen: the script failed in the thread of the "
                          "game: %s\n", why ? why : "(no message)");
                if (why && (strstr(why, "yieldable") ||
                            strstr(why, "yield across")))
                {
                    wieen_log("wieen: the script yields, it runs outside the "
                              "thread of the game\n");
                    *ptop = savedtop;
                    fallback = 1;
                    status = 0;
                }
                else
                {
                    *message = "the script failed in the thread of the game";
                    *messagelen = strlen(*message);
                    status = -1;
                }
            }
            else
            {
                status = 0;
            }
        }
        else if (status == 0)
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

                /*
                 * The script asked for a chunk to be compiled: it gave the
                 * source and waits.  The host compiles it - the client has
                 * no working loadstring - and the result is loaded here.
                 */
                if (g_compile && g_conn_fd >= 0)
                {
                    /*
                     * The client has its own compiler: the source is
                     * compiled inside it, so the bytecode is in the format
                     * of the client and needs no translation.
                     */
                    size_t srclen = 0;
                    const char* src = g_tolstring(thread, -1, &srclen);
                    if (src && srclen && srclen < 65536)
                    {
                        unsigned long outsize = 0;
                        char* code = g_compile(src, srclen, 0, &outsize);
                        wieen_log("wieen: the client compiled %lu bytes into "
                                  "%lu bytes\n", (unsigned long)srclen, outsize);
                        if (code && outsize > 8 && outsize < 0x10000 &&
                            code[0] >= 3 && code[0] <= 14)
                        {
                            int st = g_load(thread, "=wieen", code, outsize, 0);
                            free(code);
                            wieen_log("wieen: the compiled chunk is loaded, "
                                      "load returned %d\n", st);
                            if (st == 0)
                            {
                                status = g_resume(thread, parent, 1);
                                if (status != 1)
                                    break;
                                continue;
                            }
                            status = -1;
                            *message = "the client could not load the "
                                      "compiled chunk";
                            *messagelen = strlen(*message);
                            break;
                        }
                        free(code);
                    }
                }

                if (g_conn_fd >= 0)
                {
                    size_t srclen = 0;
                    const char* src = g_tolstring(thread, -1, &srclen);
                    if (src && srclen && srclen < 65536)
                    {
                        char req[9 + 65536];
                        memcpy(req, "\x00" "compile:", 9);
                        memcpy(req + 9, src, srclen);
                        unsigned int n = (unsigned int)(9 + srclen);
                        if (write(g_conn_fd, &n, 4) == 4 &&
                            write(g_conn_fd, req, n) == (ssize_t)n)
                        {
                            unsigned int rl = 0;
                            if (read(g_conn_fd, &rl, 4) == 4 && rl > 10)
                            {
                                char* buf = (char*)malloc(rl);
                                if (buf && read(g_conn_fd, buf, rl) == (ssize_t)rl &&
                                    memcmp(buf, "\x00" "compiled:", 10) == 0)
                                {
                                    int st = g_load(thread, "=wieen", buf + 10,
                                                    rl - 10, 0);
                                    wieen_log("wieen: the host compiled the "
                                              "source, %u bytes, load returned "
                                              "%d\n", rl - 10, st);
                                    free(buf);
                                    if (st == 0)
                                    {
                                        /* the function is on the stack: it
                                         * is the result of the yield */
                                        status = g_resume(thread, parent, 1);
                                        if (status != 1)
                                            break;
                                        continue;
                                    }
                                    status = -1;
                                    *message = "the host could not compile "
                                              "the source";
                                    *messagelen = strlen(*message);
                                    break;
                                }
                                free(buf);
                            }
                        }
                    }
                }

                if (++resumes > 10000)
                {
                    status = -1;
                    *message = "the script yields over and over";
                    break;
                }
            }

            wieen_log("wieen: lua_resume returned %d, status=%d, resumes=%d\n",
                      status, *(unsigned char*)((char*)thread + LSTATE_STATUS),
                      resumes);
        }

        if (fallback)
        {
            /*
             * The same chunk, run the old way: a thread of its own and the
             * resume loop of the agent, which continues a script that yields.
             * The stack of the game was already put back, so the second run
             * starts from the same place.
             */
            g_inthread_off = 1;
            status = run_one(parent, chunk, bclen, message, messagelen);
            g_inthread_off = 0;
        }

        if (!fallback)
        {
            wieen_log("wieen: reading result\n");
            size_t resultlen = 0;
            *message = g_tolstring(rt, -1, &resultlen);
            *messagelen = resultlen;
        }
        if (!fallback && !*message)
        {
            /*
             * lua_tolstring only knows strings and numbers; for the
             * other types the tag of the value is read from the stack.
             */
            char* top = *(char**)((char*)rt + LSTATE_TOP);
            if (is_mapped(top) && is_mapped(top - 16))
            {
                char* value = top - 16;
                int tag = *(int*)(value + 12);
                static char other[64];
                if (tag == 0)
                {
                    *message = "nil";
                }
                else if (tag == 1)
                {
                    *message = (*(int*)value) ? "true" : "false";
                }
                else if (tag == 5)
                {
                    *message = "table";
                }
                else if (tag == 6)
                {
                    *message = "function";
                }
                else
                {
                    snprintf(other, sizeof(other), "a value of type %d", tag);
                    *message = other;
                }
                *messagelen = strlen(*message);
            }
        }
    }

    if (env_flag("WIEEN_INTHREAD") && g_pcall && g_dcall)
    {
        /* the stack of the thread of the game is put back as it was */
        char** stack = (char**)((char*)parent + LSTATE_STACK);
        char** top = (char**)((char*)parent + LSTATE_TOP);
        *top = *stack + savedoffset;
        wieen_log("wieen: the stack of the thread of the game is restored\n");
    }

    if (status == 1 && loadstatus == 0)
    {
        *message = "coroutine yielded; yielding scripts are not supported yet";
        *messagelen = strlen(*message);
        status = -1;
    }

    /*
     * Drop the thread from the parent's stack.  The pointer saved before
     * lua_newthread cannot be used here: the call may grow the stack of
     * the parent, which reallocates it, and writing the old pointer back
     * would leave L->top pointing into memory that no longer belongs to
     * the state - the client then dies some frames later, far from here.
     * The slot is taken from the top as it is now instead.
     */
    if (pushed && !env_flag("WIEEN_LEAKTHREAD"))
    {
        char** top = (char**)((char*)parent + LSTATE_TOP);
        if (*top && *top - 16 >= *(char**)((char*)parent + LSTATE_STACK))
            *top -= 16;
    }

    return status;
}


/*
 * A script that does not fit into the bytecode the client is willing to
 * load comes in parts: the host splits it, every part is a chunk of its
 * own, and the parts are run one after another in the same VM.
 */
#define MULTI_MAGIC "WIEENMUL"

static unsigned long read_u32(const unsigned char* p)
{
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) |
           ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

/*
 * lua_pcall of upstream lapi.cpp, rebuilt over the two functions the client
 * still has.  CallS and f_call are the upstream layout: luaD_pcall catches
 * the error and restores the stack, luaD_call calls the function.
 */
struct wieen_CallS
{
    void* func;
    int nresults;
};

static void wieen_f_call(void* L, void* ud)
{
    struct wieen_CallS* c = (struct wieen_CallS*)ud;
    g_dcall(L, c->func, c->nresults, 0);
}

static void wieen_state_log(const char* tag, void* L)
{
    if (!env_flag("WIEEN_STATELOG"))
        return;
    char* stack = *(char**)((char*)L + LSTATE_STACK);
    char* top = *(char**)((char*)L + LSTATE_TOP);
    char* base = *(char**)((char*)L + LSTATE_BASE);
    char* ci = *(char**)((char*)L + LSTATE_CI);
    char* baseci = *(char**)((char*)L + 0x18);
    wieen_log("wieen: [%s] status=%d active=%d nCcalls=%u baseCcalls=%u "
              "ci=%ld baseci=%ld base=%ld top=%ld\n", tag,
              (int)*(unsigned char*)((char*)L + LSTATE_STATUS),
              (int)*(unsigned char*)((char*)L + LSTATE_ACTIVE),
              (unsigned)*(unsigned short*)((char*)L + LSTATE_NCCALLS),
              (unsigned)*(unsigned short*)((char*)L + LSTATE_BASECALLS),
              ci && baseci ? (long)(ci - baseci) : -1L,
              (long)(base - stack), (long)(base ? base - stack : 0),
              (long)(top - stack));
}

static int wieen_pcall(void* L, int nargs, int nresults, int errfunc)
{
    char* stack = *(char**)((char*)L + LSTATE_STACK);
    char* top = *(char**)((char*)L + LSTATE_TOP);
    unsigned char* status = (unsigned char*)L + LSTATE_STATUS;
    unsigned char saved = *status;
    struct wieen_CallS c;
    c.func = top - 16 * (nargs + 1);
    c.nresults = nresults;
    (void)errfunc;

    wieen_state_log("before pcall", L);

    /*
     * preresume is called while the resumed thread still says LUA_YIELD.
     * luaD_call/performcall only runs the function when the status is OK, so
     * the status is made ordinary for the nested call and put back afterwards;
     * the resume body owns the real transition.
     */
    *status = 0;
    int rc = g_pcall(L, wieen_f_call, &c, (char*)c.func - stack, 0);
    *status = saved;

    wieen_state_log(rc == 0 ? "after pcall" : "after pcall (error)", L);
    return rc;
}

/*
 * The sandbox of a call is not the mask in the state: the accessor at
 * 0x22ea488 walks the call frames down from ci, takes the innermost Lua
 * closure, and reads a capability mask from [[closure+0x18]+0x70].  This
 * prints that chain so the layout can be checked on a live state.
 */
static void wieen_log_frames(void* L, void* fnval)
{
    char* ci = *(char**)((char*)L + LSTATE_CI);
    char* baseci = *(char**)((char*)L + 0x18);
    wieen_log("wieen: the chunk: value %p, ci %p, baseci %p\n", fnval, ci,
              baseci);
    void* closure = (fnval && is_mapped(fnval)) ? *(void**)fnval : 0;
    if (closure && is_mapped(closure))
    {
        void* ctx = *(void**)((char*)closure + 0x18);
        wieen_log("wieen: the chunk: closure %p ctx %p", closure, ctx);
        if (ctx && is_mapped((char*)ctx + 0x70))
        {
            void* mp = *(void**)((char*)ctx + 0x70);
            wieen_log(" mask ptr %p", mp);
            if (mp && is_mapped(mp))
                wieen_log(" mask %#llx", *(unsigned long long*)mp);
        }
        wieen_log("\n");
    }
    for (int k = 0; k < 8 && ci >= baseci; k++, ci -= 0x30)
    {
        char* tv = *(char**)(ci + 8);
        if (!tv || !is_mapped(tv))
            continue;
        void* c2 = *(void**)tv;
        wieen_log("wieen: frame %d ci %p tv %p tag %d closure %p", k, ci, tv,
                  *(int*)(tv + 0xc), c2);
        if (c2 && is_mapped(c2))
        {
            void* ctx = *(void**)((char*)c2 + 0x18);
            wieen_log(" ctx %p", ctx);
            if (ctx && is_mapped((char*)ctx + 0x70))
            {
                void* mp = *(void**)((char*)ctx + 0x70);
                wieen_log(" mask ptr %p", mp);
                if (mp && is_mapped(mp))
                    wieen_log(" mask %#llx", *(unsigned long long*)mp);
            }
        }
        wieen_log("\n");
    }
}

/*
 * Runs the pending chunk in the given state.  The stack of the state is
 * restored afterwards, so the game does not notice that we were here.
 */
static void run_pending(void* parent)
{
    size_t bclen;

    if (env_flag("WIEEN_NOLOCKS") || env_flag("WIEEN_TAKEONLY") ||
        env_flag("WIEEN_CLAIMNOREPLY"))
    {
        if (!__atomic_exchange_n(&g_pending_ready, 0, __ATOMIC_ACQ_REL) || !parent)
            return;
        bclen = g_pending_len;
        if (env_flag("WIEEN_CLAIMNOREPLY"))
        {
            wieen_log("wieen: command claimed without completion notification\n");
            return;
        }
        if (env_flag("WIEEN_TAKEONLY"))
        {
            snprintf(g_result, sizeof(g_result), "command claimed; no Luau or completion locks");
            g_result_len = strlen(g_result);
            pthread_mutex_lock(&g_lock);
            g_finished = 1;
            pthread_cond_signal(&g_done);
            pthread_mutex_unlock(&g_lock);
            return;
        }
    }
    else
    {
        pthread_mutex_lock(&g_lock);
        if (!g_pending_ready || !parent)
        {
            pthread_mutex_unlock(&g_lock);
            return;
        }
        g_pending_ready = 0;
        bclen = g_pending_len;
        pthread_mutex_unlock(&g_lock);
    }

    static unsigned char chunk[MAX_MESSAGE];
    memcpy(chunk, g_pending, bclen);

    const char* message = 0;
    size_t messagelen = 0;
    int status = -1;

    if (bclen > 12 && memcmp(chunk, MULTI_MAGIC, 8) == 0)
    {
        size_t off = 8;
        unsigned long count = read_u32(chunk + off);
        off += 4;
        wieen_log("wieen: the script comes in %lu parts\n", count);
        for (unsigned long i = 0; i < count; i++)
        {
            if (off + 4 > bclen)
            {
                message = "the parts of the script are broken";
                messagelen = strlen(message);
                status = -1;
                break;
            }
            unsigned long len = read_u32(chunk + off);
            off += 4;
            if (off + len > bclen)
            {
                message = "the parts of the script are broken";
                messagelen = strlen(message);
                status = -1;
                break;
            }
            status = run_one(parent, chunk + off, len, &message, &messagelen);
            off += len;
            if (status != 0)
                break;
        }
    }
    else
    {
        status = run_one(parent, chunk, bclen, &message, &messagelen);
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

}
/*
 * The client runs more than one Luau VM, and only one of them is the one
 * the game itself uses.  The probe asks a VM what it can see: the game VM
 * knows `game` and `workspace`, the other ones do not.
 */
static void run_probe(void* L)
{
    static char saved[MAX_MESSAGE];
    static char savedresult[MAX_MESSAGE];
    size_t savedlen = 0, savedresultlen = 0;
    int savedready = 0, savedfinished = 0;

    pthread_mutex_lock(&g_lock);
    savedlen = g_pending_len;
    savedready = g_pending_ready;
    savedfinished = g_finished;
    savedresultlen = g_result_len;
    if (g_pending_len && g_pending_len < sizeof(saved))
        memcpy(saved, g_pending, g_pending_len);
    if (g_result_len && g_result_len < sizeof(savedresult))
        memcpy(savedresult, g_result, g_result_len);
    memcpy(g_pending, wieen_probe, wieen_probe_size);
    g_pending_len = wieen_probe_size;
    g_pending_ready = 1;
    g_finished = 0;
    pthread_mutex_unlock(&g_lock);

    run_pending(L);

    pthread_mutex_lock(&g_lock);
    snprintf(g_probe_result, sizeof(g_probe_result), "%.*s",
             (int)sizeof(g_probe_result) - 1, g_result);
    if (savedlen && savedlen < sizeof(saved))
    {
        memcpy(g_pending, saved, savedlen);
        g_pending_len = savedlen;
    }
    if (savedresultlen && savedresultlen < sizeof(savedresult))
        memcpy(g_result, savedresult, savedresultlen);
    g_result_len = savedresultlen;
    g_pending_ready = savedready;
    g_finished = savedfinished;
    pthread_mutex_unlock(&g_lock);

    wieen_log("wieen: the VM at %p says %s\n", g_installed_g, g_probe_result);
}

/*
 * The pre-resume callback in the global state.  Unlike a patch of the text,
 * this pointer lives in writable memory, so the integrity check of the
 * client does not see it.  It is called from lua_resume on the game thread,
 * which is exactly the context a script needs.
 */
static void collect_capabilities(unsigned char* g)
{
    unsigned int masks[32];
    int counts[32];
    int count = 0;
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f)
        return;
    char line[512];
    while (fgets(line, sizeof(line), f))
    {
        unsigned long lo, hi;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) != 3)
            continue;
        if (perms[0] != 'r' || perms[1] != 'w')
            continue;
        const unsigned long chunk = 64UL << 20;
        size_t pages = chunk >> 12;
        unsigned char* vec = malloc(pages);
        if (!vec)
            continue;
        for (unsigned long base = lo; base < hi; base += chunk)
        {
            unsigned long len = hi - base < chunk ? hi - base : chunk;
            if (mincore((void*)base, len, vec) != 0)
                continue;
            size_t npages = (len + 0xFFF) >> 12;
            for (size_t pg = 0; pg < npages; pg++)
            {
                if (!(vec[pg] & 1))
                    continue;
                unsigned long page = base + (pg << 12);
                for (unsigned long q = page; q + 8 <= page + 4096; q += 8)
                {
                    if (*(unsigned long*)q != (unsigned long)g)
                        continue;
                    unsigned long l = q - LSTATE_GLOBAL;
                    if (!is_mapped((void*)l))
                        continue;
                    unsigned int c = *(unsigned int*)((char*)l + LSTATE_CAPS);
                    unsigned int bits = 0;
                    for (unsigned int v = c; v; v &= v - 1)
                        bits++;
                    if (bits > 12 || c == 0)
                        continue;
                    int found = -1;
                    for (int i = 0; i < count; i++)
                        if (masks[i] == c)
                        {
                            found = i;
                            break;
                        }
                    if (found < 0)
                    {
                        if (count >= 32)
                            continue;
                        found = count++;
                        masks[found] = c;
                        counts[found] = 0;
                    }
                    counts[found]++;
                }
            }
        }
        free(vec);
    }
    fclose(f);
    for (int i = 0; i < count; i++)
        if (counts[i] >= 2)
        {
            g_rich_caps |= masks[i];
            wieen_log("wieen: the mask %#x is seen in %d states\n", masks[i],
                      counts[i]);
        }
    wieen_log("wieen: the whole set of the capabilities is %#x\n", g_rich_caps);
}

static void wieen_preresume(void* L)
{
    if (g_in_preresume)
    {
        if (g_installed_original)
            ((void (*)(void*))g_installed_original)(L);
        return;
    }
    g_in_preresume = 1;
    __atomic_add_fetch(&g_preresume_hits, 1, __ATOMIC_RELAXED);
    if (g_installed_original)
        ((void (*)(void*))g_installed_original)(L);
    if (g_probe_wanted)
    {
        g_probe_wanted = 0;
        g_probe_done = 1;
        run_probe(L);
    }
    else if (__atomic_load_n(&g_pending_ready, __ATOMIC_RELAXED))
    {
        if (g_want_caps && env_flag("WIEEN_INTHREAD"))
        {
            /*
             * The resumed threads of the game carry different masks: a
             * script of the game has rights a renderer thread does not.
             * WIEEN_WANTCAPS=<mask> says which rights the thread must have
             * for our script to run in it; the others are skipped and the
             * chunk waits for a better one.
             */
            unsigned int caps =
                *(unsigned int*)((char*)L + LSTATE_CAPS);
            if ((caps & g_want_caps) != g_want_caps)
            {
                unsigned long skipped = __atomic_add_fetch(&g_caps_skipped, 1,
                                                           __ATOMIC_RELAXED);
                if (skipped == 1 || (skipped % 2000) == 0)
                    wieen_log("wieen: the mask %#x is not the one asked for "
                              "(%#x), %lu threads skipped\n", caps,
                              g_want_caps, skipped);
                g_in_preresume = 0;
                return;
            }
            wieen_log("wieen: the mask %#x is the one asked for, running "
                      "here\n", caps);
            g_want_caps = 0;
        }
        if (state_is_usable(L))
            run_pending(L);
        else
            wieen_log("wieen: that state does not look like a Luau state (%s), "
                      "skipping\n", state_problem(L));
    }
    g_in_preresume = 0;
}

/*
 * Every executable mapping of the client, collected when the image is
 * identified.  A pointer into the client's code has to be checked against
 * all of them: the client patches and splits its text at runtime, so the
 * mapping that holds lua_resume is not the only one and is not the whole
 * of the code.
 */
#define IMAGE_SPAN 0x10000000UL
#define MAX_TEXT_RANGES 8
static unsigned long g_text_lo[MAX_TEXT_RANGES];
static unsigned long g_text_hi[MAX_TEXT_RANGES];
static int g_text_count;

static int in_client_text(unsigned long p)
{
    for (int i = 0; i < g_text_count; i++)
        if (p >= g_text_lo[i] && p < g_text_hi[i])
            return 1;
    return 0;
}

/*
 * The state of a VM has the callback of Roblox in it, the two hooks of
 * Luau around it and a small counter behind them.  A piece of memory
 * that only looks like that is not the state of a VM.
 */
static int looks_like_global_state(unsigned char* g, unsigned long lo, unsigned long hi)
{
    if ((unsigned long)g < lo || (unsigned long)g + 0x720 > hi)
        return 0;
    unsigned long userthread = *(unsigned long*)(g + 0x6a0);
    if (!in_client_text(userthread))
        return 0;
    unsigned long pre = *(unsigned long*)(g + 0x678);
    unsigned long post = *(unsigned long*)(g + 0x650);
    if (pre && !in_client_text(pre))
        return 0;
    if (post && !in_client_text(post))
        return 0;
    unsigned long marker = *(unsigned long*)(g + 0x6b0);
    if (marker > 0x10000)
        return 0;
    return 1;
}

static int plausible_state(unsigned char* L, unsigned long g,
                           unsigned long lo, unsigned long hi)
{
    if ((unsigned long)L < lo || (unsigned long)L + 0x60 > hi)
        return 0;
    if (*(unsigned long*)(L + LSTATE_GLOBAL) != g)
        return 0;
    unsigned long stack = *(unsigned long*)(L + LSTATE_STACK);
    unsigned long top = *(unsigned long*)(L + LSTATE_TOP);
    unsigned long base = *(unsigned long*)(L + LSTATE_BASE);
    if (!stack || !top || !base)
        return 0;
    if (top < stack || top - stack > 0x1000000)
        return 0;
    if (base < stack || base > top + 0x10000)
        return 0;
    return 1;
}

static int has_state_reference(unsigned long g, unsigned long lo, unsigned long hi)
{
    const unsigned long chunk = 64UL << 20;
    size_t pages = chunk >> 12;
    unsigned char* vec = malloc(pages);
    if (!vec)
        return 0;
    int found = 0;
    for (unsigned long base = lo; base < hi && !found; base += chunk)
    {
        unsigned long len = hi - base < chunk ? hi - base : chunk;
        if (mincore((void*)base, len, vec) != 0)
            continue;
        size_t npages = (len + 0xFFF) >> 12;
        for (size_t p = 0; p < npages && !found; p++)
        {
            if (!(vec[p] & 1))
                continue;
            unsigned long page = base + (p << 12);
            for (unsigned long q = page; q + 8 <= page + 4096; q += 8)
            {
                if (*(unsigned long*)q != g)
                    continue;
                unsigned long l = q - LSTATE_GLOBAL;
                if (plausible_state((unsigned char*)l, g, lo, hi))
                {
                    if (env_flag("WIEEN_CAPSCAN"))
                    {
                        static int shown;
                        if (shown < 8)
                        {
                            shown++;
                            wieen_log("wieen:   state %p has the capabilities "
                                      "%#.x\n", (void*)l,
                                      *(unsigned int*)((char*)l + LSTATE_CAPS));
                        }
                    }
                    found = 1;
                    break;
                }
            }
        }
    }
    free(vec);
    return found;
}

/*
 * Several Luau VMs live in the client and each of them has its own global
 * state, so the search collects every candidate instead of the first one.
 * The state of the VM the game actually runs its scripts in is the one
 * whose pre-resume slot is reached; the others are tried in turn.
 */
#define MAX_CANDIDATES 16
static unsigned char* g_candidates[MAX_CANDIDATES];
static int g_candidate_count;

static void dump_candidate(unsigned char* g)
{
    wieen_log("wieen: candidate g=%p cb[0x650]=%#lx cb[0x678]=%#lx "
              "cb[0x6a0]=%#lx cb[0x6b0]=%#lx\n",
              g, *(unsigned long*)(g + 0x650), *(unsigned long*)(g + 0x678),
              *(unsigned long*)(g + 0x6a0), *(unsigned long*)(g + 0x6b0));
}

/* Scan resident pages only: the mimalloc arena reserves a gigabyte and
 * most of it is untouched, and faulting all of it in just to read zeros
 * would cost more than the search. */
static unsigned char* scan_region(unsigned long lo, unsigned long hi,
                                  unsigned long anchor)
{
    const unsigned long chunk = 64UL << 20;
    size_t pages = chunk >> 12;
    unsigned char* vec = malloc(pages);
    if (!vec)
        return 0;
    unsigned char* found = 0;
    for (unsigned long base = lo; base < hi; base += chunk)
    {
        unsigned long len = hi - base < chunk ? hi - base : chunk;
        if (mincore((void*)base, len, vec) != 0)
            continue;
        size_t npages = (len + 0xFFF) >> 12;
        for (size_t p = 0; p < npages; p++)
        {
            if (!(vec[p] & 1))
                continue;
            unsigned long page = base + (p << 12);
            for (unsigned long q = page; q + 8 <= page + 4096; q += 8)
            {
                unsigned long v = *(unsigned long*)q;
                int hit = anchor ? v == anchor : in_client_text(v);
                if (!hit)
                    continue;
                unsigned long g = q - 0x6a0;
                if (!looks_like_global_state((unsigned char*)g, lo, hi) ||
                    !has_state_reference(g, lo, hi))
                    continue;
                if (!found)
                    found = (unsigned char*)g;
                if (g_candidate_count < MAX_CANDIDATES)
                    g_candidates[g_candidate_count++] = (unsigned char*)g;
            }
        }
    }
    free(vec);
    return found;
}

static unsigned char* find_global_state(void)
{
    if (!g_text_count)
        return 0;

    /*
     * In this client the userthread callback Roblox stores at g+0x6a0 is
     * the function at base+0x22e260b.  Use it as a needle when the code
     * there still matches; otherwise fall back to any pointer into the
     * client text, which is a much broader but still usable search.
     */
    static const unsigned char SIG_USERTHREAD[] = {
        0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55,
        0x41, 0x54, 0x53, 0x50, 0x49, 0x89, 0xf6, 0x49, 0x89, 0xfc,
    };
    unsigned long needle = g_base + 0x22e260bUL;
    static int said;
    int have_needle =
        memcmp((void*)needle, SIG_USERTHREAD, sizeof(SIG_USERTHREAD)) == 0;
    if (have_needle && !said)
    {
        said = 1;
        wieen_log("wieen: userthread callback at %p matches the signature\n",
                  (void*)needle);
    }

    FILE* f = fopen("/proc/self/maps", "r");
    if (!f)
        return 0;
    char line[512];
    unsigned char* found = 0;
    g_scan_tid = (pid_t)syscall(SYS_gettid);
    if (sigsetjmp(g_scan_jmp, 1) == 0)
    {
        g_scan_active = 1;
        while (fgets(line, sizeof(line), f))
        {
            unsigned long lo, hi;
            char perms[8] = {0};
            if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) != 3)
                continue;
            if (perms[0] != 'r' || perms[1] != 'w')
                continue;
            unsigned char* r = scan_region(lo, hi, have_needle ? needle : 0);
            if (r && !found)
                found = r;
            if (found && g_candidate_count >= MAX_CANDIDATES)
                break;
        }
    }
    g_scan_active = 0;
    fclose(f);
    for (int i = 0; i < g_candidate_count; i++)
        dump_candidate(g_candidates[i]);
    return found;
}

/*
 * The callback is put into the pre-resume slot of a global state and taken
 * out again when the state turns out to be the wrong one.
 */
static void remove_preresume(void)
{
    if (!g_installed_g)
        return;
    __atomic_store_n((void**)(g_installed_g + 0x678), g_installed_original,
                     __ATOMIC_RELEASE);
    wieen_log("wieen: the callback is taken out of %p\n", g_installed_g);
    g_installed_g = 0;
    g_installed_original = 0;
}

static int install_preresume(unsigned char* g)
{
    if (g_installed_g == g)
        return 1;
    remove_preresume();
    g_installed_original = *(void**)(g + 0x678);
    __atomic_store_n((void**)(g + 0x678), (void*)wieen_preresume,
                     __ATOMIC_RELEASE);
    g_installed_g = g;
    wieen_log("wieen: global state at %p, preresume %p -> %p\n", g,
              g_installed_original, (void*)wieen_preresume);
    return 1;
}

/*
 * The client holds several Luau VMs, each with its own global state, and
 * only one of them belongs to the game.  A VM that never resumes anything
 * is not the one we are after; a VM that does is asked what it can see.
 */
static void* selector_thread(void* arg)
{
    (void)arg;
    unsigned char* live = 0;
    for (int round = 0; round < 30 && !g_global_state; round++)
    {
        if (!g_candidate_count && !find_global_state())
        {
            /* The VM of the game is not there yet: it is created while the
             * client starts, and the search is expensive, so it waits a
             * little before it looks again. */
            usleep(2000000);
            continue;
        }
        for (int i = 0; i < g_candidate_count; i++)
        {
            if (g_global_state)
                break;
            install_preresume(g_candidates[i]);
            unsigned long before = g_preresume_hits;
            for (int t = 0; t < 50 && g_preresume_hits == before; t++)
                usleep(100000);
            if (g_preresume_hits == before)
            {
                wieen_log("wieen: the VM at %p does not resume anything\n",
                          g_candidates[i]);
                continue;
            }
            if (!live)
                live = g_candidates[i];
            g_probe_wanted = 1;
            g_probe_done = 0;
            for (int t = 0; t < 50 && !g_probe_done; t++)
                usleep(100000);
            wieen_log("wieen: the VM at %p says %s\n", g_candidates[i],
                      g_probe_result);
            if (strstr(g_probe_result, "Instance"))
            {
                g_global_state = g_candidates[i];
                wieen_log("wieen: the state of the game is %p\n",
                          g_global_state);
                if (env_flag("WIEEN_RICHCAPS"))
                    collect_capabilities(g_candidates[i]);
                return 0;
            }
            remove_preresume();
        }
        if (live && !g_global_state)
        {
            /* None of the VMs answered the probe, so the one that runs is
             * taken: it is the only one that resumes anything. */
            install_preresume(live);
            g_global_state = live;
            wieen_log("wieen: the state in use is %p\n", g_global_state);
            return 0;
        }
        usleep(500000);
    }
    wieen_log("wieen: no state of the game was found\n");
    return 0;
}

/*
 * The set of the capabilities of a thread is a mask in the field +0x0c of
 * the state.  The thread of the game that calls us has only a part of the
 * rights, so the sets of all the states of the VM are looked at and united
 * with it: the sets are not nested, a bit can be missing in one of them.
 */
/*
 * The socket waits for the selection when a command comes in: the script
 * has to run in the VM of the game, and the VM is only known once it has
 * answered the probe.
 */
static int ensure_preresume(void)
{
    if (g_global_state)
        return 1;
    for (int i = 0; i < 600 && !g_global_state; i++)
        usleep(100000);
    if (g_global_state)
        return 1;
    wieen_log("wieen: could not find the global state of Luau\n");
    return 0;
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
     * A fault of the search for the state is ours: the page the game has
     * just freed is read.  The search is given up, the game is not hurt.
     */
    if (g_scan_active && (pid_t)syscall(SYS_gettid) == g_scan_tid)
    {
        g_scan_active = 0;
        siglongjmp(g_scan_jmp, 1);
    }

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
 * The client is not mapped as one readable blob: the loader keeps the ELF
 * header on a read-only page and starts the text a page or two later, and
 * the client itself calls mprotect on the parts it patches at runtime.
 * Looking for one "executable range that contains the base" therefore
 * works only by luck, and it stopped working when the client moved from
 * 4 KiB to 16 KiB pages.  So the agent keeps every executable mapping of
 * the image and looks the signatures up in all of them.
 */
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
/* the socket server                                                  */
/* ------------------------------------------------------------------ */

static int read_exact(int fd, void* buf, size_t len)
{
    size_t got = 0;
    while (got < len)
    {
        ssize_t n = read(fd, (char*)buf + got, len - got);
        /*
         * A signal of the game interrupts the read: that is not the end of
         * the connection, the rest of the message is still on its way.
         */
        if (n < 0 && errno == EINTR)
            continue;
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
        if (n < 0 && errno == EINTR)
            continue;
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

        /*
         * The state of the game is looked up before the script is read: the
         * probe of the selector uses the same buffer, and the answer of the
         * game has to be known before the script can be handed over.
         */
        wieen_log("wieen: command of %u bytes received\n", len);
        if (!ensure_preresume())
        {
            static char sink[4096];
            uint32_t left = len;
            while (left)
            {
                size_t want = left < sizeof(sink) ? left : sizeof(sink);
                if (read_exact(fd, sink, want) != 0)
                    return;
                left -= (uint32_t)want;
            }
            const char message[] = "the Luau state was not found";
            uint32_t outlen = (uint32_t)(sizeof(message) - 1);
            if (write_exact(fd, &outlen, sizeof(outlen)) != 0)
                return;
            if (write_exact(fd, message, outlen) != 0)
                return;
            continue;
        }

        /* the socket of the host is where the sources are compiled */
        g_conn_fd = fd;
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        pthread_mutex_lock(&g_lock);
        g_pending_len = 0;
        g_pending_ready = 0;
        g_finished = 0;
        g_result_len = 0;
        pthread_mutex_unlock(&g_lock);

        if (len && read_exact(fd, g_pending, len) != 0)
            return;

        /*
         * Which thread of the game this command wants, if any: the mask is
         * re-read for every command, so a sweep does not need a restart.
         */
        g_want_caps = 0;
        g_caps_skipped = 0;
        const char* want = getenv("WIEEN_WANTCAPS");
        if (want && *want)
            g_want_caps = (unsigned int)strtoul(want, 0, 0);
        const char* wantfile = getenv("WIEEN_WANTFILE");
        if (wantfile && *wantfile)
        {
            FILE* wf = fopen(wantfile, "r");
            if (wf)
            {
                unsigned long v = 0;
                if (fscanf(wf, "%lx", &v) == 1)
                    g_want_caps = (unsigned int)v;
                fclose(wf);
            }
        }

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
     * The handlers of the game are watched, but they are given the fault
     * back untouched: a fault of the game is the game's own business.  Only
     * a fault of the search for the state is caught by us, and it does not
     * reach this point.
     */
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

    /*
     * The call of a function of Luau: the agent runs the script in the
     * thread of the game, so it needs lua_pcall of the same copy of the
     * VM.  The offset can be given by hand:
     * WIEEN_ALTPCALL=<offset of lua_pcall in the image>.
     */
    /*
     * The compiler of Luau inside the client: the source of a loadstring is
     * compiled by the client itself, so the bytecode is in its format.
     */
    /*
     * The compiler of Luau inside the client: the source of a loadstring is
     * compiled by the client itself, so the bytecode is in the format of the
     * client and needs no translation.  WIEEN_CLICOMP=<offset> picks another
     * copy of the compiler.
     */
    {
        /*
         * The client has its own compiler of Luau (the Roblox wrapper of
         * it is at 0x26d6400), but its calling convention is not the one of
         * upstream Luau: the source is the third argument there.  So it is
         * only used when the offset is given by hand:
         * WIEEN_CLICOMP=<offset>.
         */
        const char* clicomp = getenv("WIEEN_CLICOMP");
        if (clicomp && *clicomp)
        {
            unsigned long off = strtoul(clicomp, 0, 0);
            g_compile = (fn_compile)((unsigned char*)g_base + off);
            wieen_log("wieen: the compiler of the client is at %p (offset %#lx)\n",
                      (void*)g_compile, off);
        }
    }

    if (hash == WIEEN_KNOWN_HASH)
    {
        g_pcall = (fn_raw_pcall)((unsigned char*)g_base + LUA_RVA_D_PCALL);
        g_dcall = (fn_dcall)((unsigned char*)g_base + LUA_RVA_D_CALL);
        wieen_log("wieen: luaD_pcall at %p, luaD_call at %p\n",
                  (void*)g_pcall, (void*)g_dcall);
    }

    const char* altpcall = getenv("WIEEN_ALTPCALL");
    if (altpcall && *altpcall)
    {
        unsigned long off = strtoul(altpcall, 0, 0);
        g_pcall = (fn_raw_pcall)((unsigned char*)g_base + off);
        wieen_log("wieen: luaD_pcall is taken from %p (offset %#lx)\n",
                  (void*)g_pcall, off);
    }
    const char* altdcall = getenv("WIEEN_ALTD_CALL");
    if (altdcall && *altdcall)
    {
        unsigned long off = strtoul(altdcall, 0, 0);
        g_dcall = (fn_dcall)((unsigned char*)g_base + off);
        wieen_log("wieen: luaD_call is taken from %p (offset %#lx)\n",
                  (void*)g_dcall, off);
    }

    /*
     * The loader that Roblox wraps around luau_load refuses a bytecode
     * blob of 280 bytes or more ("bytecode corrupted"), so the plain
     * loader of another copy of Luau in the client can be tried instead:
     * WIEEN_ALTLOAD=<offset of lua_load in the image>.
     */
    const char* alt = getenv("WIEEN_ALTLOAD");
    if (alt && *alt)
    {
        unsigned long off = strtoul(alt, 0, 0);
        g_load = (fn_load)((unsigned char*)g_base + off);
        wieen_log("wieen: the loader is taken from %p (offset %#lx)\n",
                  (void*)g_load, off);
    }

    if (!g_resume_addr || !g_load || !g_tolstring || !g_newthread)
    {
        wieen_log("wieen: not installing, missing lua_resume=%d luau_load=%d "
                  "lua_tolstring=%d lua_newthread=%d\n",
                  g_resume_addr != 0, g_load != 0, g_tolstring != 0,
                  g_newthread != 0);
        return 0;
    }

    /*
     * The code of the client is left alone.  It checks the bytes of its
     * own text about a minute after the start and leaves when they do not
     * match, so a patch of lua_resume is not an option any more: the
     * hook is the pre-resume callback in the state of Luau, and that
     * pointer lives in writable memory the check does not look at.
     */
    wieen_log("wieen: the code of the client is left alone\n");

    pthread_t thread;
    if (pthread_create(&thread, 0, server_thread, 0) == 0)
        pthread_detach(thread);
    if (pthread_create(&thread, 0, selector_thread, 0) == 0)
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
    wieen_log("wieen: the hook is the pre-resume callback of the state of Luau\n");
    pthread_t thread;
    if (pthread_create(&thread, 0, setup_thread, 0) == 0)
        pthread_detach(thread);
}
