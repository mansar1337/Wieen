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
 *   - hooks lua_pcall, which hands us the game's own lua_State whenever
 *     the game runs a script,
 *   - serves a UNIX socket: the host sends a compiled Luau chunk, the
 *     agent runs it inside the game's VM and returns the result.
 *
 * The code always runs on the game's script thread, inside the hook of
 * lua_pcall, because a Luau state must not be touched from another
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
typedef int (*fn_pcall)(void* L, int nargs, int nresults, int errfunc);
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

static const unsigned char SIG_PCALL[] = {
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
static const struct signature SIGNATURES[] = {
    {"lua_pcall", SIG_PCALL, (int)sizeof(SIG_PCALL), 0x22e9432UL},
    {"luau_load", SIG_LOAD, (int)sizeof(SIG_LOAD), 0x22e4b72UL},
    {"lua_tolstring", SIG_TOLSTRING, (int)sizeof(SIG_TOLSTRING), 0x22e5f48UL},
};
#define NSIG (int)(sizeof(SIGNATURES) / sizeof(SIGNATURES[0]))

static fn_load g_load;
static fn_pcall g_pcall;
static fn_tolstring g_tolstring;
static void* g_pcall_addr;
static unsigned long g_base;

/* the offsets of the stack in a lua_State, taken from the client's code */
#define LSTATE_BASE 0x48
#define LSTATE_TOP 0x50

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
static void wieen_on_pcall(void* L, long a, long b, long c);
static void (*g_handler)(void*, long, long, long) = wieen_on_pcall;

/* ------------------------------------------------------------------ */
/* a small view of the memory map                                     */
/* ------------------------------------------------------------------ */

struct maprange
{
    unsigned long lo;
    unsigned long hi;
};

static struct maprange g_maps[512];
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

static int is_mapped(void* p)
{
    unsigned long a = (unsigned long)p;
    for (int i = 0; i < g_mapcount; i++)
        if (a >= g_maps[i].lo && a < g_maps[i].hi)
            return 1;
    return 0;
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

    void* global = *(void**)((char*)L + 0x38);
    if (!global || !is_mapped(global))
        return 0;
    if (!is_mapped((char*)global + 0x48) || !is_mapped((char*)global + 0x50))
        return 0;

    char* base = *(char**)((char*)L + 0x48);
    char* top = *(char**)((char*)L + 0x50);
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
static void run_pending(void* L)
{
    unsigned char* bytecode;
    size_t bclen;

    pthread_mutex_lock(&g_lock);
    if (!g_pending_ready || !L)
    {
        pthread_mutex_unlock(&g_lock);
        return;
    }
    g_pending_ready = 0;
    bytecode = g_pending;
    bclen = g_pending_len;
    pthread_mutex_unlock(&g_lock);

    static unsigned char chunk[MAX_MESSAGE];
    memcpy(chunk, bytecode, bclen);

    /* remember where the stack was */
    char* base = *(char**)((char*)L + LSTATE_BASE);
    char* top = *(char**)((char*)L + LSTATE_TOP);
    ptrdiff_t slots = (top - base) / 16;

    char* message;
    size_t messagelen = 0;
    int status = -1;

    wieen_log("wieen: running %lu bytes of bytecode in %p\n", (unsigned long)bclen, L);
    int rc = g_load(L, "=wieen", (const char*)chunk, bclen, 0);
    wieen_log("wieen: luau_load returned %d\n", rc);
    if (rc != 0)
    {
        message = (char*)g_tolstring(L, -1, &messagelen);
        status = -1;
    }
    else
    {
        status = g_pcall(L, 0, 1, 0);
        wieen_log("wieen: pcall returned %d\n", status);
        message = (char*)g_tolstring(L, -1, &messagelen);
        wieen_log("wieen: tolstring gave %p (%lu bytes)\n", message,
                  (unsigned long)messagelen);
    }

    pthread_mutex_lock(&g_lock);
    if (status == 0)
    {
        copy_result(g_result, sizeof(g_result), &g_result_len, message, messagelen);
    }
    else
    {
        static const char prefix[] = "error: ";
        size_t n = sizeof(prefix) - 1;
        memcpy(g_result, prefix, n);
        if (message && messagelen && n + messagelen < sizeof(g_result))
        {
            memcpy(g_result + n, message, messagelen);
            n += messagelen;
        }
        g_result[n] = 0;
        g_result_len = n;
    }
    g_finished = 1;
    pthread_cond_signal(&g_done);
    pthread_mutex_unlock(&g_lock);

    /* put the stack back where it was */
    base = *(char**)((char*)L + LSTATE_BASE);
    *(char**)((char*)L + LSTATE_TOP) = base + slots * 16;
}

static volatile int g_hits;

static void wieen_on_pcall(void* L, long a, long b, long c)
{
    if (g_in_hook)
        return;
    g_in_hook = 1;
    g_hits++;
    if (g_hits <= 8 || (g_hits % 200) == 0)
    {
        void* global = L ? *(void**)((char*)L + 0x38) : 0;
        unsigned long* f = L ? (unsigned long*)L : 0;
        wieen_log("wieen: lua_pcall hit %d, L=%p global=%p args=%ld,%ld,%ld"
                  " state[8]=%#lx state[0x48]=%#lx state[0x50]=%#lx\n",
                  g_hits, L, global, a, b, c, f[8], f[0x48], f[0x50]);
    }
    if (state_is_usable(L))
        run_pending(L);
    else if (g_hits <= 8)
        wieen_log("wieen: that state does not look like a Luau state, skipping\n");
    g_in_hook = 0;
}

/* ------------------------------------------------------------------ */
/* a crash handler, so a fault inside the game says where it happened */
/* ------------------------------------------------------------------ */

static void (*g_old_segv)(int, siginfo_t*, void*);

static void wieen_crash(int sig, siginfo_t* info, void* uc)
{
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
    if (g_base)
        wieen_log("wieen: rip is at client offset %#lx\n", rip - g_base);
    /* the bytes around the fault, and the mapping it belongs to */
    {
        char code[64];
        int n = 0;
        for (int i = 0; i < 32; i++)
        {
            unsigned char b = ((unsigned char*)rip)[i];
            n += snprintf(code + n, sizeof(code) - n, "%02x", b);
        }
        wieen_log("wieen: code at rip: %s\n", code);
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
    *s++ = 0x48; *s++ = 0x8B; *s++ = 0x7C; *s++ = 0x24; *s++ = 0x08; /* mov rdi,[rsp+8] */
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

    for (int i = 0; i < NSIG; i++)
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
            g_pcall_addr = at;
        else if (i == 1)
            g_load = (fn_load)at;
        else
            g_tolstring = (fn_tolstring)at;
    }

    if (!g_pcall_addr || !g_load || !g_tolstring)
        return 0;

    if (getenv("WIEEN_NOHOOK"))
    {
        wieen_log("wieen: hook disabled by WIEEN_NOHOOK\n");
    }
    else if (install_hook((unsigned char*)g_pcall_addr, SIG_PCALL,
                          (int)sizeof(SIG_PCALL)) != 0)
        return 0;
    else
    {
        wieen_log("wieen: hooked lua_pcall at %p\n", g_pcall_addr);
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
