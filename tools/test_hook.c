/*
 * Test the hook machinery outside the game.
 *
 * The stub, the trampoline and the patch are the same as in the agent, so
 * this shows whether the hook itself is sound.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define PROLOGUE_LEN 13

static int g_called;
static void* g_trampoline;

static void handler(void* L)
{
    g_called++;
    write(2, "handler\n", 8);
}

/* the same prologue the client's lua_pcall has */
__attribute__((naked)) int target(int x)
{
    __asm__ volatile(
        "push %rbp\n"
        "mov %rsp,%rbp\n"
        "push %r15\n"
        "push %r14\n"
        "push %rbx\n"
        "push %rax\n"
        "mov %esi,%r14d\n"
        "mov %edi,%ebx\n"
        "mov %ebx,%eax\n"
        "add $1,%eax\n"
        "pop %rax\n"
        "pop %rbx\n"
        "pop %r14\n"
        "pop %r15\n"
        "pop %rbp\n"
        "ret\n");
}

static void* alloc_exec(size_t len)
{
    void* p = mmap(0, len, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? 0 : p;
}

static unsigned char* g_stub;
static unsigned char* g_tramp;

static void install(unsigned char* tgt)
{
    unsigned char* tramp = alloc_exec(4096);
    memcpy(tramp, tgt, PROLOGUE_LEN);
    unsigned char* p = tramp + PROLOGUE_LEN;
    *p++ = 0x48; *p++ = 0xB8;
    unsigned long cont = (unsigned long)(tgt + PROLOGUE_LEN);
    for (int i = 0; i < 8; i++)
        *p++ = (unsigned char)(cont >> (i * 8));
    *p++ = 0xFF; *p++ = 0xE0;
    g_trampoline = tramp;

    unsigned char* stub = alloc_exec(4096);
    unsigned char* s = stub;
    *s++ = 0x48; *s++ = 0x81; *s++ = 0xEC; *s++ = 0x80; *s++ = 0x00; *s++ = 0x00; *s++ = 0x00;
    *s++ = 0x50; *s++ = 0x57; *s++ = 0x56; *s++ = 0x52; *s++ = 0x51;
    *s++ = 0x41; *s++ = 0x50; *s++ = 0x41; *s++ = 0x51;
    *s++ = 0x53; *s++ = 0x55;
    *s++ = 0x41; *s++ = 0x54; *s++ = 0x41; *s++ = 0x55;
    *s++ = 0x41; *s++ = 0x56; *s++ = 0x41; *s++ = 0x57;
    *s++ = 0x48; *s++ = 0x8B; *s++ = 0x7C; *s++ = 0x24; *s++ = 0x08;
    *s++ = 0x48; *s++ = 0xB8;
    {
        unsigned long v = (unsigned long)(void*)handler;
        for (int i = 0; i < 8; i++)
            s[i] = (unsigned char)(v >> (i * 8));
        s += 8;
    }
    *s++ = 0xFF; *s++ = 0xD0;
    *s++ = 0x41; *s++ = 0x5F; *s++ = 0x41; *s++ = 0x5E; *s++ = 0x41; *s++ = 0x5D;
    *s++ = 0x41; *s++ = 0x5C; *s++ = 0x5D; *s++ = 0x5B; *s++ = 0x41; *s++ = 0x59;
    *s++ = 0x41; *s++ = 0x58; *s++ = 0x59; *s++ = 0x5A; *s++ = 0x5E; *s++ = 0x5F;
    *s++ = 0x58;
    *s++ = 0x48; *s++ = 0x81; *s++ = 0xC4; *s++ = 0x80; *s++ = 0x00; *s++ = 0x00; *s++ = 0x00;
    *s++ = 0x48; *s++ = 0xB8;
    {
        unsigned long v = (unsigned long)tramp;
        for (int i = 0; i < 8; i++)
            s[i] = (unsigned char)(v >> (i * 8));
        s += 8;
    }
    *s++ = 0xFF; *s++ = 0xE0;

    g_stub = stub;
    g_tramp = tramp;
    tgt[0] = 0x49; tgt[1] = 0xBB;
    unsigned long a = (unsigned long)stub;
    for (int i = 0; i < 8; i++)
        tgt[2 + i] = (unsigned char)(a >> (i * 8));
    tgt[10] = 0x41; tgt[11] = 0xFF; tgt[12] = 0xE3;
}

int main(void)
{
    long page = ((long)target) & ~0xFFFUL;
    if (mprotect((void*)page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    {
        perror("mprotect");
        return 1;
    }
    install((unsigned char*)target);
    int plain = target(41);
    write(2, "before\n", 7);
    {
        FILE* f = fopen("/tmp/opencode/stub.bin", "wb");
        fwrite(g_stub, 1, 64, f);
        fclose(f);
        f = fopen("/tmp/opencode/tramp.bin", "wb");
        fwrite(g_tramp, 1, 64, f);
        fclose(f);
    }
    int r = target(41);
    write(2, "after\n", 6);
    printf("unhooked target(41) = %d, hooked = %d, handler called %d time(s)\n",
           plain, r, g_called);
    return (r == plain && g_called == 1) ? 0 : 1;
}
