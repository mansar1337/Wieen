/*
 * Wieen loader shim — replaces Sober's /app/bin/libbadcpu.so.
 *
 * Sober's own loader (libloader.so) loads libbadcpu.so into the Roblox
 * client process.  The original library only installs a SIGILL handler, so
 * this shim keeps that behaviour and additionally loads the Wieen agent.
 *
 * Both loads happen on a helper thread: doing them inside the constructor
 * would call dlopen() while the loader still holds its lock, which
 * deadlocks the client.
 *
 * The original is kept next to it as libbadcpu_orig.so.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>

#define ORIGINAL_LIB "/app/bin/libbadcpu_orig.so"

static void* wieen_load_all(void* arg)
{
    (void)arg;
    /* the real thing first: it installs the SIGILL handler */
    dlopen(ORIGINAL_LIB, RTLD_NOW | RTLD_GLOBAL);

    const char* agent = getenv("WIEEN_AGENT");
    if (agent && *agent)
        dlopen(agent, RTLD_NOW | RTLD_GLOBAL);
    return 0;
}

__attribute__((constructor)) static void wieen_shim_init(void)
{
    pthread_t thread;
    if (pthread_create(&thread, 0, wieen_load_all, 0) == 0)
        pthread_detach(thread);
}
