/*
 * wieen-compile - compile a Luau snippet into bytecode.
 *
 * The agent inside the client cannot compile: the Roblox client only
 * ships the Luau VM, not the compiler.  So the host compiles the snippet
 * and sends the bytecode over the socket, and the agent loads it with the
 * client's own luau_load.
 *
 *   wieen-compile <file>     compile a file
 *   wieen-compile -           compile stdin
 *
 * The bytecode goes to stdout, the diagnostics to stderr.
 */
#include "luacode.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

int main(int argc, char** argv)
{
    std::string source;

    if (argc > 1 && strcmp(argv[1], "-") != 0)
    {
        FILE* f = fopen(argv[1], "rb");
        if (!f)
        {
            fprintf(stderr, "wieen-compile: cannot open %s\n", argv[1]);
            return 1;
        }
        char buf[65536];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
            source.append(buf, n);
        fclose(f);
    }
    else
    {
        char buf[65536];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0)
            source.append(buf, n);
    }

    /*
     * The snippet runs inside the game, so it is wrapped into a function:
     * that way a top level "return" works and the result can be turned
     * into a string for us.
     */
    std::string wrapped = "local __wieen = function()\n";
    wrapped += source;
    wrapped += "\nend\nreturn tostring(__wieen())\n";

    size_t size = 0;
    char* bytecode = luau_compile(wrapped.data(), wrapped.size(), nullptr, &size);
    if (!bytecode || !size)
    {
        fprintf(stderr, "wieen-compile: compilation failed\n");
        return 1;
    }
    fwrite(bytecode, 1, size, stdout);
    free(bytecode);
    return 0;
}
