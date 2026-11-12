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
 *
 * The client does not use the upstream opcode numbering: its bytecode
 * format numbers the opcodes differently, and while it loads a function
 * it rewrites them into the scattered numbers of its own dispatch table.
 * The bytecode is therefore translated after compilation - see
 * translate_opcodes() below.
 */
#include "luacode.h"
#include "opcode_map.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

/*
 * A cursor over the bytecode blob.  The format is the one the client
 * itself reads; only the parts that are needed to find the instruction
 * arrays are decoded here.
 */
struct Blob
{
    uint8_t* data;
    size_t size;
    size_t off = 0;

    bool eof(size_t n) const
    {
        return off + n > size;
    }

    bool u8(uint8_t& out)
    {
        if (eof(1))
            return false;

        out = data[off++];
        return true;
    }

    bool varint(uint32_t& out)
    {
        uint32_t result = 0;
        uint32_t shift = 0;

        for (int i = 0; i < 5; i++)
        {
            if (eof(1))
                return false;

            uint8_t byte = data[off++];
            result |= uint32_t(byte & 0x7f) << shift;
            shift += 7;

            if (!(byte & 0x80))
            {
                out = result;
                return true;
            }
        }

        return false;
    }

    bool u32(uint32_t& out)
    {
        if (eof(4))
            return false;

        out = uint32_t(data[off]) | (uint32_t(data[off + 1]) << 8) | (uint32_t(data[off + 2]) << 16) |
              (uint32_t(data[off + 3]) << 24);
        off += 4;
        return true;
    }

    bool put32(uint32_t value)
    {
        if (eof(4))
            return false;

        data[off++] = uint8_t(value);
        data[off++] = uint8_t(value >> 8);
        data[off++] = uint8_t(value >> 16);
        data[off++] = uint8_t(value >> 24);
        return true;
    }

    bool skip(size_t n)
    {
        if (eof(n))
            return false;

        off += n;
        return true;
    }
};

bool fail(std::string& error, const char* what)
{
    error = what;
    return false;
}

/*
 * Rewrite the opcode of every instruction into the client's numbering.
 *
 * An instruction is one or two words: the ones with an AUX word carry a
 * second word that is *not* an instruction and must not be touched, so
 * the walk follows the length of each opcode.
 */
bool translate_opcodes(char* bytecode, size_t size, std::string& error)
{
    Blob blob{reinterpret_cast<uint8_t*>(bytecode), size};

    uint8_t version = 0;
    if (!blob.u8(version))
        return fail(error, "truncated bytecode");

    if (version < 12)
        return fail(error, "bytecode version too old to be translated");

    uint8_t typesversion = 0;
    if (!blob.u8(typesversion))
        return fail(error, "truncated bytecode");

    // the string table
    uint32_t stringCount = 0;
    if (!blob.varint(stringCount))
        return fail(error, "truncated bytecode");

    for (uint32_t i = 0; i < stringCount; i++)
    {
        uint32_t length = 0;
        if (!blob.varint(length) || !blob.skip(length))
            return fail(error, "truncated string table");
    }

    // the userdata type table, only present in the newer type versions
    if (typesversion == 3)
    {
        uint8_t index = 0;
        if (!blob.u8(index))
            return fail(error, "truncated bytecode");

        while (index != 0)
        {
            uint32_t id = 0;
            if (!blob.varint(id) || !blob.u8(index))
                return fail(error, "truncated userdata table");
        }
    }

    // the functions
    uint32_t protoCount = 0;
    if (!blob.varint(protoCount))
        return fail(error, "truncated bytecode");

    for (uint32_t i = 0; i < protoCount; i++)
    {
        uint32_t protoSize = 0;
        if (!blob.varint(protoSize))
            return fail(error, "truncated bytecode");

        size_t protoStart = blob.off;

        // maxstacksize, numparams, nups, is_vararg, flags
        if (!blob.skip(5))
            return fail(error, "truncated function");

        uint32_t typesize = 0;
        if (!blob.varint(typesize) || !blob.skip(typesize))
            return fail(error, "truncated function");

        uint32_t sizecode = 0;
        if (!blob.varint(sizecode))
            return fail(error, "truncated function");

        for (uint32_t j = 0; j < sizecode;)
        {
            uint32_t word = 0;
            if (!blob.u32(word))
                return fail(error, "truncated instructions");

            uint8_t op = uint8_t(word & 0xff);
            if (op >= WIEEN_OPCODE_COUNT)
                return fail(error, "unknown opcode in the bytecode");

            blob.off -= 4;
            if (!blob.put32((word & ~uint32_t(0xff)) | kWireOpcode[op]))
                return fail(error, "truncated instructions");

            /*
             * The opcodes with an AUX word are followed by a second word
             * that belongs to the instruction and holds no opcode, so it
             * is stepped over without being touched.
             */
            if (kOpWords[op] == 2)
            {
                if (!blob.skip(4))
                    return fail(error, "truncated instructions");
            }

            j += kOpWords[op];
        }

        // the rest of the function is not needed, the client reads it
        blob.off = protoStart + protoSize;
        if (blob.off > blob.size)
            return fail(error, "function size out of range");
    }

    // the main function
    uint32_t mainid = 0;
    if (!blob.varint(mainid))
        return fail(error, "truncated bytecode");

    if (blob.off != blob.size)
        return fail(error, "unexpected data at the end of the bytecode");

    return true;
}

}  // namespace

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
    bool wrap = !(argc > 2 && strcmp(argv[2], "--raw") == 0);
    std::string wrapped;
    if (wrap)
    {
        wrapped = "local __wieen = function()\n";
        wrapped += source;
        /*
         * The extra parentheses make the call give exactly one value, so
         * a script that returns nothing is a nil instead of an error.
         */
        wrapped += "\nend\nreturn tostring((__wieen()))\n";
    }
    else
    {
        wrapped = source;
    }

    size_t size = 0;
    char* bytecode = luau_compile(wrapped.data(), wrapped.size(), nullptr, &size);
    if (!bytecode || !size)
    {
        fprintf(stderr, "wieen-compile: compilation failed\n");
        return 1;
    }

    /*
     * The client numbers its opcodes differently, so the bytecode has to
     * be translated before it is handed to the client's VM.
     */
    bool keep_upstream = false;
    for (int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "--upstream") == 0)
            keep_upstream = true;
    }

    std::string error;
    if (!keep_upstream && !translate_opcodes(bytecode, size, error))
    {
        fprintf(stderr, "wieen-compile: cannot translate the opcodes: %s\n", error.c_str());
        free(bytecode);
        return 1;
    }

    fwrite(bytecode, 1, size, stdout);
    free(bytecode);
    return 0;
}
