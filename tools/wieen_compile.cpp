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

#include "Luau/Ast.h"
#include "Luau/Lexer.h"
#include "Luau/ParseOptions.h"
#include "Luau/ParseResult.h"
#include "Luau/Parser.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

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

/*
 * The loader of the client takes bytecode of less than 280 bytes, so a
 * script that does not fit is split into parts that do.  The parts are
 * run one after another in the same VM.
 */
static const size_t kPartLimit = 279;

/* defined below: a call of game:HttpGet becomes a call of the host */
static bool rewrite_httpget(std::string& text);

/*
 * The function a rewritten call needs.  It is put only into a chunk that
 * really downloads, so a chunk without HttpGet pays nothing for it.  The
 * guard keeps one copy for every chunk of a script and for a nested
 * loadstring.
 */
static const char kHttpPrelude[] =
    "_WH = function(u) return (coroutine.yield(\"\\1h:\" .. u))() end\n";

static bool compile_source(const std::string& source, lua_CompileOptions options,
                           bool keep_upstream, std::string& out, std::string& error)
{
    std::string text = source;
    if (rewrite_httpget(text))
        text = kHttpPrelude + text;
    size_t size = 0;
    lua_CompileOptions opts = options;
    char* bytecode = luau_compile(text.data(), text.size(), &opts, &size);
    if (!bytecode || !size)
    {
        error = "compilation failed";
        return false;
    }

    /*
     * The client numbers its opcodes differently, so the bytecode has to
     * be translated before it is handed to the client's VM.
     */
    if (!keep_upstream && !translate_opcodes(bytecode, size, error))
    {
        free(bytecode);
        return false;
    }

    out.assign(bytecode, size);
    free(bytecode);
    return true;
}

/* the byte offset of a place of the source */
static size_t offset_of(const std::string& source, const Luau::Position& position)
{
    if (position.line == UINT_MAX)
        return 0;
    /* the lines of the parser start at zero */
    size_t line = 0;
    size_t offset = 0;
    while (line < position.line && offset < source.size())
    {
        if (source[offset] == '\n')
            line++;
        offset++;
    }
    return offset + position.column;
}

/* the text of a place is replaced by spaces, so the positions stay */
static void blank(std::string& text, size_t begin, size_t end)
{
    if (begin >= end || end > text.size())
        return;
    for (size_t i = begin; i < end; i++)
        text[i] = ' ';
}

/*
 * The top level locals of a script become globals, so the parts of a
 * split script still share their state.
 */
static void make_globals(std::string& text, const Luau::ParseResult& result)
{
    for (Luau::AstStat* stat : result.root->body)
    {
        size_t begin = offset_of(text, stat->location.begin);
        size_t end = offset_of(text, stat->location.end);
        bool isLocal = false;

        if (Luau::AstStatLocal* local = stat->as<Luau::AstStatLocal>())
        {
            if (local->values.size == 0)
            {
                /* a local without a value has nothing to do */
                blank(text, begin, end);
                continue;
            }
            isLocal = true;
            for (Luau::AstLocal* var : local->vars)
                if (var->annotation)
                    blank(text, offset_of(text, var->annotation->location.begin),
                          offset_of(text, var->annotation->location.end));
        }
        else if (stat->as<Luau::AstStatLocalFunction>())
        {
            isLocal = true;
            Luau::AstStatLocalFunction* lf = stat->as<Luau::AstStatLocalFunction>();
            if (lf->name->annotation)
                blank(text, offset_of(text, lf->name->annotation->location.begin),
                      offset_of(text, lf->name->annotation->location.end));
        }

        if (getenv("WIEEN_DEBUG"))
            fprintf(stderr, "wieen-compile: local %d at %zu: [%s]\n", (int)isLocal, begin,
                    text.substr(begin, 8).c_str());
        if (isLocal && text.compare(begin, 5, "local") == 0)
            blank(text, begin, begin + 5);
    }
}

/*
 * The client has no HTTP client (game:HttpGet does not exist there), so a
 * script that downloads with it would stop at the first call.  The call is
 * rewritten into one of our own function: it asks the host for the text,
 * and the host is the only side that has a network.
 *
 * The usual shape loadstring(game:HttpGet(url)) is rewritten tighter: the
 * URL goes straight into loadstring, which already downloads and compiles
 * a link itself, so the text never travels through the client.
 */
struct HttpEdit
{
    size_t begin;
    size_t end;
    std::string text;
};

class HttpRewriter : public Luau::AstVisitor
{
public:
    explicit HttpRewriter(const std::string& text)
        : text(text)
    {
    }

    bool visit(Luau::AstExprCall* call) override
    {
        /* loadstring(game:HttpGet(url)) -> loadstring(url): the link of a
         * loadstring is downloaded and compiled by the host as it is */
        Luau::AstExprGlobal* name = call->func->as<Luau::AstExprGlobal>();
        if (name && name->name == "loadstring" && call->args.size == 1)
        {
            Span inner;
            if (httpget(call->args.data[0], inner))
            {
                edits.push_back({inner.begin, inner.end,
                                 text.substr(inner.argBegin,
                                             inner.argEnd - inner.argBegin)});
                return false;
            }
        }

        Span span;
        if (httpget(call, span))
        {
            edits.push_back({span.begin, span.end,
                             "_WH(" + text.substr(span.argBegin,
                                                  span.argEnd - span.argBegin) + ")"});
            return false;
        }
        return true;
    }

    /* the span of the whole game:HttpGet(...) call and the span of its URL */
    struct Span
    {
        size_t begin, end, argBegin, argEnd;
    };

    bool httpget(Luau::AstExpr* expr, Span& span)
    {
        Luau::AstExprCall* call = expr->as<Luau::AstExprCall>();
        if (!call)
            return false;
        Luau::AstExprIndexName* index = call->func->as<Luau::AstExprIndexName>();
        if (!index)
            return false;
        if (index->index != "HttpGet" && index->index != "HttpGetAsync")
            return false;
        Luau::AstExprGlobal* base = index->expr->as<Luau::AstExprGlobal>();
        if (!base || base->name != "game")
            return false;
        if (!call->args.size)
            return false;
        span.begin = offset_of(text, call->location.begin);
        span.end = offset_of(text, call->location.end);
        span.argBegin = offset_of(text, call->args.data[0]->location.begin);
        span.argEnd =
            offset_of(text, call->args.data[call->args.size - 1]->location.end);
        return true;
    }

    std::vector<HttpEdit> edits;

private:
    const std::string& text;
};

static bool rewrite_httpget(std::string& text)
{
    if (text.find("HttpGet") == std::string::npos)
        return false;

    Luau::Allocator allocator;
    Luau::AstNameTable names(allocator);
    Luau::ParseOptions parseOptions;
    Luau::ParseResult result =
        Luau::Parser::parse(text.data(), text.size(), names, allocator, parseOptions);
    if (!result.errors.empty() || !result.root)
        return false;

    HttpRewriter rewriter(text);
    result.root->visit(&rewriter);
    if (rewriter.edits.empty())
        return false;

    std::sort(rewriter.edits.begin(), rewriter.edits.end(),
              [](const HttpEdit& a, const HttpEdit& b) {
                  return a.begin > b.begin;
              });
    for (const HttpEdit& edit : rewriter.edits)
        text.replace(edit.begin, edit.end - edit.begin, edit.text);
    return true;
}

/*
 * A return of a chunk ends the whole chunk.  A chunk that came in parts
 * runs in the same call, so a return of an early part has to stop the
 * dispatcher before the parts that follow: every return that leaves the
 * chunk gets a call of __wieen_stop(...) instead.  Returns inside
 * functions are left alone - they leave the function, not the chunk.
 */
class ReturnCollector : public Luau::AstVisitor
{
public:
    explicit ReturnCollector(const std::string& text)
        : text(text)
    {
    }

    bool visit(Luau::AstStatReturn* stat) override
    {
        returns.push_back({offset_of(text, stat->location.begin),
                           offset_of(text, stat->location.end)});
        return false;
    }

    bool visit(Luau::AstExprFunction*) override
    {
        return false;
    }

    std::vector<std::pair<size_t, size_t>> returns;

private:
    const std::string& text;
};

static void stop_returns(std::string& text)
{
    Luau::Allocator allocator;
    Luau::AstNameTable names(allocator);
    Luau::ParseOptions parseOptions;
    Luau::ParseResult result =
        Luau::Parser::parse(text.data(), text.size(), names, allocator, parseOptions);
    if (!result.errors.empty() || !result.root)
        return;

    ReturnCollector collector(text);
    result.root->visit(&collector);

    /* from the end, so the offsets of the untouched text stay valid */
    std::sort(collector.returns.begin(), collector.returns.end(),
              [](const std::pair<size_t, size_t>& a,
                 const std::pair<size_t, size_t>& b) {
                  return a.first > b.first;
              });
    for (const std::pair<size_t, size_t>& place : collector.returns)
    {
        size_t begin = place.first;
        size_t end = place.second;
        if (begin >= end || end > text.size() ||
            text.compare(begin, 6, "return") != 0)
            continue;
        std::string values = text.substr(begin + 6, end - begin - 6);
        text.replace(begin, end - begin,
                     "__wieen_stop = true; return" + values);
    }
}

/*
 * A chunk of a loadstring runs on its own: the local loadstring of the
 * script that asked for it is not visible here, and the global one of the
 * client does not work.  Every chunk gets the stub of its own, so a
 * downloaded script may load another one the same way.
 */
static const char kLoadstringPrelude[] =
    "local loadstring = function(src) return coroutine.yield(src) end\n";

static bool compile_part(const std::string& piece, lua_CompileOptions options,
                         bool keep_upstream, bool stopReturn,
                         std::string& out, std::string& error)
{
    std::string text = stopReturn ? kLoadstringPrelude + piece : piece;
    if (stopReturn)
        stop_returns(text);
    return compile_source(text, options, keep_upstream, out, error);
}

/*
 * Splits the script into parts that the client is able to load.  The
 * parts are the top level statements, grouped so that every part fits
 * into the limit of the loader.
 */
static bool split_script(const std::string& source, lua_CompileOptions options,
                         bool keep_upstream, bool stopReturn,
                         std::vector<std::string>& parts,
                         std::string& error)
{
    Luau::Allocator allocator;
    Luau::AstNameTable names(allocator);
    Luau::ParseOptions parseOptions;
    Luau::ParseResult result =
        Luau::Parser::parse(source.data(), source.size(), names, allocator, parseOptions);
    if (!result.errors.empty())
    {
        error = result.errors[0].getMessage();
        return false;
    }

    std::string text = source;
    make_globals(text, result);

    if (getenv("WIEEN_DEBUG"))
    {
        for (Luau::AstStat* stat : result.root->body)
            fprintf(stderr, "wieen-compile: statement %u:%u..%u:%u\n",
                    stat->location.begin.line, stat->location.begin.column,
                    stat->location.end.line, stat->location.end.column);
    }

    size_t partBegin = 0;
    size_t partEnd = 0;
    bool haveStatement = false;

    for (Luau::AstStat* stat : result.root->body)
    {
        size_t end = offset_of(text, stat->location.end);

        std::string piece = text.substr(partBegin, end - partBegin);
        std::string bytes;
        if (!compile_part(piece, options, keep_upstream, stopReturn, bytes, error))
            return false;
        if (bytes.size() > kPartLimit)
        {
            /* without the information about the lines the part is smaller */
            lua_CompileOptions plain = options;
            plain.debugLevel = 0;
            std::string smaller;
            if (compile_part(piece, plain, keep_upstream, stopReturn, smaller, error) &&
                smaller.size() < bytes.size())
            {
                bytes = smaller;
                options = plain;
            }
        }

        if (bytes.size() > kPartLimit)
        {
            if (getenv("WIEEN_DEBUG"))
                fprintf(stderr, "wieen-compile: the part of %lu bytes is too big\n",
                        (unsigned long)bytes.size());
            if (haveStatement)
            {
                /* the part ends before this statement */
                std::string done;
                if (!compile_part(text.substr(partBegin, partEnd - partBegin),
                                 options, keep_upstream, stopReturn, done, error))
                    return false;
                parts.push_back(done);
                partBegin = partEnd;
                haveStatement = false;
                piece = text.substr(partBegin, end - partBegin);
                if (!compile_part(piece, options, keep_upstream, stopReturn, bytes, error))
                    return false;
                if (bytes.size() > kPartLimit)
                {
                    lua_CompileOptions plain = options;
                    plain.debugLevel = 0;
                    std::string smaller;
                    if (compile_part(piece, plain, keep_upstream, stopReturn, smaller, error) &&
                        smaller.size() < bytes.size())
                    {
                        bytes = smaller;
                        options = plain;
                    }
                }
            }
            if (bytes.size() > kPartLimit)
            {
                if (getenv("WIEEN_DEBUG"))
                    fprintf(stderr, "wieen-compile: the statement is too big:\n---8<---\n%s\n---8<---\n",
                            piece.c_str());
                error = "the statement is too big for the loader of the client";
                return false;
            }
        }

        haveStatement = true;
        partEnd = end;

        if (stat->is<Luau::AstStatReturn>())
            break;
    }

    if (haveStatement)
    {
        std::string done;
        if (!compile_part(text.substr(partBegin, partEnd - partBegin), options,
                         keep_upstream, stopReturn, done, error))
            return false;
        parts.push_back(done);
    }

    return true;
}

/*
 * The framing of a script that comes in parts: the magic, the number of
 * the parts, and then the length and the bytes of every part.
 */
static std::string frame_parts(const std::vector<std::string>& parts)
{
    std::string out = "WIEENMUL";
    unsigned long count = (unsigned long)parts.size();
    for (int i = 0; i < 4; i++)
        out += (char)((count >> (8 * i)) & 0xff);
    for (const std::string& part : parts)
    {
        unsigned long len = (unsigned long)part.size();
        for (int i = 0; i < 4; i++)
            out += (char)((len >> (8 * i)) & 0xff);
        out += part;
    }
    return out;
}

/*
 * A loadstring source that does not fit into one chunk is compiled into
 * parts plus a dispatcher.  The dispatcher takes the functions of the
 * parts and returns one function: calling it runs the parts in order.
 * The parts share their top level state through globals, and a return of
 * any part stops the dispatcher (see stop_returns above).
 */
static const char kLoadstringDispatcher[] =
    "local p = {...}\n"
    "return function(...)\n"
    " __wieen_stop = nil\n"
    " local r = {}\n"
    " for i = 1, #p do\n"
    "  r = {p[i](...)}\n"
    "  if __wieen_stop then break end\n"
    " end\n"
    " return table.unpack(r)\n"
    "end\n";

static std::string frame_loadstring(const std::string& dispatcher,
                                    const std::vector<std::string>& parts)
{
    std::string out = "WIEENLSP";
    unsigned long dlen = (unsigned long)dispatcher.size();
    for (int i = 0; i < 4; i++)
        out += (char)((dlen >> (8 * i)) & 0xff);
    out += dispatcher;
    unsigned long count = (unsigned long)parts.size();
    for (int i = 0; i < 4; i++)
        out += (char)((count >> (8 * i)) & 0xff);
    for (const std::string& part : parts)
    {
        unsigned long len = (unsigned long)part.size();
        for (int i = 0; i < 4; i++)
            out += (char)((len >> (8 * i)) & 0xff);
        out += part;
    }
    return out;
}


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
    bool raw = false;
    bool loadstring = false;
    for (int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "--raw") == 0)
            raw = true;
        if (strcmp(argv[i], "--loadstring") == 0)
            loadstring = true;
    }
    bool wrap = !raw && !loadstring;

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
    else if (loadstring)
    {
        wrapped = kLoadstringPrelude;
        wrapped += source;
    }
    else
    {
        wrapped = source;
    }

    lua_CompileOptions options;
    memset(&options, 0, sizeof(options));
    options.optimizationLevel = 1;
    options.debugLevel = 1;
    for (int i = 2; i < argc; i++)
        if (strcmp(argv[i], "--nodebug") == 0)
            options.debugLevel = 0;

    bool keep_upstream = false;
    for (int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "--upstream") == 0)
            keep_upstream = true;
    }

    std::string error;
    std::string bytes;
    if (!compile_source(wrapped, options, keep_upstream, bytes, error))
    {
        fprintf(stderr, "wieen-compile: %s\n", error.c_str());
        return 1;
    }

    if (bytes.size() <= kPartLimit)
    {
        fwrite(bytes.data(), 1, bytes.size(), stdout);
        return 0;
    }

    if (loadstring)
    {
        /*
         * A loadstring source is a function, not a script that runs now:
         * the parts are wrapped into a dispatcher that returns one
         * function over all of them.
         */
        std::vector<std::string> parts;
        if (!split_script(source, options, keep_upstream, true, parts, error))
        {
            fprintf(stderr, "wieen-compile: cannot split the loadstring: %s\n",
                    error.c_str());
            return 1;
        }

        std::string dispatcher;
        if (!compile_source(kLoadstringDispatcher, options, keep_upstream,
                            dispatcher, error))
        {
            fprintf(stderr, "wieen-compile: %s\n", error.c_str());
            return 1;
        }
        if (dispatcher.size() > kPartLimit)
        {
            lua_CompileOptions plain = options;
            plain.debugLevel = 0;
            std::string smaller;
            if (compile_source(kLoadstringDispatcher, plain, keep_upstream,
                               smaller, error))
                dispatcher = smaller;
        }
        if (dispatcher.size() > kPartLimit)
        {
            fprintf(stderr, "wieen-compile: the loadstring dispatcher is "
                            "too big for the loader of the client\n");
            return 1;
        }

        std::string framed = frame_loadstring(dispatcher, parts);
        fwrite(framed.data(), 1, framed.size(), stdout);
        return 0;
    }

    /*
     * The script does not fit into the bytecode the client is willing to
     * load, so it is split into parts that do.
     */
    std::vector<std::string> parts;
    if (!split_script(source, options, keep_upstream, false, parts, error))
    {
        fprintf(stderr, "wieen-compile: cannot split the script: %s\n", error.c_str());
        return 1;
    }

    std::string framed = frame_parts(parts);
    fwrite(framed.data(), 1, framed.size(), stdout);
    return 0;
}
