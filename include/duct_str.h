/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_str.h
 *  @brief The engine's text module: views over non-terminated text, the endpoint rule,
 *  the scan of a view, the error text and the hex text of bytes.
 *
 *  Every view-taking function takes a @c duct_view_cc and never requires a terminator
 *  behind the bytes: the readers of configuration files and of key files work on capped
 *  buffers, where a terminator means one. The endpoint half demands the canonical
 *  reprint of what it reads, so blanks, signs and leading zeros refuse an address; the
 *  dial parser shares the split core and keeps its lenient rule.
 *
 *  @c duct_str_scan reads a view through a bounded internal scratch and counts the whole
 *  view as consumed: a format that stops short refuses, which is the check the callers
 *  of a bare sscanf make with a hand-run @c %n. A view of the scratch's size or more
 *  refuses outright.
 *
 *  Includes @c duct_core.h for @c duct_view_cc and the log-side macros; the error text and
 *  the hex text are the string functions of those headers and live here since this file.
 */

#ifndef DUCT_STR_H
#define DUCT_STR_H

#include "duct_core.h"

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Compile-time scanf format check for a variadic function, as @c duct_printf_like for printf. */
#if defined(__MINGW32__) && defined(__MINGW_GNU_SCANF)
    #define duct_scanf_like(f, a) __MINGW_GNU_SCANF(f, a)
#elif defined(__GNUC__) || defined(__clang__)
    #define duct_scanf_like(f, a) __attribute__((format(scanf, f, a)))
#else
    #define duct_scanf_like(f, a)
#endif

/** @brief Test whether @p c is a blank, a space or a tab. */
static inline bool duct_str_blank(char c)
{
    return c == ' ' || c == '\t';
}

/** @brief Strip blanks from the start of @p s, and blanks and carriage returns from its end. */
static inline duct_view_cc duct_str_trim(duct_view_cc s)
{
    auto at = s.data;
    while (s.size && duct_str_blank(at[0])) {
        ++at;
        --s.size;
    }
    while (s.size && (duct_str_blank(at[s.size - 1u]) || at[s.size - 1u] == '\r'))
        --s.size;
    return (duct_view_cc){ .data = at, .size = s.size };
}

/** @brief Test whether @p s holds exactly the bytes of @p literal. */
duct_nonnull(2) static inline bool duct_str_is(duct_view_cc s, const char *literal)
{
    return s.size == strlen(literal) && memcmp(s.data, literal, s.size) == 0;
}

/** @brief Copy @p s into @p out of @p cap bytes with a terminator behind it.
 *  @return false, @p out untouched, for a span of @p cap bytes or more.
 */
duct_nonnull(2) static inline bool duct_str_copy(duct_view_cc s, char *out, size_t cap)
{
    if (s.size >= cap)
        return false;
    memcpy(out, s.data, s.size);
    out[s.size] = '\0';
    return true;
}

/** @brief Take the next line off the front of @p rest, trimmed.
 *  The line ends at the first newline and @p rest moves past it; the last line needs no
 *  newline, and an empty line gives an empty view. @p rest holds at least one byte on entry.
 */
duct_nonnull(1) static inline duct_view_cc duct_str_line(duct_view_cc *rest)
{
    auto at = rest->data;
    auto nl = (const char *)memchr(at, '\n', rest->size);
    size_t n = nl ? (size_t)(nl - at) : rest->size,
           used = nl ? n + 1u : n;
    duct_view_cc line = duct_str_trim((duct_view_cc){ at, n });
    *rest = (duct_view_cc){ at + used, rest->size - used };
    return line;
}

/** @brief Name and value of one @c name @c : @c value line. */
typedef struct {
    duct_view_cc name,  /**< Text before the colon, trimmed, with a null @c data when the line holds no colon. */
               value; /**< Text after the colon, trimmed, later colons included. */
} duct_str_field_t;

/** @brief Split @p line at its first colon into a trimmed name and a trimmed value.
 *  A line with no colon gives two empty views with a null @c data; a colon at the start
 *  or the end gives an empty name or value whose @c data is not null.
 */
static inline duct_str_field_t duct_str_field(duct_view_cc line)
{
    auto at = line.data;
    auto colon = (const char *)memchr(at, ':', line.size);
    if (!colon)
        return (duct_str_field_t){};
    size_t head = (size_t)(colon - at);
    return (duct_str_field_t){
        .name = duct_str_trim((duct_view_cc){ at, head }),
        .value = duct_str_trim((duct_view_cc){ colon + 1, line.size - head - 1u }),
    };
}

/** @brief Read @p s as a decimal number of 1 to @p digits digits, with no sign and no blank among them.
 *  @p digits is at most 18. Leading zeros count as digits.
 *  @return true with the number in @p out; false, @p out untouched, for an empty view, any
 *          other character, more digits than @p digits or a number over @p max.
 */
duct_nonnull(4) static inline bool duct_str_decimal(duct_view_cc s, size_t digits, int64_t max, int64_t *out)
{
    auto at = s.data;
    if (!at || !s.size || s.size > digits || digits > 18u)
        return false;
    int64_t value = 0;
    for (size_t i = 0u; i < s.size; ++i) {
        if (at[i] < '0' || at[i] > '9')
            return false;
        value = value * 10 + (at[i] - '0');
    }
    if (value > max)
        return false;
    *out = value;
    return true;
}

/** @brief Render the view @p s through the format @p fmt over a bounded internal scratch, in place of the copy a bare sscanf needs.
 *  The scratch holds 255 bytes, so a view of 255 bytes or more refuses. The format has to
 *  be a string literal without a @c %n: the reading macro pastes one and demands that the
 *  scan consumed every byte of the view, which is the whole-view check a bare sscanf
 *  leaves to a hand-run @c %n. A trailing blank is an unconsumed byte like any other.
 *  @return the assignments the format made over a fully consumed view; @c -1 when the scan
 *          stopped short, the view is too long or the view is empty and @p fmt starts with
 *          a converting directive.
 */
duct_nonnull(2) duct_scanf_like(2, 3) static inline int duct_str_scan_impl(duct_view_cc s, const char *fmt, ...)
{
    char scratch[256u];
    duct_do_if(s.size >= sizeof scratch, return -1);
    if (s.size)
        memcpy(scratch, s.data, s.size);
    scratch[s.size] = '\0';
    va_list ap;
    va_start(ap, fmt);
    int count = vsscanf(scratch, fmt, ap);
    va_end(ap);
    return count;
}

/** @brief Scan the view @p s by the literal format @p fmt, whole view or nothing.
 *  Expands to @c duct_str_scan_impl with a pasted @c %n and the consumption check beside
 *  it; @p fmt is a string literal and carries no @c %n of its own. A compound literal
 *  written as the view needs a variable of its own, the commas parting the macro's arguments.
 *  @return what @c duct_str_scan_impl answers.
 */
#define duct_str_scan(s, fmt, ...)                                                                    \
    ({                                                                                                \
        duct_view_cc _scan_view = (s);                                                                \
        int _scan_consumed = 0;                                                                       \
        int _scan_count = duct_str_scan_impl(_scan_view, fmt "%n", ##__VA_ARGS__, &_scan_consumed);   \
        _scan_consumed == (int)_scan_view.size ? _scan_count : -1;                                    \
    })

/** @brief The host and the port text of @p text, split by its bracket or its last colon.
 *  Bracketed, the host runs between the brackets and the port starts past @c ]:, which
 *  must both be there; plain, the last colon splits, and neither a hostname nor an IPv4
 *  literal ever carries one. The port runs to the end of the string.
 */
typedef struct {
    const char *host;     /**< First byte of the host, nullptr when the text does not split. */
    size_t      host_len; /**< Bytes of the host. */
    const char *port;     /**< First byte of the port text, to the end of the string. */
} duct_str_split_t;

duct_nonnull(1) static inline duct_str_split_t duct_str_split(const char *text)
{
    if (text[0] == '[') {
        auto close = strchr(text, ']');
        if (!close || close[1] != ':' || !close[2])
            return (duct_str_split_t){};
        return (duct_str_split_t){ text + 1, (size_t)(close - text) - 1u, close + 2 };
    }
    auto colon = strrchr(text, ':');
    if (!colon || colon == text || !colon[1])
        return (duct_str_split_t){};
    return (duct_str_split_t){ text, (size_t)(colon - text), colon + 1 };
}

/** @brief Bytes of a buffer that holds any endpoint text the endpoint readers accept, terminator included: the bracketed longest host, its colon and the port. */
static constexpr size_t duct_str_endpoint_max = 54u;

/** @brief Host of a server argument, as text. */
typedef struct {
    char text[46u]; /**< Address text without brackets: dotted decimals for IPv4, hex digits, colons and dots for IPv6; empty for an argument that is no IP address with a port. */
} duct_str_host_t;

static_assert(duct_str_endpoint_max == sizeof(duct_str_host_t) + 8u,
    "the endpoint bound is the bracketed host, its colon and the port");

/** @brief Read the host out of a server argument written as an IP address and a port.
 *  The argument is an IPv4 address and a port as @c a.b.c.d:port, or an IPv6 address in
 *  brackets and a port as @c [x:x::x]:port, the port 1 to 65535. The text has to equal what
 *  prints back from the numbers read, so a blank, a sign, a leading zero in a decimal
 *  number and trailing text refuse it. An IPv4 host is a whole address; an IPv6 host is
 *  checked for its shape alone, hex digits, colons and dots with two colons at least, and
 *  @c inet_pton judges it further.
 *  @return the host without its brackets, empty for an argument that does not read.
 */
duct_nonnull(1) static inline duct_str_host_t duct_str_endpoint_host(const char *text)
{
    duct_str_host_t host = {};
    auto split = duct_str_split(text);
    duct_do_if(!split.host, return host);
    duct_view_cc port_view = { split.port, strlen(split.port) };
    unsigned port = 0u;
    int scanned = duct_str_scan(port_view, "%5u", &port);
    duct_do_if(scanned != 1 || port < 1u || port > UINT16_MAX, return host);
    char printed[8u];
    if (snprintf(printed, sizeof printed, "%u", port) != (int)port_view.size
        || memcmp(printed, split.port, port_view.size) != 0)
        return host;
    if (text[0] == '[') {
        duct_do_if(split.host_len >= sizeof host.text, return host);
        unsigned colons = 0u;
        for (size_t i = 0u; i < split.host_len; ++i) {
            char c = split.host[i];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')
                  || c == ':' || c == '.'))
                return host;
            colons += c == ':';
        }
        duct_do_if(colons < 2u, return host);
        memcpy(host.text, split.host, split.host_len);
        return host;
    }
    unsigned o[4];
    duct_view_cc host_view = { split.host, split.host_len };
    if (duct_str_scan(host_view, "%3u.%3u.%3u.%3u", &o[0], &o[1], &o[2], &o[3]) != 4
        || o[0] > 255u || o[1] > 255u || o[2] > 255u || o[3] > 255u)
        return host;
    char canonical[16u];
    int n = snprintf(canonical, sizeof canonical, "%u.%u.%u.%u", o[0], o[1], o[2], o[3]);
    if (n != (int)split.host_len || memcmp(canonical, split.host, split.host_len) != 0)
        return host;
    memcpy(host.text, canonical, (size_t)n + 1u);
    return host;
}

/** @brief Test whether @p text reads as an IP address and a port to @c duct_str_endpoint_host. */
duct_nonnull(1) static inline bool duct_str_endpoint_valid(const char *text)
{
    return duct_str_endpoint_host(text).text[0] != '\0';
}

/** @brief Capacity of the buffer that holds the error text of a log line, bytes.
 *  Holds every Winsock and WFP text; a Windows text longer than this renders as @c error @c N.
 */
static constexpr size_t duct_err_text_max = 256u;

/** @brief Render error code @p err as text into @p buf, NUL-terminated.
 *  Thread-safe on every platform. @p err is an @c errno value, or on Windows a Win32, WSA,
 *  HRESULT or WFP code; a Windows code the system has no text for, or whose text is longer
 *  than @p cap, renders as @c error @c N.
 *  @return @p buf, or "" when @p cap is 0.
 */
duct_nonnull(2) static inline const char *duct_strerr(int err, char *buf, size_t cap)
{
    duct_do_if(cap == 0u, return "");
#ifdef _WIN32
    if (0 == FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM
                            | FORMAT_MESSAGE_IGNORE_INSERTS
                            | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                            nullptr, (DWORD)err,
                            MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                            buf, (DWORD)cap, nullptr))
        duct_discard snprintf(buf, cap, "error %d", err);
#else
    auto r = strerror_r(err, buf, cap);
    const char *s = _Generic(r, char *: r, default: r == 0 ? buf : nullptr);
    if (!s)
        duct_discard snprintf(buf, cap, "error %d", err);
    else if (s != buf)
        duct_discard snprintf(buf, cap, "%s", s);
#endif
    return buf;
}

/** @brief Pointer to the first element of the array @p a.
 *  Any other pointer stops the build: only an array carries its size in its type, which the hex
 *  macros below read.
 */
#define duct_array_start(a)                                                                 \
    ({                                                                                      \
        static_assert(!duct_is_types_compatible((a), &(a)[0]), "an array, its size in its type"); \
        &(a)[0];                                                                            \
    })

/** @brief Write the lowercase hex text of the @p size bytes at @p in into @p out, closed by a NUL.
 *  @p out holds 2 * @p size + 1 bytes.
 *  @return @p out.
 */
duct_nonnull(1, 3) static inline char *
duct_hex_encode(const uint8_t *in, size_t size, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0u; i < size; ++i) {
        out[i * 2u]      = digits[in[i] >> 4u];
        out[i * 2u + 1u] = digits[in[i] & 0x0fu];
    }
    out[size * 2u] = '\0';
    return out;
}

/** @brief Lowercase hex text of the array @p a, in storage of the calling block.
 *  The text is 2 * sizeof(a) digits and a NUL, and lasts to the end of the enclosing block. A
 *  pointer in place of an array stops the build.
 *  @code
 *  duct_log(stdout, "digest %s", duct_hex_text(list->digest));
 *  @endcode
 */
#define duct_hex_text(a) duct_hex_encode(duct_array_start(a), sizeof(a), (char[2u * sizeof(a) + 1u]){})

/** @brief Decode the hex digits in @p text into the @p size bytes at @p out.
 *  @p text holds exactly 2 * @p size digits of either case and needs no terminator. @p out is
 *  written only when every digit is good.
 *  @return @c rc_ok, or @c rc_invalid_arg for another count of digits or a character that is no
 *          digit.
 */
duct_nonnull(2) static inline duct_result_t
duct_hex_decode_into(duct_view_cc text, void *out, size_t size)
{
    auto digits = (const unsigned char *)text.data;
    if (text.size != size * 2u || (size && !digits))
        return rc_invalid_arg;
    for (size_t i = 0u; i < text.size; ++i)
        if ((unsigned)(digits[i] - '0') > 9u && (unsigned)((digits[i] | 0x20u) - 'a') > 5u)
            return rc_invalid_arg;
    auto bytes = (uint8_t *)out;
    for (size_t i = 0u; i < size; ++i) {
        unsigned value = 0u;
        for (unsigned half = 0u; half < 2u; ++half) {
            unsigned c = digits[i * 2u + half];
            value = (value << 4u) | (c <= '9' ? c - '0' : (c | 0x20u) - 'a' + 10u);
        }
        bytes[i] = (uint8_t)value;
    }
    return rc_ok;
}

/** @brief Decode the hex digits in the view @p text into the array @p out.
 *  The size is that of the array's type, and a pointer in its place stops the build; otherwise
 *  as @c duct_hex_decode_into. A view written as a compound literal with designators needs a
 *  variable of its own, the commas parting the macro's arguments.
 *  @return @c rc_ok, or @c rc_invalid_arg.
 */
#define duct_hex_decode(text, out) duct_hex_decode_into((text), duct_array_start(out), sizeof(out))

#ifdef __cplusplus
}
#endif

#endif
