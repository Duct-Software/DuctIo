/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

#include "duct.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

static duct_view_cc s_of(const char *text)
{
    return (duct_view_cc){ text, strlen(text) };
}

static const char *sc_trim(void)
{
    expect(duct_str_is(duct_str_trim(s_of("  a b \t")), "a b"),
           "blanks at the ends were kept or the one inside was taken");
    expect(duct_str_is(duct_str_trim(s_of("x\r")), "x"), "a carriage return at the end was kept");
    expect(duct_str_is(duct_str_trim(s_of(" x \r")), "x"),
           "blanks before a carriage return at the end were kept");
    expect(duct_str_is(duct_str_trim(s_of("\rx")), "\rx"),
           "a carriage return at the start was taken");
    expect(!duct_str_trim(s_of("\r")).size, "a lone carriage return was kept");
    expect(!duct_str_trim(s_of(" \t ")).size, "a span of blanks was kept");
    expect(!duct_str_trim(s_of("")).size, "an empty span grew");
    expect(duct_str_blank(' ') && duct_str_blank('\t') && !duct_str_blank('\n') && !duct_str_blank('x'),
           "the blank set is not space and tab alone");
    return nullptr;
}

static const char *sc_is(void)
{
    static constexpr char text[] = "NET4=x";
    expect(duct_str_is(s_of("NET4"), "NET4"), "equal text did not match");
    expect(!duct_str_is(s_of("NET4"), "NET"), "a shorter literal matched");
    expect(!duct_str_is(s_of("NET"), "NET4"), "a longer literal matched");
    expect(!duct_str_is(s_of("NET5"), "NET4"), "a differing byte matched");
    expect(duct_str_is(s_of(""), ""), "an empty span did not equal an empty literal");
    expect(duct_str_is((duct_view_cc){ text, 4u }, "NET4"),
           "a span cut from longer text was compared past its length");
    return nullptr;
}

static const char *sc_copy(void)
{
    char out[8] = {};
    expect(duct_str_copy(s_of("1234567"), out, sizeof out) && strcmp(out, "1234567") == 0,
           "a span that fits was not copied with its terminator");
    out[0] = 0;
    expect(!duct_str_copy(s_of("12345678"), out, sizeof out) && !out[0],
           "a span of the capacity was taken or the output was touched");
    expect(duct_str_copy(s_of(""), out, sizeof out) && !out[0], "an empty span was not copied");
    return nullptr;
}

static const char *sc_line(void)
{
    auto rest = s_of("a\nb \r\n\n  c  ");
    expect(duct_str_is(duct_str_line(&rest), "a"), "the first line was not taken");
    expect(duct_str_is(duct_str_line(&rest), "b"), "a line ending in a CRLF was not trimmed");
    expect(!duct_str_line(&rest).size, "an empty line was not empty");
    expect(duct_str_is(duct_str_line(&rest), "c") && !rest.size,
           "a last line with no newline was not taken whole");
    rest = s_of("\n");
    expect(!duct_str_line(&rest).size && !rest.size, "a lone newline left text behind");
    rest = s_of("only");
    expect(duct_str_is(duct_str_line(&rest), "only") && !rest.size,
           "a single line with no newline was not taken whole");
    return nullptr;
}

static const char *sc_field(void)
{
    auto f = duct_str_field(s_of("  name :  value with: colon \r"));
    expect(duct_str_is(f.name, "name") && duct_str_is(f.value, "value with: colon"),
           "a line was not split at its first colon with both halves trimmed");
    f = duct_str_field(s_of(":x"));
    expect(f.name.data && !f.name.size && duct_str_is(f.value, "x"), "an empty name was lost");
    f = duct_str_field(s_of("k:"));
    expect(duct_str_is(f.name, "k") && f.value.data && !f.value.size, "an empty value was lost");
    f = duct_str_field(s_of("no colon"));
    expect(!f.name.data, "a line with no colon was split");
    f = duct_str_field((duct_view_cc){ "k:vXXXX", 3u });
    expect(duct_str_is(f.name, "k") && duct_str_is(f.value, "v"),
           "a span cut from longer text was read past its length");
    return nullptr;
}

static const char *sc_decimal(void)
{
    int64_t v = 0;
    expect(duct_str_decimal(s_of("0"), 3u, 255, &v) && v == 0
               && duct_str_decimal(s_of("7"), 3u, 255, &v) && v == 7
               && duct_str_decimal(s_of("255"), 3u, 255, &v) && v == 255
               && duct_str_decimal(s_of("007"), 3u, 255, &v) && v == 7,
           "digits within the limits were not read");
    expect(!duct_str_decimal(s_of("256"), 3u, 255, &v), "a number over the maximum was taken");
    expect(!duct_str_decimal(s_of("1000"), 3u, 9999, &v),
           "a number of more digits than allowed was taken");
    expect(duct_str_decimal(s_of("65535"), 5u, 65535, &v) && v == 65535,
           "the greatest number of the widest field was refused");
    expect(!duct_str_decimal(s_of(""), 3u, 255, &v) && !duct_str_decimal((duct_view_cc){}, 3u, 255, &v),
           "an empty span was taken");
    expect(!duct_str_decimal(s_of("-1"), 3u, 255, &v) && !duct_str_decimal(s_of("+1"), 3u, 255, &v)
               && !duct_str_decimal(s_of(" 1"), 3u, 255, &v) && !duct_str_decimal(s_of("1 "), 3u, 255, &v)
               && !duct_str_decimal(s_of("1a"), 3u, 255, &v) && !duct_str_decimal(s_of("0x1"), 3u, 255, &v),
           "a sign, a blank or a letter was taken for a digit");
    expect(duct_str_decimal((duct_view_cc){ "12XXXX", 2u }, 3u, 255, &v) && v == 12,
           "a span cut from longer text was read past its length");
    expect(duct_str_decimal(s_of("999999999999999999"), 18u, INT64_MAX, &v) && v == 999999999999999999,
           "the widest number was refused");
    return nullptr;
}

static const char *sc_scan(void)
{
    unsigned a = 0u, b = 0u;
    expect(duct_str_scan(s_of("12 34"), "%u %u", &a, &b) == 2 && a == 12u && b == 34u,
           "a plain two-number scan was not taken");
    expect(duct_str_scan(s_of("12 34x"), "%u %u", &a, &b) == -1,
           "a scan that stops short of the end was taken");
    expect(duct_str_scan(s_of("12 34 "), "%u %u", &a, &b) == -1,
           "a scan leaving a trailing blank was taken");
    a = 0u;
    expect(duct_str_scan(s_of("00123"), "%5u", &a) == 1 && a == 123u,
           "a number with a leading zero was not scanned");
    expect(duct_str_scan(s_of(""), "%u", &a) == -1, "an empty view was scanned");
    duct_view_cc cut = { "1x", 1u };
    expect(duct_str_scan(cut, "%u", &a) == 1 && a == 1u,
           "a view cut from longer text was read past its length");
    long long big = 0;
    expect(duct_str_scan(s_of("-42"), "%lld", &big) == 1 && big == -42,
           "a signed number was not scanned");
    char word[8] = {};
    expect(duct_str_scan(s_of("abcdefa"), "%7[abcdef]", word) == 1 && strcmp(word, "abcdefa") == 0,
           "a scanset was not scanned");
    expect(duct_str_scan(s_of("abcdefg"), "%7[abcdef]", word) == -1,
           "a scanset that stops short was taken");
    expect(duct_str_scan(s_of("0"), "%*[0-9]") == 0, "a suppressed scan that consumed all was refused");
    expect(duct_str_scan(s_of("0z"), "%*[0-9]") == -1, "a suppressed scan that stops short was taken");
    return nullptr;
}

static const char *sc_hex(void)
{
    uint8_t out[4] = {};
    expect(duct_hex_decode_into(s_of("00ff10Ab"), out, sizeof out) == rc_ok
               && out[0] == 0x00u && out[1] == 0xffu && out[2] == 0x10u && out[3] == 0xabu,
           "digits of either case were not decoded");
    expect(duct_hex_decode_into(s_of("00ff10"), out, sizeof out) == rc_invalid_arg,
           "a short run of digits was taken");
    expect(duct_hex_decode_into(s_of("00ff10ab00"), out, sizeof out) == rc_invalid_arg,
           "a long run of digits was taken");
    expect(out[0] == 0x00u && out[1] == 0xffu && out[2] == 0x10u && out[3] == 0xabu,
           "a refused run of digits touched the output");
    expect(duct_hex_decode_into(s_of("00ff10zz"), out, sizeof out) == rc_invalid_arg,
           "a non-digit was taken");
    expect(out[0] == 0x00u && out[1] == 0xffu && out[2] == 0x10u && out[3] == 0xabu,
           "a run with a non-digit touched the output");
    expect(duct_hex_decode_into(s_of(""), out, sizeof out) == rc_invalid_arg, "an empty run was taken");
    expect(duct_hex_decode_into((duct_view_cc){ "0102XXXX", 4u }, out, 2u) == rc_ok
               && out[0] == 1u && out[1] == 2u,
           "a span cut from longer text was read past its length");
    uint8_t key[32];
    char digits[65];
    memset(digits, 'a', sizeof digits - 1u);
    digits[sizeof digits - 1u] = '\0';
    expect(duct_hex_decode_into((duct_view_cc){ digits, 64u }, key, sizeof key) == rc_ok && key[31] == 0xaau,
           "a run of the most digits was refused");
    char text[65] = {};
    expect(strcmp(duct_hex_encode(key, sizeof key, text), digits) == 0,
           "the encoded text of the decoded bytes is not the digits they came from");
    uint8_t pair[2] = { 0xdeu, 0xadu };
    expect(strcmp(duct_hex_text(pair), "dead") == 0, "the text macro did not print the array");
    return nullptr;
}

static const char *sc_strerr(void)
{
    char buf[duct_err_text_max];
    expect(duct_strerr(0, buf, sizeof buf) == buf && buf[0] != '\0',
           "the text of error 0 is empty");
    expect(duct_strerr(1, buf, sizeof buf)[0] != '\0', "the text of error 1 is empty");
    expect(duct_strerr(1, buf, 0)[0] == '\0', "a zero capacity was not answered with an empty text");
    return nullptr;
}

static void s_wide(char *out, size_t host_len)
{
    memcpy(out, "[::", 3u);
    memset(out + 3u, 'a', host_len - 4u);
    memcpy(out + host_len - 1u, "]:80", 5u);
}

static const char *sc_endpoint(void)
{
    static const struct { const char *text; bool valid; const char *why; } texts[] = {
        { "192.0.2.1:4000",         true,  "an IPv4 address with a port was refused" },
        { "10.0.0.1:1",             true,  "the lowest port was refused" },
        { "255.255.255.255:65535",  true,  "the highest address and port were refused" },
        { "[2001:db8::1]:4000",     true,  "a bracketed IPv6 address was refused" },
        { "[::1]:443",              true,  "the shortest bracketed IPv6 address was refused" },
        { "[::ffff:192.0.2.1]:443", true,  "an IPv6 address ending in dotted decimals was refused" },
        { "[0000:0000:0000:0000:0000:ffff:255.255.255.255]:65535", true, "the longest IPv6 text was refused" },
        { "example.com:4000",       false, "a host name was taken" },
        { "localhost:80",           false, "localhost was taken" },
        { "192.0.2.1",              false, "an address with no port was taken" },
        { "192.0.2.1:",             false, "an empty port was taken" },
        { ":4000",                  false, "an empty host was taken" },
        { "",                       false, "an empty text was taken" },
        { "192.0.2.1:0",            false, "port 0 was taken" },
        { "192.0.2.1:65536",        false, "a port over 65535 was taken" },
        { "192.0.2.1:123456",       false, "a port of six digits was taken" },
        { "192.0.2.1:80a",          false, "a port with a letter was taken" },
        { "192.0.2:80",             false, "three groups were taken for an address" },
        { "192.0.2.1.5:80",         false, "five groups were taken for an address" },
        { "256.0.0.1:80",           false, "an octet over 255 was taken" },
        { "01.2.3.4:80",            false, "an octet with a leading zero was taken" },
        { "192.0.2.1:04000",        false, "a port with a leading zero was taken" },
        { " 192.0.2.1:4000",        false, "a blank before the address was taken" },
        { "+1.2.3.4:80",            false, "a sign before an octet was taken" },
        { "1.2.3.4:+80",            false, "a sign before the port was taken" },
        { "1..2.3:80",              false, "an empty group was taken" },
        { "1.2.3.4.:80",            false, "a dot at the end was taken" },
        { "1234.1.1.1:80",          false, "an octet of four digits was taken" },
        { "::1:80",                 false, "an IPv6 address with no brackets was taken" },
        { "[1:2]:3",                false, "a bracketed text with one colon was taken" },
        { "[::1]",                  false, "a bracketed address with no port was taken" },
        { "[::1:80",                false, "an unclosed bracket was taken" },
        { "[::g]:80",               false, "a letter past f between brackets was taken" },
        { "[]:80",                  false, "empty brackets were taken" },
    };
    for (size_t i = 0u; i < sizeof texts / sizeof texts[0]; ++i)
        expect(duct_str_endpoint_valid(texts[i].text) == texts[i].valid, texts[i].why);
    expect(strcmp(duct_str_endpoint_host("192.0.2.1:4000").text, "192.0.2.1") == 0
               && strcmp(duct_str_endpoint_host("[2001:db8::1]:4000").text, "2001:db8::1") == 0,
           "the host of an endpoint was not given as it is without its brackets");
    expect(!duct_str_endpoint_host("example.com:80").text[0] && !duct_str_endpoint_host("[1:2]:80").text[0],
           "the host of a text that is no endpoint was not empty");
    char wide[duct_str_endpoint_max + 8u];
    constexpr size_t host_cap = sizeof((duct_str_host_t){}.text) + 1u;
    s_wide(wide, host_cap);
    expect(duct_str_endpoint_valid(wide), "a bracketed host of the most bytes was refused");
    s_wide(wide, host_cap + 1u);
    expect(!duct_str_endpoint_valid(wide), "a bracketed host a byte past the most was taken");
    return nullptr;
}

int main(void)
{
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "trim",     sc_trim },
        { "is",       sc_is },
        { "copy",     sc_copy },
        { "line",     sc_line },
        { "field",    sc_field },
        { "decimal",  sc_decimal },
        { "scan",     sc_scan },
        { "hex",      sc_hex },
        { "strerr",   sc_strerr },
        { "endpoint", sc_endpoint },
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "str: %s: %s\n", cases[i].name, err);
            return 1;
        }
    }
    printf("str: OK\n");
    return 0;
}
