/* Copyright (c) 2018-2024 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#ifndef UTIL_H
#define UTIL_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>             // size_t
#include <stdint.h>
#include <stdio.h>              // fprintf, stderr
#include <stdlib.h>             // malloc, realloc, free
#include <string.h>             // strerror

extern uint8_t debug;
extern const char *colorGray,
                  *colorRed,
                  *colorYellow,
                  *colorBlue,
                  *colorPink,
                  *colorCyan,
                  *colorReset;

#define LOG(str, args...)   do { fprintf(stderr, str "\n", ##args); } while(0)
#define DBG(lvl, str, args...)   do { if(debug >= lvl) LOG("%s[DBG] " str "%s", colorPink, ##args, colorReset); } while(0)
#define WRN(str, args...)   LOG("%s[WRN] " str "%s", colorYellow, ##args, colorReset)
#define ERR(str, args...)   LOG("%s[ERR] " str "%s", colorRed, ##args, colorReset)
#define ERRNO(str, args...) ERR(str ": %s", ##args, strerror(errno))

#define STRINGIFX(x) #x
#define STRINGIFY(x) STRINGIFX(x)

#define SWAP32(x) (((x & 0xff000000) >> 24) | ((x & 0xff0000) >> 8) | ((x & 0xff00) << 8) | ((x & 0xff) << 24))

#define STEP_MEM(_type, _var, _base, _size, _min) \
for(const _type *_var = (const _type*)(_base), *_end = (const _type*)((uintptr_t)(_var) + (_size)) - (_min); _var <= _end; ++_var)

#define ARRDECL(type, name) \
struct \
{ \
    size_t size; \
    size_t idx; \
    type *val; \
} name

#define ARRDEF(type, name, sz) \
ARRDECL(type, name); \
ARRINIT(name, sz)

#define ARRDEFEMPTY(type, name) \
ARRDECL(type, name); \
do \
{ \
    (name).size = 0; \
    (name).idx = 0; \
    (name).val = NULL; \
} while(0)

#define ARRINIT(name, sz) \
do \
{ \
    (name).size = (sz); \
    (name).idx = 0; \
    (name).val = malloc((name).size * sizeof(*(name).val)); \
    if(!(name).val) \
    { \
        ERRNO("malloc"); \
        exit(-1); \
    } \
} while(0)

#define ARRCAST(type, name, from) \
struct \
{ \
    size_t size; \
    size_t idx; \
    type *val; \
} *name = (void*)(from)

#define ARREXPAND(name) \
do \
{ \
    if((name).size <= (name).idx) \
    { \
        (name).size *= 2; \
        (name).val = realloc((name).val, (name).size * sizeof(*(name).val)); \
        if(!(name).val) \
        { \
            ERRNO("realloc(0x%zx)", (name).size); \
            exit(-1); \
        } \
    } \
} while(0)

#define ARRNEXT(name, ptr) \
do \
{ \
    ARREXPAND((name)); \
    (ptr) = &(name).val[(name).idx++]; \
} while(0)

#define ARRPUSH(name, ...) \
do \
{ \
    ARREXPAND((name)); \
    (name).val[(name).idx++] = (__VA_ARGS__); \
} while(0)

#define ARRFREE(name) \
do \
{ \
    if((name).val) \
    { \
        free((name).val); \
    } \
    (name).size = 0; \
    (name).idx = 0; \
    (name).val = NULL; \
} while(0)

typedef struct
{
    uint32_t bundle    :  1,
             bfilt     :  1,
             cfilt     :  1,
             bsort     :  1,
             csort     :  1,
             extend    :  1,
             inherit   :  1,
             meta      :  1,
             metaclass :  1,
             maxmap    :  1,
             overrides :  1,
             ofilt     :  1,
             parent    :  1,
             size      :  1,
             symmap    :  1,
             vtab      :  1,
             mangle    :  1,
             _reserved : 15;
} opt_t;

static inline bool isws(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r'; // disregard newline by design
}

static inline bool isal(char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_';
}

static inline bool isdg(char ch)
{
    return ch >= '0' && ch <= '9';
}

static inline bool isan(char ch)
{
    return isal(ch) || isdg(ch);
}

int map_file(const char *file, int prot, void **addrp, size_t *lenp);

#endif
