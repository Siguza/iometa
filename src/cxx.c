/* Copyright (c) 2018-2020 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#include <stdbool.h>
#include <stdio.h>              // asprintf
#include <stdlib.h>             // malloc, free
#include <string.h>             // strncmp, strndup, memcpy

#include "cxx.h"
#include "util.h"

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define SIPROUND            \
do {                        \
    v0 += v1;               \
    v1 = ROTL(v1, 13) ^ v0; \
    v0 = ROTL(v0, 32);      \
    v2 += v3;               \
    v3 = ROTL(v3, 16) ^ v2; \
    v0 += v3;               \
    v3 = ROTL(v3, 21) ^ v0; \
    v2 += v1;               \
    v1 = ROTL(v1, 17) ^ v2; \
    v2 = ROTL(v2, 32);      \
} while(0)

static uint64_t siphash(const uint8_t *in, uint64_t inlen)
{
    uint64_t v0 = 0x0a257d1c9bbab1c0ULL;
    uint64_t v1 = 0xb0eef52375ef8302ULL;
    uint64_t v2 = 0x1533771c85aca6d4ULL;
    uint64_t v3 = 0xa0e4e32062ff891cULL;
    for(const uint8_t *end = in + (inlen & ~7ULL); in != end; in += 8)
    {
        uint64_t m = ((uint64_t)in[7] << 56)
                   | ((uint64_t)in[6] << 48)
                   | ((uint64_t)in[5] << 40)
                   | ((uint64_t)in[4] << 32)
                   | ((uint64_t)in[3] << 24)
                   | ((uint64_t)in[2] << 16)
                   | ((uint64_t)in[1] <<  8)
                   | ((uint64_t)in[0]);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
    }
    uint64_t b = inlen << 56;
    switch(inlen & 7)
    {
        case 7: b |= (uint64_t)in[6] << 48;
        case 6: b |= (uint64_t)in[5] << 40;
        case 5: b |= (uint64_t)in[4] << 32;
        case 4: b |= (uint64_t)in[3] << 24;
        case 3: b |= (uint64_t)in[2] << 16;
        case 2: b |= (uint64_t)in[1] <<  8;
        case 1: b |= (uint64_t)in[0];
        case 0: break;
    }
    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

bool cxx_compute_pac(const char *sym, uint16_t *pac)
{
    if(sym[0] != '_')
    {
        return false;
    }
    size_t len = 0;
    for(const char *s = sym + 1; *s != '\0' && *s != '.'; ++s)
    {
        ++len;
    }
    *pac = (siphash((const uint8_t*)(sym + 1), len) % 0xffff) + 1;
    return true;
}

static int cxx_demangle_num(const char **ptr)
{
    const char *sym = *ptr;
    if(!(*sym >= '0' && *sym <= '9'))
    {
        return -1;
    }
    int ret = 0;
    while(*sym >= '0' && *sym <= '9')
    {
        ret = (ret * 10) + (*sym - '0');
        ++sym;
    }
    *ptr = sym;
    return ret;
}

#if 1

extern char* __cxa_demangle(const char *sym, char *buf, size_t *len, int *status);

bool cxx_demangle(const char *sym, const char **classptr, const char **methodptr, bool *structorptr)
{
    bool retval = false;
    char *str  = NULL,
         *copy = NULL;
    if(sym[0] != '_') goto out;

    const char *dot = strchr(sym, '.');
    if(dot)
    {
        copy = strndup(sym, dot - sym);
        if(!copy) goto out;
        sym = copy;
    }

    int r = 0;
    str = __cxa_demangle(sym + 1, NULL, NULL, &r);
    if(!str || r != 0) goto out;

    int len = 0;
    for(int i = 0; str[i] != '\0' && str[i] != '('; ++i)
    {
        if(str[i] == ':' && str[i+1] == ':')
        {
            len = i;
            break;
        }
    }
    if(!len) goto out;

    str[len] = '\0';
    str[len+1] = '\0';
    const char *p = sym + 4;
    int slen = cxx_demangle_num(&p);
    *structorptr = slen == len && strncmp(p, str, len) == 0 && (p[len] == 'C' || p[len] == 'D');
    *methodptr = str + len + 2;
    *classptr = str;
    str = NULL; // prevent free
    retval = true;
out:;
    if(str)  free(str);
    if(copy) free(copy);
    return retval;
}

#else

// Ghetto homebrew parsing

bool cxx_demangle(const char *sym, const char **classptr, const char **methodptr, bool *structorptr)
{
    if(strncmp(sym, "__ZN", 4) != 0)
    {
        return false;
    }
    sym += 4;
    bool cnst = false;
    if(*sym == 'K')
    {
        cnst = true;
        ++sym;
    }
    int clslen = cxx_demangle_num(&sym);
    if(clslen == -1)
    {
        return false;
    }
    char *cls = malloc(clslen + 1);
    if(!cls)
    {
        return false;
    }
    memcpy(cls, sym, clslen);
    cls[clslen] = '\0';
    sym += clslen;
    char *mthd = NULL;
    bool structor = false;
    switch(*sym)
    {
        case 'C':
        {
            asprintf(&mthd, "%s()%s", cls, cnst ? " const" : "");
            structor = true;
            break;
        }
        case 'D':
        {
            asprintf(&mthd, "~%s()%s", cls, cnst ? " const" : "");
            structor = true;
            break;
        }
        default:
        {
            int mthdlen = cxx_demangle_num(&sym);
            if(mthdlen == -1)
            {
                return false;
            }
            asprintf(&mthd, "%.*s()%s", mthdlen, sym, cnst ? " const" : "");
            // TODO: arguments
            break;
        }
    }
    if(!mthd)
    {
        free(cls);
        return false;
    }

    *classptr = cls;
    *methodptr = mthd;
    *structorptr = structor;
    return true;
}

#endif

#ifdef CXXPAC_DEBUG
int main(int argc, const char **argv)
{
    if(argc != 2)
    {
        fprintf(stderr, "Usage: %s symbol\n", argv[0]);
        return -1;
    }
    uint16_t pac = 0;
    if(!cxx_compute_pac(argv[1], &pac))
    {
        fprintf(stderr, "Symbol must start with underscore\n");
        return -1;
    }
    printf("PAC: 0x%04hx\n", pac);
    return 0;
}
#endif
