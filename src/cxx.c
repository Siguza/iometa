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
#include <string.h>             // strncmp, memcpy

#include "cxx.h"

static int demangle_num(const char **ptr)
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
    int slen = demangle_num(&p);
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
    int clslen = demangle_num(&sym);
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
            int mthdlen = demangle_num(&sym);
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
