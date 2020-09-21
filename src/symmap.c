/* Copyright (c) 2018-2020 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#include <stdint.h>
#include <string.h>             // memcpy, strcmp, strlen
#include <stdio.h>              // printf
#include <stdlib.h>             // malloc, free, qsort

#include "meta.h"
#include "symmap.h"
#include "util.h"

int compare_symclass(const void *a, const void *b)
{
    const symmap_class_t *cla = a,
                         *clb = b;
    return strcmp(cla->name, clb->name);
}

int compare_symclass_name(const void *a, const void *b)
{
    const char *key = a;
    const symmap_class_t *cls = b;
    return strcmp(key, cls->name);
}

int parse_symmap(char *mem, size_t len, size_t *num, symmap_class_t **entries)
{
    int retval = -1;
    ARRDEF(symmap_class_t, map, NUM_METACLASSES_EXPECT);

    // One loop iteration = one line of data.
    // At the end of an iteration, mem points to the newline at the end of the line.
    // Since we skip leading whitespace, this saves us the ++mem as third for() argument,
    // which in turn saves us a lot of headache with making sure we stay < end.
    bool zero_nl = false;
    size_t line = 1;
    struct
    {
        const char *class;
        ARRDECL(symmap_method_t, arr);
    } current;
    current.class = NULL;
    ARRINIT(current.arr, 0x100);
#define PUSHENT() \
do \
{ \
    symmap_class_t *ent; \
    ARRNEXT(map, ent); \
    symmap_method_t *methods = NULL; \
    if(current.arr.idx > 0) \
    { \
        size_t sz = current.arr.idx * sizeof(*methods); \
        methods = malloc(sz); \
        if(!methods) \
        { \
            ERRNO("malloc(symmap methods)"); \
            goto bad; \
        } \
        memcpy(methods, current.arr.val, sz); \
    } \
    ent->metaclass = NULL; \
    ent->name = current.class; \
    ent->num = current.arr.idx; \
    ent->methods = methods; \
    ent->duplicate = 0; \
} while(0)
    for(char *end = mem + len; mem < end;)
    {
        char ch;

        // Skip leading whitespace and empty lines
        while(mem < end)
        {
            ch = *mem;
            if(ch == '\n')
            {
                if(zero_nl)
                {
                    *mem = '\0';
                    zero_nl = false;
                }
                ++line;
            }
            else if(!isws(ch))
            {
                break;
            }
            ++mem;
        }
        if(mem >= end) break;
        DBG("Symmap line %lu", line);

        ch = *mem;

        // Comment, jump to end of line
        if(ch == '#')
        {
            do
            {
                ++mem;
            } while(mem < end && *mem != '\n');
        }
        // This is a method
        else if(ch == '-')
        {
            DBG("Got symmap method");

            // Must have seen a class name before
            if(!current.class)
            {
                ERR("Symbol map, line %lu: method declaration before first class declaration", line);
                goto bad;
            }
            ++mem; // Skip dash
            // Skip leading whitespace
            while(mem < end && isws(*mem))
            {
                ++mem;
            }
            // Empty lines are permitted as "no name assigned"
            ch = *mem;
            if(mem >= end || ch == '\n' || ch == '#')
            {
                if(ch == '#')
                {
                    do
                    {
                        ++mem;
                    } while(mem < end && *mem != '\n');
                }
                symmap_method_t *ent;
                ARRNEXT(current.arr, ent);
                ent->class = NULL;
                ent->method = NULL;
                ent->structor = 0;
                ent->reserved = 0;
                if(mem >= end) break;
                goto next;
            }

            bool structor = false;
            const char *classname = NULL,
                       *methname  = NULL,
                       *namestart = mem;
            // Seek end of identifier
            while(mem < end && isan(*mem))
            {
                ++mem;
            }
            if(mem >= end)
            {
                ERR("Symbol map, line %lu: incomplete method declaration", line);
                goto bad;
            }
            // If we are at "::", this is a class name
            if(mem < end - 1 && mem[0] == ':' && mem[1] == ':')
            {
                *mem = '\0'; // terminate class name
                mem += 2;
                classname = namestart;
                namestart = mem;
            }
            if(mem < end && *mem == '~')
            {
                ++mem;
            }
            while(mem < end && isan(*mem))
            {
                ++mem;
            }
            if(mem >= end)
            {
                ERR("Symbol map, line %lu: incomplete method declaration (identifier)", line);
                goto bad;
            }
            ch = *mem;
            if(ch != '(')
            {
                ERR("Symbol map, line %lu: expected '(', got '%c' (0x%hhu)", line, ch, (unsigned char)ch);
                goto bad;
            }
            while(mem < end && *mem != '\n' && *mem != '#')
            {
                ++mem;
            }
            char *pos = mem;
            while(isws(pos[-1]))
            {
                --pos;
            }
            if(*pos == '\n')
            {
                zero_nl = true; // Defer termination to next loop iteration
            }
            else
            {
                *pos = '\0';
            }
            while(mem < end && *mem != '\n')
            {
                ++mem;
            }
            methname = namestart;
            if(!classname)
            {
                classname = current.class;
                // Do this here so structors can be suppressed by prefixing with "ClassName::".
                size_t sz = strlen(classname);
                const char *tmp = methname;
                if(tmp[0] == '~')
                {
                    ++tmp;
                }
                if(strncmp(classname, tmp, sz) == 0 && tmp[sz] == '(')
                {
                    structor = true;
                }
            }
            symmap_method_t *ent;
            ARRNEXT(current.arr, ent);
            ent->class = classname;
            ent->method = methname;
            ent->structor = !!structor;
            ent->reserved = 0;
        }
        // This is a class name
        else
        {
            DBG("Got symmap class");

            const char *classname = mem;
            while(mem < end && isan(*mem))
            {
                ++mem;
            }
            char *pos = mem;
            while(isws(*mem))
            {
                ++mem;
            }
            if(*mem == '#')
            {
                while(mem < end && *mem != '\n')
                {
                    ++mem;
                }
            }
            if(mem < end && (ch = *mem) != '\n')
            {
                ERR("Symbol map, line %lu: expected newline, got '%c' (0x%hhu)", line, ch, (unsigned char)ch);
                goto bad;
            }
            if(mem == pos)
            {
                zero_nl = true; // Defer termination to next loop iteration
            }
            else
            {
                *pos = '\0';
            }
            if(current.class)
            {
                PUSHENT();
            }
            current.class = classname;
            current.arr.idx = 0; // don't realloc or anything
        }

    next:;
        if(mem < end && *mem != '\n')
        {
            ERR("Symbol map, line %lu: error in parse_symmap implementation, loop does not end on newline", line);
            goto bad;
        }
    }
    // Can ignore zero_nl here, since mmap() guarantees zeroed mem afterwards, and we mapped len + 1.
    if(current.class)
    {
        PUSHENT();
        current.class = NULL;
    }
    size_t sz = map.idx * sizeof(*map.val);
    symmap_class_t *ptr = malloc(sz);
    if(!ptr)
    {
        ERRNO("malloc(symmap final)");
        goto bad;
    }
    memcpy(ptr, map.val, sz);
    qsort(ptr, map.idx, sizeof(*map.val), &compare_symclass);

    // Mark duplicates and warn if methods don't match
    for(size_t i = 1; i < map.idx; ++i)
    {
        symmap_class_t *prev = &ptr[i-1],
                       *cur  = &ptr[i];
        if(strcmp(prev->name, cur->name) == 0)
        {
            DBG("Duplicate symmap class: %s", cur->name);
            cur->duplicate = 1;
            if(prev->num != cur->num)
            {
                WRN("Duplicate symmap classes %s have different number of methods (%lu vs %lu)", cur->name, prev->num, cur->num);
            }
            else
            {
                for(size_t j = 0; j < cur->num; ++j)
                {
                    symmap_method_t *one = &prev->methods[j],
                                    *two = &cur ->methods[j];
                    if(!one->method && !two->method) // note the AND
                    {
                        continue;
                    }
                    if(!one->method || !two->method || strcmp(one->class, two->class) != 0 || strcmp(one->method, two->method) != 0)
                    {
                        WRN("Mismatching method names of duplicate symmap class %s: %s::%s vs %s::%s", cur->name, one->class, one->method, two->class, two->method);
                    }
                }
            }
        }
    }

    *entries = ptr;
    *num = map.idx;

    retval = 0;
    goto out;

bad:;
    for(size_t i = 0; i < map.idx; ++i)
    {
        free(map.val[i].methods);
        map.val[i].methods = NULL;
    }
out:;
    ARRFREE(current.arr);
    ARRFREE(map);
    return retval;
#undef PUSHENT
}

void print_syment(const char *owner, const char *class, const char *method)
{
    if(!method)
    {
        // Quick exit - preserve empty placeholder
        printf("-\n");
        return;
    }
    printf("- ");
    if(strcmp(class, owner) != 0)
    {
        printf("%s::", class);
    }
    printf("%s\n", method);
}

void print_symmap(metaclass_t *meta)
{
    printf("%s\n", meta->name);
    metaclass_t *parent = meta->parentP;
    while(parent && !parent->vtab)
    {
        parent = parent->parentP;
    }
    for(size_t i = parent ? parent->nmethods : 0; i < meta->nmethods; ++i)
    {
        vtab_entry_t *ent = &meta->methods[i];
        print_syment(meta->name, ent->class, ent->authoritative ? ent->method : NULL);
    }
}
