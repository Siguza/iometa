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
#include <stddef.h>
#include <stdio.h>              // printf
#include <stdlib.h>             // qsort, malloc, free
#include <string.h>             // strlen, strcmp, strncmp

#include "meta.h"
#include "print.h"
#include "util.h"

// ---------- ---------- ---------- ---------- iometa ---------- ---------- ---------- ----------

static bool iometa_print_init(metaclass_t **list, size_t lsize, opt_t opt, void **argp)
{
    size_t namelen = 0;
    if(opt.bundle && !opt.overrides)
    {
        // Calculate name length because spaced out looks weird without methods in between
        for(size_t i = 0; i < lsize; ++i)
        {
            size_t nl = strlen(list[i]->name);
            if(opt.metaclass)
            {
                nl += 11; // "::MetaClass"
            }
            if(nl > namelen)
            {
                namelen = nl;
            }
        }
    }
    *argp = (void*)(uintptr_t)namelen;
    return true;
}

static bool iometa_print_class(metaclass_t *meta, opt_t opt, metaclass_t *OSMetaClass, print_sym_t print_sym, void *arg)
{
    int namelen = (int)(uintptr_t)arg;
    if(opt.vtab)
    {
        if(meta->vtab == -1)
        {
            printf("%svtab=??????????????????%s ", colorRed, colorReset);
        }
        else
        {
            printf("vtab=" ADDR " ", meta->vtab);
        }
    }
    if(opt.size)
    {
        printf("size=0x%08x ", meta->objsize);
    }
    if(opt.meta)
    {
        printf("meta=" ADDR " parent=" ADDR " ", meta->addr, meta->parent);
        if(opt.vtab)
        {
            printf("metavtab=" ADDR " ", meta->metavtab);
        }
    }
    printf("%s%-*s%s", colorCyan, namelen, meta->name, colorReset);
    if(opt.bundle)
    {
        if(meta->bundle)
        {
            printf(" (%s%s%s)", colorBlue, meta->bundle, colorReset);
        }
        else
        {
            printf(" (%s???%s)", colorRed, colorReset);
        }
    }
    printf("\n");
    if(opt.overrides)
    {
        metaclass_t *parent = meta->parentP;
        while(parent && !parent->vtab)
        {
            parent = parent->parentP;
        }
        for(size_t i = 0; i < meta->nmethods; ++i)
        {
            vtab_entry_t *ent = &meta->methods[i];
            if(!ent->overrides && !opt.inherit)
            {
                continue;
            }
            const char *color = ent->addr == -1 ? colorRed : !ent->overrides ? colorGray : "";
            vtab_entry_t *pent = (parent && i < parent->nmethods) ? &parent->methods[i] : NULL;
            size_t hex = i * sizeof(kptr_t);
            int hexlen = 5;
            for(size_t h = hex; h >= 0x10; h >>= 4) --hexlen;
            if(opt.mangle)
            {
                printf("%s    %*s%lx func=" ADDR " overrides=" ADDR " pac=0x%04hx %s%s\n", color, hexlen, "0x", hex, ent->addr, pent ? pent->addr : 0, ent->pac, ent->mangled, colorReset);
            }
            else
            {
                printf("%s    %*s%lx func=" ADDR " overrides=" ADDR " pac=0x%04hx %s::%s%s\n", color, hexlen, "0x", hex, ent->addr, pent ? pent->addr : 0, ent->pac, ent->class, ent->method, colorReset);
            }
        }
    }
    if(opt.metaclass)
    {
        if(opt.vtab)
        {
            printf("vtab=" ADDR " ", meta->metavtab);
        }
        if(opt.size)
        {
            printf("size=---------- ");
        }
        if(opt.meta)
        {
            printf("meta=------------------ parent=------------------ ");
            if(opt.vtab)
            {
                printf("metavtab=------------------ ");
            }
        }
        printf("%s%s%-*s%s", colorCyan, meta->name, namelen ? namelen - (int)strlen(meta->name) : 0, "::MetaClass", colorReset);
        if(opt.bundle)
        {
            if(meta->bundle)
            {
                printf(" (%s%s%s)", colorBlue, meta->bundle, colorReset);
            }
            else
            {
                printf(" (%s???%s)", colorRed, colorReset);
            }
        }
        printf("\n");
        if(opt.overrides)
        {
            for(size_t i = 0; i < meta->nmetamethods; ++i)
            {
                vtab_entry_t *ent = &meta->metamethods[i];
                if(!ent->overrides && !opt.inherit)
                {
                    continue;
                }
                const char *color = ent->addr == -1 ? colorRed : !ent->overrides ? colorGray : "";
                vtab_entry_t *pent = (OSMetaClass && i < OSMetaClass->nmethods) ? &OSMetaClass->methods[i] : NULL;
                size_t hex = i * sizeof(kptr_t);
                int hexlen = 5;
                for(size_t h = hex; h >= 0x10; h >>= 4) --hexlen;
                if(opt.mangle)
                {
                    printf("%s    %*s%lx func=" ADDR " overrides=" ADDR " pac=0x%04hx %s%s\n", color, hexlen, "0x", hex, ent->addr, pent ? pent->addr : 0, ent->pac, ent->mangled, colorReset);
                }
                else
                {
                    printf("%s    %*s%lx func=" ADDR " overrides=" ADDR " pac=0x%04hx %s::%s%s\n", color, hexlen, "0x", hex, ent->addr, pent ? pent->addr : 0, ent->pac, ent->class, ent->method, colorReset);
                }
            }
        }
    }
    return true;
}

// ---------- ---------- ---------- ---------- radare2 ---------- ---------- ---------- ----------

// Turn special chars to underscores for r2.
static const char* radarify(const char *sym)
{
    static char *buf = NULL;
    static size_t buflen = 0;
    size_t len = strlen(sym) + 1;
    if(len > buflen)
    {
        buf = realloc(buf, len);
        if(!buf)
        {
            ERRNO("radarify: malloc(buf)");
            return NULL;
        }
        buflen = len;
    }
    size_t from = 0,
           to   = 0,
           last = 0;
    while(from < len)
    {
        char c = sym[from++];
        if(
            (c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c == '.') ||
            (c == ':')
        )
        {
            last = to;
        }
        else
        {
            c = '_';
        }
        buf[to++] = c;
    }
    buf[last+1] = '\0';
    return buf;
}

static bool radare2_init(metaclass_t **list, size_t lsize, opt_t opt, void **argp)
{
    printf("fs symbols\n");
    return true;
}

static bool radare2_print_symbol(const char *sym, kptr_t addr, void *arg)
{
    const char *r2name = radarify(sym);
    if(!r2name)
    {
        return false;
    }
    printf("f sym.%s 0 " ADDR "\n", r2name, addr);
    printf("\"fN sym.%s %s\"\n", r2name, sym);
    return true;
}

// ---------- ---------- ---------- ---------- other ---------- ---------- ---------- ----------

print_t iometa_print =
{
    .init = iometa_print_init,
    .print_symbol = NULL,
    .print_class = iometa_print_class,
    .finish = NULL,
};
print_t radare2_print =
{
    .init = radare2_init,
    .print_symbol = radare2_print_symbol,
    .print_class = NULL,
    .finish = NULL,
};

static bool default_print_entry(vtab_entry_t *ent, opt_t opt, metaclass_t *OSMetaClass, print_sym_t print_sym, void *arg)
{
    static char *buf = NULL;
    static size_t buflen = 0;
    if(!ent->overrides || ent->addr == -1)
    {
        return true;
    }
    const char *s;
    if(opt.mangle)
    {
        s = ent->mangled;
    }
    else
    {
    again:;
        size_t nl = snprintf(buf, buflen, "%s::%s", ent->class, ent->method);
        if(nl >= buflen)
        {
            ++nl;
            buf = realloc(buf, nl);
            if(!buf)
            {
                ERRNO("default_print_class: malloc(buf)");
                return false;
            }
            buflen = nl;
            goto again;
        }
        s = buf;
    }
    if(!print_sym(s, ent->addr, arg))
    {
        return false;
    }
    return true;
}

static bool default_print_class(metaclass_t *meta, opt_t opt, metaclass_t *OSMetaClass, print_sym_t print_sym, void *arg)
{
    static char *buf = NULL;
    static size_t buflen = 0;
    size_t len = strlen(meta->name);
    size_t nl = len + 21;
    for(size_t i = len; i >= 10; i /= 10)
    {
        ++nl;
    }
    if(nl > buflen)
    {
        buf = realloc(buf, nl);
        if(!buf)
        {
            ERRNO("default_print_class: malloc(buf)");
            return false;
        }
        buflen = nl;
    }

    if(opt.vtab && meta->vtab != 0 && meta->vtab != -1)
    {
        if(opt.mangle) snprintf(buf, buflen, "__ZTV%lu%s", len, meta->name);
        else           snprintf(buf, buflen, "vtablefor%s", meta->name);
        if(!print_sym(buf, meta->vtab, arg)) return false;
    }
    if(opt.meta && meta->addr)
    {
        if(opt.mangle) snprintf(buf, buflen, "__ZN%lu%s10gMetaClassE", len, meta->name);
        else           snprintf(buf, buflen, "%s::gMetaClass", meta->name);
        if(!print_sym(buf, meta->addr, arg)) return false;
    }
    if(opt.meta && meta->metavtab != 0 && meta->metavtab != -1)
    {
        if(opt.mangle) snprintf(buf, buflen, "__ZTVN%lu%s9MetaClassE", len, meta->name);
        else           snprintf(buf, buflen, "vtablefor%s::MetaClass", meta->name);
        if(!print_sym(buf, meta->metavtab, arg)) return false;
    }

    if(opt.overrides)
    {
        for(size_t i = 0; i < meta->nmethods; ++i)
        {
            if(!default_print_entry(&meta->methods[i], opt, OSMetaClass, print_sym, arg))
            {
                return false;
            }
        }
        if(opt.metaclass)
        {
            for(size_t i = 0; i < meta->nmetamethods; ++i)
            {
                if(!default_print_entry(&meta->metamethods[i], opt, OSMetaClass, print_sym, arg))
                {
                    return false;
                }
            }
        }
    }

    return true;
}

bool print_all(void *classes, opt_t opt, metaclass_t *OSMetaClass, const char *filt_class, const char *filt_override, const char **filter, kptr_t pure_virtual, kptr_t OSMetaClassConstructor, kptr_t OSMetaClassAltConstructor, print_t *print)
{
    bool success = false;
    ARRCAST(metaclass_t, metas, classes);
    metaclass_t **target = NULL;
    metaclass_t **list = NULL;
    if(filt_class)
    {
        // Exact match
        {
            size_t num = 0;
            for(size_t i = 0; i < metas->idx; ++i)
            {
                if(strcmp(metas->val[i].name, filt_class) == 0)
                {
                    ++num;
                }
            }
            if(num)
            {
                target = malloc((num + 1) * sizeof(*target));
                if(!target)
                {
                    ERRNO("malloc(target)");
                    goto out;
                }
                target[num] = NULL;
                num = 0;
                for(size_t i = 0; i < metas->idx; ++i)
                {
                    if(strcmp(metas->val[i].name, filt_class) == 0)
                    {
                        target[num++] = &metas->val[i];
                    }
                }
            }
        }
        // Partial match
        if(!target)
        {
            size_t num = 0;
            for(size_t i = 0; i < metas->idx; ++i)
            {
                if(strstr(metas->val[i].name, filt_class))
                {
                    ++num;
                }
            }
            if(num)
            {
                target = malloc((num + 1) * sizeof(*target));
                if(!target)
                {
                    ERRNO("malloc(target)");
                    goto out;
                }
                target[num] = NULL;
                num = 0;
                for(size_t i = 0; i < metas->idx; ++i)
                {
                    if(strstr(metas->val[i].name, filt_class))
                    {
                        target[num++] = &metas->val[i];
                    }
                }
            }
        }
        if(!target)
        {
            ERR("No class matching %s.", filt_class);
            goto out;
        }
    }
    list = malloc(metas->idx * sizeof(metaclass_t*));
    if(!list)
    {
        ERRNO("malloc(list)");
        goto out;
    }
    size_t lsize = 0;
    if(opt.parent)
    {
        for(metaclass_t **ptr = target; *ptr; ++ptr)
        {
            for(metaclass_t *meta = *ptr; meta; )
            {
                if(meta->visited)
                {
                    break;
                }
                meta->visited = 1;
                list[lsize++] = meta;
                meta = meta->parentP;
            }
        }
    }
    else if(target)
    {
        for(metaclass_t **ptr = target; *ptr; ++ptr)
        {
            (*ptr)->visited = 1;
            list[lsize++] = *ptr;
        }
        if(opt.extend)
        {
            for(size_t j = 0; j < lsize; ++j)
            {
                kptr_t addr = list[j]->addr;
                for(size_t i = 0; i < metas->idx; ++i)
                {
                    metaclass_t *meta = &metas->val[i];
                    if(!meta->visited && meta->parent == addr)
                    {
                        list[lsize++] = meta;
                        meta->visited = 1;
                    }
                }
            }
        }
    }
    else
    {
        for(size_t i = 0; i < metas->idx; ++i)
        {
            list[lsize++] = &metas->val[i];
        }
    }
    if(filter)
    {
        size_t nsize = 0;
        for(size_t i = 0; i < lsize; ++i)
        {
            const char *bundle = list[i]->bundle;
            for(const char **ptr = filter; *ptr; ++ptr)
            {
                if(strcmp(bundle, *ptr) == 0)
                {
                    list[nsize++] = list[i];
                }
            }
        }
        lsize = nsize;
    }
    if(filt_override)
    {
        size_t slen = strlen(filt_override),
               nsize = 0;
        for(size_t i = 0; i < lsize; ++i)
        {
            metaclass_t *m = list[i];
            for(size_t i = 0; i < m->nmethods; ++i)
            {
                vtab_entry_t *ent = &m->methods[i];
                if(ent->overrides && strncmp(ent->method, filt_override, slen) == 0 && ent->method[slen] == '(') // Pretty sure this is as proper as it gets
                {
                    list[nsize++] = m;
                    break;
                }
            }
        }
        lsize = nsize;
    }
    if(opt.bsort || opt.csort)
    {
        qsort(list, lsize, sizeof(*list), opt.bsort ? &compare_meta_bundles : &compare_meta_names);
    }

    void *arg = NULL;
    if(print->init && !print->init(list, lsize, opt, &arg))
    {
        goto out;
    }
    bool ok = true;
    if(print->print_symbol)
    {
        if(pure_virtual)
        {
            ok = print->print_symbol("___cxa_pure_virtual", pure_virtual, arg);
        }
        if(ok && OSMetaClassConstructor)
        {
            ok = print->print_symbol(opt.mangle ? "__ZN11OSMetaClassC2EPKcPKS_j" : "OSMetaClass::OSMetaClass(char const*, OSMetaClass const*, unsigned int)", OSMetaClassConstructor, arg);
        }
        if(ok && OSMetaClassAltConstructor)
        {
            ok = print->print_symbol(opt.mangle ? "__ZN11OSMetaClassC2EPKcPKS_jPP4zoneS1_19zone_create_flags_t" : "OSMetaClass::OSMetaClass(char const*, OSMetaClass const*, unsigned int, zone**, char const*, zone_create_flags_t)", OSMetaClassAltConstructor, arg);
        }
    }
    if(ok)
    {
        print_class_t pr = print->print_class ? print->print_class : default_print_class;
        for(size_t i = 0; i < lsize; ++i)
        {
            ok = pr(list[i], opt, OSMetaClass, print->print_symbol, arg);
            if(!ok)
            {
                break;
            }
        }
    }
    // Run this unconditionally
    if(print->finish)
    {
        if(!print->finish(arg))
        {
            ok = false;
        }
    }
    success = ok;

out:;
    if(target) free(target);
    if(list)   free(list);
    return success;
}
