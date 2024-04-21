/* Copyright (c) 2018-2024 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#include <stddef.h>             // size_t
#include <stdio.h>
#include <stdlib.h>             // realloc, free
#include <string.h>             // strcmp, strlen

#include "a64.h"
#include "a64emu.h"
#include "macho.h"
#include "meta.h"
#include "util.h"

int compare_meta_candidates(const void *a, const void *b)
{
    const metaclass_candidate_t *x = (const metaclass_candidate_t*)a,
                                *y = (const metaclass_candidate_t*)b;
    int r = strcmp(x->name, y->name);
    return r != 0 ? r : !x->fncall - !y->fncall;
}

int compare_meta_names(const void *a, const void *b)
{
    const metaclass_t *x = *(const metaclass_t**)a,
                      *y = *(const metaclass_t**)b;
    int r;
    if(!x->name || !y->name)
    {
        r = !!x->name - !!y->name;
    }
    else
    {
        r = strcmp(x->name, y->name);
    }
    return r;
}

int compare_meta_bundles(const void *a, const void *b)
{
    const metaclass_t *x = *(const metaclass_t**)a,
                      *y = *(const metaclass_t**)b;
    int r;
    if(!x->bundle || !y->bundle)
    {
        r = !!x->bundle - !!y->bundle;
    }
    else
    {
        r = strcmp(x->bundle, y->bundle);
    }
    return r != 0 ? r : compare_meta_names(a, b);
}

void add_metaclass(macho_t *macho, void *arg, a64_state_t *state, const uint32_t *callsite, bool want_vtabs)
{
    ARRCAST(metaclass_t, metas, arg);
    const char *name = macho_vtop(macho, state->x[1], 0);
    DBG(1, "Adding metaclass: %s", name);

    metaclass_t *meta;
    ARRNEXT(*metas, meta);
    meta->addr = state->x[0];
    meta->parent = state->x[2];
    meta->vtab = 0;
    meta->metavtab = 0;
    meta->callsite = macho_ptov(macho, callsite);
    meta->parentP = NULL;
    meta->symclass = NULL;
    meta->name = name;
    meta->bundle = NULL;
    meta->methods = NULL;
    meta->metamethods = NULL;
    meta->nmethods = 0;
    meta->nmetamethods = 0;
    meta->objsize = state->x[3];
    meta->methods_done = 0;
    meta->methods_err = 0;
    meta->visited = 0;
    meta->duplicate = 0;
    meta->has_dependents = 0;
    meta->reserved = 0;
    if(want_vtabs)
    {
        if(macho_have_symbols(macho))
        {
            char buf[512];
            uint32_t len = strlen(name);
            if(snprintf(buf, sizeof(buf), "__ZTV%u%s", len, name) >= sizeof(buf))
            {
                WRN("Class name too big for buffer: %s", name);
            }
            else
            {
                meta->vtab = macho_symbol(macho, buf);
                if(meta->vtab)
                {
                    meta->vtab += 2 * sizeof(kptr_t);
                }
                if(snprintf(buf, sizeof(buf), "__ZTVN%u%s9MetaClassE", len, name) >= sizeof(buf))
                {
                    WRN("MetaClass name too big for buffer: %s", name);
                }
                else
                {
                    meta->metavtab = macho_symbol(macho, buf);
                    if(meta->metavtab)
                    {
                        meta->metavtab += 2 * sizeof(kptr_t);
                    }
                }
            }
        }
        if(!meta->metavtab)
        {
            kptr_t x0 = state->x[0];
            for(const uint32_t *m = callsite + 1; is_linear_inst(m) || is_cbz((cbz_t*)m) || is_cbnz((cbz_t*)m) || is_tbz((tbz_t*)m) || is_tbnz((tbz_t*)m); ++m)
            {
                // Kinda trash, but works... and it's at least a possible path
                if(is_cbz((const cbz_t*)m) || is_cbnz((const cbz_t*)m) || is_tbz((const tbz_t*)m) || is_tbnz((const tbz_t*)m))
                {
                    continue;
                }
                emu_ret_t ret = a64_emulate(macho, state, m, &a64cb_check_equal, (void*)(m + 1), false, true, kEmuFnIgnore);
                if(ret != kEmuEnd)
                {
                    DBG(1, "a64_emulate returned %u", ret);
                    break;
                }
                const str_uoff_t *stru = (const str_uoff_t*)m;
                if(is_str_uoff(stru) && (state->valid & (1 << stru->Rn)) && state->x[stru->Rn] + get_str_uoff(stru) == x0)
                {
                    DBG(1, "Got str at " ADDR, macho_ptov(macho, stru));
                    if(!(state->valid & (1 << stru->Rt)))
                    {
                        DBG(1, "Store has no valid source register");
                    }
                    else
                    {
                        meta->metavtab = state->x[stru->Rt];
                    }
                    break;
                }
            }
        }
        if(!meta->metavtab)
        {
            WRN("Failed to find metavtab for %s", name);
        }
    }
}

bool meta_constructor_cb(macho_t *macho, bool want_vtabs, void *metas, void *names, a64_state_t *state, const uint32_t *fnstart, const uint32_t *bl, kptr_t bladdr, void *arg)
{
    const char *name = NULL;
    const uint32_t *fncall = NULL;
    if((state->valid & 0x2) && (state->wide & 0x2))
    {
        name = macho_vtop(macho, state->x[1], 0);
        if(!name)
        {
            DBG(1, "meta->name: " ADDR " (untagged: " ADDR ")", state->x[1], macho_fixup(macho, state->x[1], NULL, NULL, NULL, NULL));
            ERR("Name of MetaClass lies outside all segments at " ADDR, bladdr);
            return false;
        }
    }
    DBG(1, "Constructor candidate for %s", name ? name : "???");
    if((state->valid & 0xe) != 0xe)
    {
        // Check for alt constructor
        if((state->valid & 0xe) == 0x0)
        {
            for(size_t i = 0; i < 32; ++i)
            {
                state->x[i] = 0;
                state->q[i] = 0;
            }
            // NOTE: Will have to revise this if the constructors ever diverge in x0-x3
            state->x[0]  = 0x6174656d656b6166; // "fakemeta"
            state->x[1]  = 0x656d616e656b6166; // "fakename"
            state->x[2]  = 0x00727470656b6166; // "fakeptr"
            state->x[3]  = 0x656b6166; // "fake"
            state->flags  = 0;
            state->valid  = 0xf;
            state->qvalid = 0x0;
            state->wide   = 0x7;
            state->host   = 0x0;
            if(a64_emulate(macho, state, fnstart, &a64cb_check_equal, (void*)bl, false, true, kEmuFnIgnore) == kEmuEnd)
            {
                if((state->valid & 0xf) == 0xf && (state->wide & 0xf) == 0x7 && state->x[0] == 0x6174656d656b6166 && state->x[1] == 0x656d616e656b6166 && state->x[2] == 0x00727470656b6166 && state->x[3] == 0x656b6166)
                {
                    kptr_t addr = macho_ptov(macho, fnstart);
                    DBG(1, "OSMetaClassAltConstructor: " ADDR, addr);
                    // We wanna land here even if we already got OSMetaClassAltConstructor off symtab, in order to suppress the warning below.
                    // But we obviously never wanna store a result or fail on multiple candidates in that case.
                    if(arg)
                    {
                        if(*(kptr_t*)arg)
                        {
                            ERR("More than one candidate for OSMetaClassAltConstructor");
                            exit(-1);
                        }
                        *(kptr_t*)arg = addr;
                    }
                    // Do NOT fall through
                    return true;
                }
            }
        }
        WRN("Skipping constructor call without x1-x3 (%x) at " ADDR, state->valid, bladdr);
        // Fall through
    }
    else if((state->valid & 0x1) != 0x1)
    {
        DBG(1, "Skipping constructor call without x0 at " ADDR, bladdr);
        fncall = bl;
        // Fall through
    }
    else if((state->wide & 0xf) != 0x7)
    {
        WRN("Skipping constructor call with unexpected register widths (%x) at " ADDR, state->wide, bladdr);
        // Fall through
    }
    else
    {
        DBG(1, "Processing constructor call at " ADDR " (%s)", bladdr, name);
        add_metaclass(macho, metas, state, bl, want_vtabs);
        // Do NOT fall through
        return true;
    }
    // We only get here on failure:
    if(name)
    {
        ARRCAST(metaclass_candidate_t, namelist, names);
        metaclass_candidate_t *cand;
        ARRNEXT(*namelist, cand);
        cand->name = name;
        cand->fncall = fncall;
    }
    return true;
}

bool meta_alt_constructor_cb(macho_t *macho, bool want_vtabs, void *metas, void *names, a64_state_t *state, const uint32_t *fnstart, const uint32_t *bl, kptr_t bladdr, void *arg)
{
    const char *name = NULL;
    if((state->valid & 0x2) && (state->wide & 0x2))
    {
        name = macho_vtop(macho, state->x[1], 0);
        if(!name)
        {
            DBG(1, "meta->name: " ADDR " (untagged: " ADDR ")", state->x[1], macho_fixup(macho, state->x[1], NULL, NULL, NULL, NULL));
            ERR("Name of MetaClass lies outside all segments at " ADDR, bladdr);
            return false;
        }
    }
    DBG(1, "Alt constructor candidate for %s", name ? name : "???");
    if((state->valid & 0x7e) != 0x7e)
    {
        WRN("Skipping alt constructor call without x1-x6 (%x) at " ADDR, state->valid, bladdr);
        // Fall through
    }
    else if((state->valid & 0x1) != 0x1)
    {
        DBG(1, "Skipping alt constructor call without x0 (%x) at " ADDR, state->valid, bladdr);
        // Fall through
    }
    else if((state->wide & 0x7f) != 0x37)
    {
        WRN("Skipping alt constructor call with unexpected register widths (%x) at " ADDR, state->wide, bladdr);
        // Fall through
    }
    else
    {
        DBG(1, "Processing alt constructor call at " ADDR " (%s)", bladdr, name);
        // NOTE: Will have to revise this if the constructors ever diverge in x0-x3
        add_metaclass(macho, metas, state, bl, want_vtabs);
        // Do NOT fall through
        return true;
    }
    // We only get here on failure:
    if(name)
    {
        // For now, always set NULL for alt constructor
        ARRCAST(metaclass_candidate_t, namelist, names);
        metaclass_candidate_t *cand;
        ARRNEXT(*namelist, cand);
        cand->name = name;
        cand->fncall = NULL;
    }
    return true;
}

typedef struct
{
    macho_t *macho;
    bool want_vtabs;
    void *arr;
    void *metas;
    void *names;
    meta_constructor_cb_t cb;
    void *arg;
} find_meta_constructor_calls_args_t;

static bool find_meta_constructor_calls_cb(const void *ptr, kptr_t addr, size_t size, uint32_t prot, void *arg)
{
    if(!(prot & VM_PROT_EXECUTE))
    {
        return true;
    }
    find_meta_constructor_calls_args_t *args = arg;
    ARRCAST(kptr_t, aliases, args->arr);
    STEP_MEM(uint32_t, mem, ptr, size, 1)
    {
        const bl_t *bl = (const bl_t*)mem;
        if(is_bl(bl) || is_b(bl))
        {
            kptr_t bladdr = addr + ((uintptr_t)bl - (uintptr_t)ptr);
            kptr_t bltarg = bladdr + get_bl_off(bl);
            for(size_t i = 0; i < aliases->idx; ++i)
            {
                if(bltarg == aliases->val[i])
                {
                    const uint32_t *fnstart = find_function_start(args->macho, "OSMetaClass constructor call", mem, ptr, is_bl(bl));
                    if(fnstart)
                    {
                        a64_state_t state;
                        if(a64_emulate(args->macho, &state, fnstart, &a64cb_check_equal, (void*)mem, true, true, kEmuFnIgnore) == kEmuEnd)
                        {
                            if(!args->cb(args->macho, args->want_vtabs, args->metas, args->names, &state, fnstart, mem, bladdr, args->arg))
                            {
                                return false;
                            }
                        }
                    }
                    break;
                }
            }
        }
    }
    return true;
}

bool find_meta_constructor_calls(macho_t *macho, bool want_vtabs, void *arr, void *metas, void *names, meta_constructor_cb_t cb, void *arg)
{
    find_meta_constructor_calls_args_t args =
    {
        .macho = macho,
        .want_vtabs = want_vtabs,
        .arr = arr,
        .metas = metas,
        .names = names,
        .cb = cb,
        .arg = arg,
    };
    return macho_foreach_map(macho, &find_meta_constructor_calls_cb, &args);
}
