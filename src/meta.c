/* Copyright (c) 2018-2020 Siguza
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

// Turn special chars to underscores for now.
// Eventually this should be replaced by the mangled name.
// TODO: split r2 stuff to its own file
static const char* radarify(const char *sym)
{
    static char *buf = NULL;
    static size_t buflen = 0;
    size_t len = strlen(sym) + 1;
    if(len > buflen)
    {
        buf = realloc(buf, len);
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

void print_metaclass(metaclass_t *meta, int namelen, opt_t opt)
{
    // TODO: OSMetaClass::alloc()
    if(opt.radare)
    {
        if(opt.mangle)
        {
            size_t len = strlen(meta->name);
            if(meta->vtab != 0 && meta->vtab != -1)
            {
                printf("f sym.__ZTV%lu%s 0 " ADDR "\n", len, meta->name, meta->vtab);
                printf("fN sym.__ZTV%lu%s __ZTV%lu%s\n", len, meta->name, len, meta->name);
            }
            if(meta->addr)
            {
                printf("f sym.__ZN%lu%s10gMetaClassE 0 " ADDR "\n", len, meta->name, meta->addr);
                printf("fN sym.__ZN%lu%s10gMetaClassE __ZN%lu%s10gMetaClassE\n", len, meta->name, len, meta->name);
            }
            if(meta->metavtab != 0 && meta->metavtab != -1)
            {
                printf("f sym.__ZTVN%lu%s9MetaClassE 0 " ADDR "\n", len, meta->name, meta->metavtab);
                printf("fN sym.__ZTVN%lu%s9MetaClassE __ZTVN%lu%s9MetaClassE\n", len, meta->name, len, meta->name);
            }
            for(size_t i = 0; i < meta->nmethods; ++i)
            {
                vtab_entry_t *ent = &meta->methods[i];
                if(!ent->overrides || ent->addr == -1)
                {
                    continue;
                }
                printf("f sym.%s 0 " ADDR "\n", ent->mangled, ent->addr);
                printf("fN sym.%s %s\n", ent->mangled, ent->mangled);
            }
        }
        else
        {
            if(meta->vtab != 0 && meta->vtab != -1)
            {
                printf("f sym.vtablefor%s 0 " ADDR "\n", meta->name, meta->vtab);
                printf("fN sym.vtablefor%s vtablefor%s\n", meta->name, meta->name);
            }
            if(meta->addr)
            {
                printf("f sym.%s::gMetaClass 0 " ADDR "\n", meta->name, meta->addr);
                printf("fN sym.%s::gMetaClass %s::gMetaClass\n", meta->name, meta->name);
            }
            if(meta->metavtab != 0 && meta->metavtab != -1)
            {
                printf("f sym.vtablefor%s::MetaClass 0 " ADDR "\n", meta->name, meta->metavtab);
                printf("fN sym.vtablefor%s::MetaClass vtablefor%s::MetaClass\n", meta->name, meta->name);
            }
            for(size_t i = 0; i < meta->nmethods; ++i)
            {
                vtab_entry_t *ent = &meta->methods[i];
                if(!ent->overrides || ent->addr == -1)
                {
                    continue;
                }
                const char *r2name = radarify(ent->method);
                printf("f sym.%s::%s 0 " ADDR "\n", ent->class, r2name, ent->addr);
                printf("\"fN sym.%s::%s %s::%s\"\n", ent->class, r2name, ent->class, ent->method);
            }
        }
    }
    else
    {
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
            printf("meta=" ADDR " parent=" ADDR " metavtab=" ADDR " ", meta->addr, meta->parent, meta->metavtab);
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
    }
}

void add_metaclass(void *kernel, kptr_t kbase, fixup_kind_t fixupKind, void *arg, a64_state_t *state, uint32_t *callsite, bool want_vtabs, sym_t *bsyms, size_t nsyms)
{
    ARRCAST(metaclass_t, metas, arg);
    const char *name = addr2ptr(kernel, state->x[1]);
    DBG("Adding metaclass: %s", name);

    metaclass_t *meta;
    ARRNEXT(*metas, meta);
    meta->addr = state->x[0];
    meta->parent = state->x[2];
    meta->vtab = 0;
    meta->metavtab = 0;
    meta->callsite = off2addr(kernel, (uintptr_t)callsite - (uintptr_t)kernel);
    meta->parentP = NULL;
    meta->symclass = NULL;
    meta->name = name;
    meta->bundle = NULL;
    meta->methods = NULL;
    meta->nmethods = 0;
    meta->objsize = state->x[3];
    meta->methods_done = 0;
    meta->methods_err = 0;
    meta->visited = 0;
    meta->duplicate = 0;
    meta->reserved = 0;
    if(want_vtabs)
    {
        if(nsyms > 0)
        {
            char buf[512];
            uint32_t len = strlen(name);
            if(snprintf(buf, sizeof(buf), "__ZTV%u%s", len, name) >= sizeof(buf))
            {
                WRN("Class name too big for buffer: %s", name);
            }
            else
            {
                meta->vtab = find_sym_by_name(buf, bsyms, nsyms);
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
                    meta->metavtab = find_sym_by_name(buf, bsyms, nsyms);
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
            for(uint32_t *m = callsite + 1; is_linear_inst(m) || is_cbz((cbz_t*)m) || is_cbnz((cbz_t*)m) || is_tbz((tbz_t*)m) || is_tbnz((tbz_t*)m); ++m)
            {
                // Kinda trash, but works... and it's at least a possible path
                if(is_cbz((cbz_t*)m) || is_cbnz((cbz_t*)m) || is_tbz((tbz_t*)m) || is_tbnz((tbz_t*)m))
                {
                    continue;
                }
                emu_ret_t ret = a64_emulate(kernel, kbase, fixupKind, state, m, &a64cb_check_equal, m + 1, false, true, kEmuFnIgnore);
                if(ret != kEmuEnd)
                {
                    DBG("a64_emulate returned %u", ret);
                    break;
                }
                str_uoff_t *stru = (str_uoff_t*)m;
                if(is_str_uoff(stru) && (state->valid & (1 << stru->Rn)) && state->x[stru->Rn] + get_str_uoff(stru) == x0)
                {
                    DBG("Got str at " ADDR, off2addr(kernel, (uintptr_t)stru - (uintptr_t)kernel));
                    if(!(state->valid & (1 << stru->Rt)))
                    {
                        DBG("Store has no valid source register");
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

void meta_constructor_cb(void *kernel, kptr_t kbase, mach_seg_t *seg, fixup_kind_t fixupKind, bool want_vtabs, void *metas, void *names, sym_t *bsyms, size_t nsyms, a64_state_t *state, uint32_t *fnstart, uint32_t *bl, kptr_t bladdr, void *arg)
{
    const char *name = NULL;
    uint32_t *fncall = NULL;
    if((state->valid & 0x2) && (state->wide & 0x2))
    {
        name = addr2ptr(kernel, state->x[1]);
        if(!name)
        {
            DBG("meta->name: " ADDR " (untagged: " ADDR ")", state->x[1], kuntag(kbase, fixupKind, state->x[1], NULL, NULL, NULL, NULL));
            ERR("Name of MetaClass lies outside all segments at " ADDR, bladdr);
            exit(-1);
        }
    }
    DBG("Constructor candidate for %s", name ? name : "???");
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
            state->valid  = 0xf;
            state->qvalid = 0x0;
            state->wide   = 0x7;
            state->host   = 0x0;
            if(a64_emulate(kernel, kbase, fixupKind, state, fnstart, &a64cb_check_equal, bl, false, true, kEmuFnIgnore) == kEmuEnd)
            {
                if((state->valid & 0xf) == 0xf && (state->wide & 0xf) == 0x7 && state->x[0] == 0x6174656d656b6166 && state->x[1] == 0x656d616e656b6166 && state->x[2] == 0x00727470656b6166 && state->x[3] == 0x656b6166)
                {
                    kptr_t addr = seg->vmaddr + ((uintptr_t)fnstart - ((uintptr_t)kernel + seg->fileoff));
                    DBG("OSMetaClassAltConstructor: " ADDR, addr);
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
                    return;
                }
            }
        }
        WRN("Skipping constructor call without x1-x3 (%x) at " ADDR, state->valid, bladdr);
        // Fall through
    }
    else if((state->valid & 0x1) != 0x1)
    {
        DBG("Skipping constructor call without x0 at " ADDR, bladdr);
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
        DBG("Processing constructor call at " ADDR " (%s)", bladdr, name);
        add_metaclass(kernel, kbase, fixupKind, metas, state, bl, want_vtabs, bsyms, nsyms);
        // Do NOT fall through
        return;
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
}

void meta_alt_constructor_cb(void *kernel, kptr_t kbase, mach_seg_t *seg, fixup_kind_t fixupKind, bool want_vtabs, void *metas, void *names, sym_t *bsyms, size_t nsyms, a64_state_t *state, uint32_t *fnstart, uint32_t *bl, kptr_t bladdr, void *arg)
{
    const char *name = NULL;
    if((state->valid & 0x2) && (state->wide & 0x2))
    {
        name = addr2ptr(kernel, state->x[1]);
        if(!name)
        {
            DBG("meta->name: " ADDR " (untagged: " ADDR ")", state->x[1], kuntag(kbase, fixupKind, state->x[1], NULL, NULL, NULL, NULL));
            ERR("Name of MetaClass lies outside all segments at " ADDR, bladdr);
            exit(-1);
        }
    }
    DBG("Alt constructor candidate for %s", name ? name : "???");
    if((state->valid & 0x7e) != 0x7e)
    {
        WRN("Skipping alt constructor call without x1-x6 (%x) at " ADDR, state->valid, bladdr);
        // Fall through
    }
    else if((state->valid & 0x1) != 0x1)
    {
        DBG("Skipping alt constructor call without x0 (%x) at " ADDR, state->valid, bladdr);
        // Fall through
    }
    else if((state->wide & 0x7f) != 0x37)
    {
        WRN("Skipping alt constructor call with unexpected register widths (%x) at " ADDR, state->wide, bladdr);
        // Fall through
    }
    else
    {
        DBG("Processing alt constructor call at " ADDR " (%s)", bladdr, name);
        // NOTE: Will have to revise this if the constructors ever diverge in x0-x3
        add_metaclass(kernel, kbase, fixupKind, metas, state, bl, want_vtabs, bsyms, nsyms);
        // Do NOT fall through
        return;
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
}

void find_meta_constructor_calls(void *kernel, mach_hdr_t *hdr, kptr_t kbase, fixup_kind_t fixupKind, bool have_plk_text_exec, bool want_vtabs, void *arr, void *metas, void *names, sym_t *bsyms, size_t nsyms, meta_constructor_cb_t cb, void *arg)
{
    ARRCAST(kptr_t, aliases, arr);
    FOREACH_CMD(hdr, cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            if(seg->filesize > 0 && SEG_IS_EXEC(seg, fixupKind, have_plk_text_exec))
            {
                STEP_MEM(uint32_t, mem, (uintptr_t)kernel + seg->fileoff, seg->filesize, 1)
                {
                    bl_t *bl = (bl_t*)mem;
                    if(is_bl(bl) || is_b(bl))
                    {
                        kptr_t bladdr = seg->vmaddr + ((uintptr_t)bl - ((uintptr_t)kernel + seg->fileoff));
                        kptr_t bltarg = bladdr + get_bl_off(bl);
                        for(size_t i = 0; i < aliases->idx; ++i)
                        {
                            if(bltarg == aliases->val[i])
                            {
                                uint32_t *fnstart = find_function_start(kernel, seg, "OSMetaClass constructor call", mem, is_bl(bl));
                                if(fnstart)
                                {
                                    a64_state_t state;
                                    if(a64_emulate(kernel, kbase, fixupKind, &state, fnstart, &a64cb_check_equal, mem, true, true, kEmuFnIgnore) == kEmuEnd)
                                    {
                                        cb(kernel, kbase, seg, fixupKind, want_vtabs, metas, names, bsyms, nsyms, &state, fnstart, mem, bladdr, arg);
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}
