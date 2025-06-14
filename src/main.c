/* Copyright (c) 2018-2025 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#if 0
How this works:

1.  First we find the OSMetaClass constructor, by finding the only function that
    is called with each "IORegistryEntry", "IOService" and "IOUserClient" in x1.
2.  Then we get all locations where that is hardcoded as a pointer (usually for imports), dubbed "refs".
3.  For all refs, we then get all locations where that pointer is loaded and jumped to, in the form:

    adrp xN, ...
    add xN, xN, ...
    br xN

    Together with the original constructor we put those in a list, dubbed "aliases".
4.  We get all places where any alias is called, seek backwards as far as we understand the instructions
    and there are no branches, and do some best-effort emulation to fill registers x0-x3.
    - If we end up with x0 missing, we skip the invocation.
    - If we end up with any of x1-x3 missing, we print a warning because that should never happen.
    - Otherwise, we get name (x1) and size (x3) of the class as well as address of the metaclass (x0) and its parent (x2).
5.  If we want vtables, we first find out at what offset OSObject::getMetaClass is in the vtable.
6.  Then we find all locations returning a metaclass address in one of two possible forms:

    adrp xN, ...
    add x0, xN, ...
    ret

    adr x0, ...
    (nop)
    ret

7.  To all of those locations we search a hardcoded pointer in the kernel.
    If we find one in an array of pointers preceded by two NULL pointers, we accept this as the class vtable.
8.  We go through all vtable entries until we hit another NULL pointer marking the end (this is an -mkernel exclusive)
    and do things like comparing against the parent, computing C++ symbols for PAC diversifier, etc.
9.  If we want bundle names, we shill out to the Mach-O layer and ask it to match against metaclass constructor callsites.
10. Finally we do some filtering and sorting, and print our findings.
#endif

#include <stdbool.h>
#include <stdint.h>             // uintptr_t
#include <stdio.h>              // fprintf, stderr
#include <stdlib.h>             // malloc, realloc, qsort, bsearch, exit
#include <string.h>             // strcmp, strstr, memcpy, memmem
#include <strings.h>            // bzero
#include <sys/mman.h>           // PROT_READ, PROT_WRITE
#include <CoreFoundation/CoreFoundation.h>

#include "a64.h"
#include "a64emu.h"
#include "cxx.h"
#include "macho.h"
#include "meta.h"
#include "print.h"
#include "symmap.h"
#include "util.h"

#define NUM_KEXTS_EXPECT 0x200

static bool get_import_target(const adr_t *adrp, kptr_t alias, bool space_for_4, kptr_t *addr)
{
    const ldr_uoff_t *ldr1 = (const ldr_uoff_t*)(adrp + 1);
    const br_t *br = (const br_t*)(adrp + 2);
    const add_imm_t *add = (const add_imm_t*)(adrp + 1);
    const ldr_uoff_t *ldr2 = (const ldr_uoff_t*)(adrp + 2);
    const bra_t *bra = (const bra_t*)(adrp + 3);
    if
    (
        is_ldr_uoff(ldr1) && ldr1->sf == 1 && is_br(br) && // Types
        adrp->Rd == ldr1->Rn && ldr1->Rt == br->Rn         // Registers
    )
    {
        *addr = (alias & ~0xfffULL) + get_adr_off(adrp) + get_ldr_uoff(ldr1);
        return true;
    }
    else if
    (
        space_for_4 &&
        is_add_imm(add) && add->sf == 1 && is_ldr_uoff(ldr2) && ldr2->sf == 1 && is_bra(bra) && // Types
        adrp->Rd == add->Rn && add->Rd == ldr2->Rn && ldr2->Rt == bra->Rn && ldr2->Rn == bra->Rm && // Registers
        get_ldr_uoff(ldr2) == 0
    )
    {
        *addr = (alias & ~0xfffULL) + get_adr_off(adrp) + get_add_sub_imm(add);
        return true;
    }
    return false;
}

typedef struct
{
    kptr_t reloc;
    kptr_t alias;
} find_stub_for_reloc_args_t;

static bool find_stub_for_reloc_cb(const void *ptr, kptr_t addr, size_t size, uint32_t prot, void *arg)
{
    if(!(prot & VM_PROT_EXECUTE))
    {
        return true;
    }
    find_stub_for_reloc_args_t *args = arg;
    STEP_MEM(uint32_t, mem, ptr, size, 3)
    {
        const adr_t *adrp = (const adr_t*)mem;
        if(!is_adrp(adrp))
        {
            continue;
        }
        kptr_t offset = (uintptr_t)adrp - (uintptr_t)ptr;
        kptr_t alias = addr + offset;
        kptr_t target = 0;
        if(!get_import_target(adrp, alias, (size - offset) / sizeof(uint32_t) >= 4, &target))
        {
            continue;
        }
        if(target == args->reloc)
        {
            args->alias = alias;
            return false; // stop searching
        }
    }
    return true;
}

static kptr_t find_stub_for_reloc(macho_t *macho, const char *sym)
{
    kptr_t reloc = macho_reloc(macho, sym);
    if(!reloc)
    {
        return 0;
    }
    DBG(1, "Found stub for %s at " ADDR, sym, reloc);
    find_stub_for_reloc_args_t args =
    {
        .reloc = reloc,
        .alias = 0,
    };
    macho_foreach_map(macho, &find_stub_for_reloc_cb, &args);
    return args.alias;
}

typedef struct
{
    macho_t *macho;
    void *refs;
    kptr_t func;
} find_imports_ref_args_t;

static bool find_imports_ref_cb(const kptr_t *ptr, void *arg)
{
    find_imports_ref_args_t *args = arg;
    ARRCAST(kptr_t, refs, args->refs);
    bool bind = false;
    kptr_t addr = macho_fixup(args->macho, *ptr, &bind, NULL, NULL, NULL);
    if(!bind && addr == args->func)
    {
        kptr_t ref = macho_ptov(args->macho, ptr);
        DBG(1, "ref: " ADDR, ref);
        ARRPUSH(*refs, ref);
    }
    return true;
}

typedef struct
{
    void *refs;
    void *arr;
} find_imports_alias_args_t;

static bool find_imports_alias_cb(const void *ptr, kptr_t addr, size_t size, uint32_t prot, void *arg)
{
    if(!(prot & VM_PROT_EXECUTE))
    {
        return true;
    }
    find_imports_alias_args_t *args = arg;
    ARRCAST(kptr_t, refs, args->refs);
    ARRCAST(kptr_t, aliases, args->arr);
    STEP_MEM(uint32_t, mem, ptr, size, 3)
    {
        const adr_t *adrp = (const adr_t*)mem;
        if(!is_adrp(adrp))
        {
            continue;
        }
        kptr_t offset = (uintptr_t)adrp - (uintptr_t)ptr;
        kptr_t alias = addr + offset;
        kptr_t target = 0;
        if(!get_import_target(adrp, alias, (size - offset) / sizeof(uint32_t) >= 4, &target))
        {
            continue;
        }
        for(size_t i = 0; i < refs->idx; ++i)
        {
            if(target == refs->val[i])
            {
                DBG(1, "alias: " ADDR, alias);
                ARRPUSH(*aliases, alias);
                break;
            }
        }
    }
    return true;
}

static bool find_imports(macho_t *macho, void *arr, kptr_t func)
{
    if(macho_is_kext(macho))
    {
        return true;
    }

    ARRDEF(kptr_t, refs, NUM_KEXTS_EXPECT);
    find_imports_ref_args_t ptr_args =
    {
        .macho = macho,
        .refs = &refs,
        .func = func,
    };
    if(!macho_foreach_ptr(macho, &find_imports_ref_cb, &ptr_args))
    {
        return false;
    }
    find_imports_alias_args_t map_args =
    {
        .refs = &refs,
        .arr = arr,
    };
    macho_foreach_map(macho, &find_imports_alias_cb, &map_args);
    ARRFREE(refs);
    return true;
}

typedef enum
{
    kVtabFunc,
    kVtabChunk,
    kVtabEnd,
} vtab_check_t;

static vtab_check_t check_vtab_elem(macho_t *macho, uint32_t objsize, const kptr_t *vtab, kptr_t vtabaddr, size_t idx)
{
    // TODO: hoist this lookup to the callsites?
    const void *segptr = NULL;
    size_t segsize = 0;
    if(!macho_segment_for_ptr(macho, vtab, &segptr, NULL, &segsize, NULL))
    {
        ERR("vtable ptr (" ADDR ") is not in any segment.", vtabaddr);
        exit(-1);
    }

    // TODO: refactor exit() calls into a return value here?
    if(idx >= (segsize - ((uintptr_t)vtab - (uintptr_t)segptr)) / sizeof(kptr_t))
    {
        ERR("vtable (" ADDR ") runs off the end of its segment.", vtabaddr);
        exit(-1);
    }
    if(macho_is_ptr(macho, &vtab[idx]))
    {
        return kVtabFunc;
    }
    kptr_t val = vtab[idx];
    if(val == 0x0)
    {
        return kVtabEnd;
    }
    if((int64_t)val >= 0)
    {
        ERR("vtable (" ADDR ") has non-negative offset-to-top (idx 0x%zx)", vtabaddr, idx);
        exit(-1);
    }
    if((0ULL - val) >= objsize)
    {
        ERR("vtable (" ADDR ") offset-to-top exceeds object size (idx 0x%zx, size 0x%x)", vtabaddr, idx, objsize);
        exit(-1);
    }
    ++idx;
    if(idx >= (segsize - ((uintptr_t)vtab - (uintptr_t)segptr)) / sizeof(kptr_t))
    {
        ERR("vtable (" ADDR ") runs off the end of its segment.", vtabaddr);
        exit(-1);
    }
    val = vtab[idx];
    if(val != 0x0)
    {
        ERR("vtable (" ADDR ") has non-zero rtti (idx 0x%zx)", vtabaddr, idx);
        exit(-1);
    }
    return kVtabChunk;
}

typedef struct
{
    void *arr;
    const char *str;
} find_str_args_t;

static bool find_str_cb(kptr_t addr, void *arg)
{
    find_str_args_t *args = arg;
    DBG(1, "strref(%s): " ADDR, args->str, addr);
    ARRCAST(kptr_t, arr, args->arr);
    ARRPUSH(*arr, addr);
    return true;
}

static bool find_str(macho_t *macho, void *arg, const char *str)
{
    find_str_args_t args =
    {
        .arr = arg,
        .str = str,
    };
    size_t len = strlen(str) + 1;
    return macho_find_bytes(macho, str, len, 1, find_str_cb, &args);
}

typedef struct
{
    macho_t *macho;
    void *prev;
    void *cur;
    void *strrefs;
    const char *str;
    bool first;
} OSMetaClassConstructor_args_t;

static bool OSMetaClassConstructor_cb(const void *ptr, kptr_t addr, size_t size, uint32_t prot, void *arg)
{
    if(!(prot & VM_PROT_EXECUTE))
    {
        return true;
    }
    OSMetaClassConstructor_args_t *args = arg;
    ARRCAST(kptr_t, strrefs, args->strrefs);
    ARRCAST(kptr_t, curCand, args->cur);
    ARRCAST(kptr_t, prevCand, args->prev);
    STEP_MEM(uint32_t, mem, ptr, size, 2)
    {
        adr_t     *adr = (adr_t*    )(mem + 0);
        add_imm_t *add = (add_imm_t*)(mem + 1);
        if
        (
            (is_adr(adr)  && is_nop(mem + 1) && adr->Rd == 1) ||
            (is_adrp(adr) && is_add_imm(add) && adr->Rd == add->Rn && add->Rd == 1)
        )
        {
            kptr_t refloc = (uintptr_t)mem - (uintptr_t)ptr + addr,
                   ref    = refloc;
            if(is_adrp(adr))
            {
                ref &= ~0xfff;
                ref += get_add_sub_imm(add);
            }
            ref += get_adr_off(adr);
            for(size_t i = 0; i < strrefs->idx; ++i)
            {
                if(ref == strrefs->val[i])
                {
                    DBG(1, "Found ref to \"%s\" at " ADDR, args->str, refloc);
                    goto look_for_bl;
                }
            }
            continue;
        look_for_bl:;
            STEP_MEM(uint32_t, m, mem + 2, size - ((uintptr_t)(mem + 2) - (uintptr_t)ptr), 1)
            {
                kptr_t bladdr = (uintptr_t)m - (uintptr_t)ptr + addr,
                       blref  = bladdr;
                bl_t *bl = (bl_t*)m;
                if(is_bl(bl))
                {
                    a64_state_t state;
                    if(a64_emulate(args->macho, &state, mem, &a64cb_check_equal, (void*)m, true, true, kEmuFnIgnore) != kEmuEnd)
                    {
                        // a64_emulate should've printed error already
                        goto skip;
                    }
                    if(!(state.valid & (1 << 1)) || !(state.wide & (1 << 1)) || state.x[1] != ref)
                    {
                        DBG(1, "Value of x1 changed, skipping...");
                        goto skip;
                    }
                    blref += get_bl_off(bl);
                    DBG(1, "Considering constructor " ADDR, blref);
                    size_t idx = -1;
                    for(size_t i = 0; i < curCand->idx; ++i)
                    {
                        if(curCand->val[i] == blref)
                        {
                            idx = i;
                            break;
                        }
                    }
                    // If we have this already, just skip
                    if(idx == -1)
                    {
                        // first iteration: collect
                        // subsequent iterations: eliminate
                        if(!args->first)
                        {
                            idx = -1;
                            for(size_t i = 0; i < prevCand->idx; ++i)
                            {
                                if(prevCand->val[i] == blref)
                                {
                                    idx = i;
                                    break;
                                }
                            }
                            if(idx == -1)
                            {
                                DBG(1, "Candidate " ADDR " not in prev list.", bladdr);
                                goto skip;
                            }
                        }
                        ARRPUSH(*curCand, blref);
                    }
                    goto skip;
                }
                else if(!is_linear_inst(m))
                {
                    WRN("Unexpected instruction at " ADDR, bladdr);
                    goto skip;
                }
            }
            ERR("Reached end of segment without finding bl from " ADDR, refloc);
            return false;
        }
    skip:;
    }
    return true;
}

typedef struct
{
    kptr_t OSMetaClassMetaClass;
    kptr_t OSObjectGetMetaClass;
} getMetaClass_args_t;

static bool getMetaClass_cb(const void *ptr, kptr_t addr, size_t size, uint32_t prot, void *arg)
{
    if(!(prot & VM_PROT_EXECUTE))
    {
        return true;
    }
    getMetaClass_args_t *args = arg;
    STEP_MEM(uint32_t, mem, ptr, size, 3)
    {
        const adr_t     *adr = (const adr_t*    )(mem + 0);
        const add_imm_t *add = (const add_imm_t*)(mem + 1);
        const ret_t     *ret = (const ret_t*    )(mem + 2);
        if
        (
            is_ret(ret) &&
            (
                (is_adr(adr) && is_nop(mem + 1) && adr->Rd == 0) ||
                (is_adrp(adr) && is_add_imm(add) && adr->Rd == add->Rn && add->Rd == 0)
            )
        )
        {
            kptr_t refloc = (uintptr_t)mem - (uintptr_t)ptr + addr,
                   ref    = refloc;
            if(is_adrp(adr))
            {
                ref &= ~0xfff;
                ref += get_add_sub_imm(add);
            }
            ref += get_adr_off(adr);
            if(ref == args->OSMetaClassMetaClass)
            {
                if((uintptr_t)mem > (uintptr_t)ptr && is_bti((const bti_t*)(mem - 1)))
                {
                    refloc -= sizeof(uint32_t);
                }
                if(args->OSObjectGetMetaClass == -1)
                {
                    ERR("More than one candidate for OSMetaClass::getMetaClass: " ADDR, refloc);
                }
                else if(args->OSObjectGetMetaClass != 0)
                {
                    ERR("More than one candidate for OSMetaClass::getMetaClass: " ADDR, args->OSObjectGetMetaClass);
                    ERR("More than one candidate for OSMetaClass::getMetaClass: " ADDR, refloc);
                    args->OSObjectGetMetaClass = -1;
                }
                else
                {
                    DBG(1, "OSMetaClass::getMetaClass: " ADDR, refloc);
                    args->OSObjectGetMetaClass = refloc;
                }
            }
        }
    }
    return true;
}

typedef struct
{
    macho_t *macho;
    void *strref;
    kptr_t *pure_virtual;
} pure_virtual_args_t;

static bool pure_virtual_cb(const void *ptr, kptr_t addr, size_t size, uint32_t prot, void *arg)
{
    if(!(prot & VM_PROT_EXECUTE))
    {
        return true;
    }
    pure_virtual_args_t *args = arg;
    ARRCAST(kptr_t, strref, args->strref);

    STEP_MEM(uint32_t, mem, ptr, size, 5) // TODO: 6
    {
#if 0
        adr_t      *adr1 = (adr_t*     )(mem + 0);
        add_imm_t  *add1 = (add_imm_t* )(mem + 1);
        str_imm_t  *stri = (str_imm_t* )(mem + 2);
        str_uoff_t *stru = (str_uoff_t*)(mem + 2);
        adr_t      *adr2 = (adr_t*     )(mem + 3);
        add_imm_t  *add2 = (add_imm_t* )(mem + 4);
        bl_t       *bl   = (bl_t*      )(mem + 5);
        if
        (
            is_bl(bl) &&
            (
                (is_adr(adr2)  && is_nop(mem + 4)  && adr2->Rd == 0) ||
                (is_adrp(adr2) && is_add_imm(add2) && adr2->Rd == add2->Rn && add2->Rd == 0)
            ) &&
            (
                (is_str_uoff(stru) && stru->Rn == 31 && get_str_uoff(stru) == 0) ||
                (is_str_pre(stri)  && stri->Rn == 31)
            ) &&
            (
                // stri and stru have Rt and Rn at same offsets
                (is_adr(adr1)  && is_nop(mem + 1)  && adr1->Rd == stru->Rt) ||
                (is_adrp(adr1) && is_add_imm(add1) && adr1->Rd == add1->Rn && add1->Rd == stru->Rt)
            )
        )
#endif
        adr_t      *adr1 = (adr_t*     )(mem + 0);
        add_imm_t  *add1 = (add_imm_t* )(mem + 1);
        adr_t      *adr2 = (adr_t*     )(mem + 3);
        add_imm_t  *add2 = (add_imm_t* )(mem + 4);
        if
        (
            (is_adr(adr1)  && is_nop((uint32_t*)add1)) ||
            (is_adrp(adr1) && is_add_imm(add1) && adr1->Rd == add1->Rn)
        )
        {
            kptr_t refloc = (uintptr_t)mem - (uintptr_t)ptr + addr,
                   ref1   = refloc,
                   ref2   = refloc + 3 * sizeof(uint32_t);
            if(is_adrp(adr1))
            {
                ref1 &= ~0xfff;
                ref1 += get_add_sub_imm(add1);
            }
            ref1 += get_adr_off(adr1);
            for(size_t i = 0; i < strref->idx; ++i)
            {
                if(ref1 == strref->val[i])
                {
                    DBG(1, "Found ref to \"__cxa_pure_virtual\" at " ADDR, refloc);
                    goto ref_matches;
                }
            }
            continue;

        ref_matches:;
            for(size_t i = 0, bound = (const uint32_t*)((uintptr_t)ptr + size) - (const uint32_t*)adr2, max = bound > 5 ? 5 : bound; i < max; ++i)
            {
                if
                (
                    (is_adr(adr2)  && is_nop((uint32_t*)add2) && adr2->Rd == 0) ||
                    (is_adrp(adr2) && is_add_imm(add2)        && adr2->Rd == add2->Rn && add2->Rd == 0)
                )
                {
                    goto x0_matches;
                }
                ++adr2;
                ++add2;
                ref2 += sizeof(uint32_t);
            }
            DBG(1, "__cxa_pure_virtual: failed to find adr(p) x0");
            continue;

        x0_matches:;
            if(is_adrp(adr2))
            {
                ref2 &= ~0xfff;
                ref2 += get_add_sub_imm(add2);
            }
            ref2 += get_adr_off(adr2);
            const char *x0 = macho_vtop(args->macho, ref2, 0);
            if(strcmp(x0, "\"%s\"") != 0 && strcmp(x0, "%s @%s:%d") != 0)
            {
                DBG(1, "__cxa_pure_virtual: x0 != \"%%s\" && x0 != %%s @%%s:%%d");
                continue;
            }

            add_imm_t *add = (add_imm_t*)(mem - 1);
            for(size_t i = 0, bound = (const uint32_t*)add - (const uint32_t*)ptr, max = bound > 5 ? 5 : bound; i < max; ++i)
            {
                if(is_add_imm(add) && add->Rd == 29 && add->Rn == 31) // ignore add amount
                {
                    goto x29_matches;
                }
                --add;
            }
            DBG(1, "__cxa_pure_virtual: add x29, sp, ...");
            continue;

        x29_matches:;
            uint32_t *loc = (uint32_t*)add;
            refloc -= (mem - loc) * sizeof(uint32_t);

            stp_t *stp = (stp_t*)(loc - 1);
            if(!((is_stp_uoff(stp) || is_stp_pre(stp)) && stp->Rt == 29 && stp->Rt2 == 30 && stp->Rn == 31))
            {
                DBG(1, "__cxa_pure_virtual: stp x29, x30, [sp, ...]");
                continue;
            }
            loc--;
            refloc -= sizeof(uint32_t);

            if(is_stp_uoff(stp))
            {
                sub_imm_t *sub = (sub_imm_t*)(loc - 1);
                if(!(is_sub_imm(sub) && sub->Rd == 31 && sub->Rn == 31))
                {
                    DBG(1, "__cxa_pure_virtual: sub sp, sp, ...");
                    continue;
                }
                loc--;
                refloc -= sizeof(uint32_t);
            }
            pacsys_t *pac = (pacsys_t*)(loc - 1);
            if(is_pacsys(pac))
            {
                loc--;
                refloc -= sizeof(uint32_t);
            }
            if(*args->pure_virtual == -1)
            {
                DBG(1, "__cxa_pure_virtual candidate: " ADDR, refloc);
            }
            else if(*args->pure_virtual != 0)
            {
                DBG(1, "__cxa_pure_virtual candidate: " ADDR, *args->pure_virtual);
                DBG(1, "__cxa_pure_virtual candidate: " ADDR, refloc);
                *args->pure_virtual = -1;
            }
            else
            {
                *args->pure_virtual = refloc;
            }
        }
    }
    return true;
}

typedef struct
{
    macho_t *macho;
    //void *candidates;
    size_t VtabGetMetaClassIdx;
    metaclass_t *meta;
    kptr_t func;
} vtab_via_getMetaClass_ptr_args_t;

static bool vtab_via_getMetaClass_ptr_cb(const kptr_t *ptr, void *arg)
{
    vtab_via_getMetaClass_ptr_args_t *args = arg;
    //ARRCAST(kptr_t, candidates, args->candidates);
    size_t VtabGetMetaClassIdx = args->VtabGetMetaClassIdx;
    metaclass_t *meta = args->meta;

    bool bind = false;
    kptr_t addr = macho_fixup(args->macho, *ptr, &bind, NULL, NULL, NULL);
    if(!bind && addr == args->func)
    {
        const void *segptr = NULL;
        kptr_t segaddr = 0;
        size_t segsize = 0;
        if(!macho_segment_for_ptr(args->macho, ptr, &segptr, &segaddr, &segsize, NULL))
        {
            ERR("%s::getMetaClass vtable ptr is not in any segment.", meta->name);
            return false;
        }
        kptr_t ref = (uintptr_t)(ptr - VtabGetMetaClassIdx) - (uintptr_t)segptr + segaddr;
        if((uintptr_t)ptr - (uintptr_t)segptr < (VtabGetMetaClassIdx + 2) * sizeof(kptr_t))
        {
            ERR("%s::getMetaClass vtable ptr too close to start of segment (" ADDR ").", meta->name, ref);
            return false;
        }
        if(ptr[-(VtabGetMetaClassIdx + 1)] != 0x0 || ptr[-(VtabGetMetaClassIdx + 2)] != 0x0)
        {
            ERR("%s::getMetaClass vtable ptr vtable not preceded by zero ptrs (" ADDR ").", meta->name, ref);
            return false;
        }

        if(meta->vtab == 0)
        {
            meta->vtab = ref;
        }
        else
        {
            if(meta->vtab != -1)
            {
                DBG(1, "More than one vtab for %s: " ADDR, meta->name, meta->vtab);
                //ARRPUSH(candidates, meta->vtab);
                meta->vtab = -1;
            }
            DBG(1, "More than one vtab for %s: " ADDR, meta->name, ref);
            //ARRPUSH(candidates, ref);
        }
    }
    return true;
}

typedef struct
{
    macho_t *macho;
    void *metas;
    //void *candidates;
    size_t VtabGetMetaClassIdx;
    kptr_t OSMetaClassMetaClass;
} vtab_via_getMetaClass_args_t;

static bool vtab_via_getMetaClass_cb(const void *ptr, kptr_t addr, size_t size, uint32_t prot, void *arg)
{
    if(!(prot & VM_PROT_EXECUTE))
    {
        return true;
    }
    vtab_via_getMetaClass_args_t *args = arg;
    ARRCAST(metaclass_t, metas, args->metas);
    //ARRCAST(kptr_t, candidates, args->candidates);

    STEP_MEM(uint32_t, mem, ptr, size, 2)
    {
        adr_t *adr = (adr_t*)mem;
        add_imm_t *add = (add_imm_t*)(mem + 1);
        add_imm_t *add2 = (add_imm_t*)(mem + 2);
        nop_t *nop = (nop_t*)(mem + 1);
        ret_t *ret1 = (ret_t*)(mem + 1);
        ret_t *ret2 = (ret_t*)(mem + 2);
        ret_t *ret3 = (ret_t*)(mem + 3);
        bool iz_adrp = is_adrp(adr),
             iz_add  = is_add_imm(add);
        size_t nleft = (const uint32_t*)((uintptr_t)ptr + size) - mem;
        if
        (
            (nleft >= 3 && iz_adrp && iz_add && is_ret(ret2) && adr->Rd == add->Rn && add->Rd == 0) ||
            (is_adr(adr) && (is_ret(ret1) || (nleft >= 3 && is_nop(nop) && is_ret(ret2))) && adr->Rd == 0) ||
            (nleft >= 4 && is_ret(ret3) && is_add_imm(add2) && iz_add && iz_adrp && add2->Rd == 0 && add2->Rn == add->Rd && adr->Rd == add->Rn) // iOS 9
        )
        {
            kptr_t func = (uintptr_t)mem - (uintptr_t)ptr + addr,
                   ref  = func;
            if((uintptr_t)mem > (uintptr_t)ptr && is_bti((const bti_t*)&mem[-1]))
            {
                func -= sizeof(uint32_t);
            }
            if(iz_adrp)
            {
                ref &= ~0xfff;
            }
            ref += get_adr_off(adr);
            if(iz_add)
            {

                ref += get_add_sub_imm(add);
                if(is_add_imm(add2))
                {
                    ref += get_add_sub_imm(add2);
                }
            }
            if(ref == args->OSMetaClassMetaClass)
            {
                continue;
            }
            for(size_t i = 0; i < metas->idx; ++i)
            {
                metaclass_t *meta = &metas->val[i];
                if(meta->addr != ref)
                {
                    continue;
                }
                DBG(1, "Got func " ADDR " referencing MetaClass %s", func, meta->name);
                //args->candidates.idx = 0;
                if(!meta->vtab)
                {
                    vtab_via_getMetaClass_ptr_args_t ptr_args =
                    {
                        .macho = args->macho,
                        //.candidates = candidates,
                        .VtabGetMetaClassIdx = args->VtabGetMetaClassIdx,
                        .meta = meta,
                        .func = func,
                    };
                    if(!macho_foreach_ptr(args->macho, &vtab_via_getMetaClass_ptr_cb, &ptr_args))
                    {
                        return false;
                    }
                }
                break;
            }
        }
    }
    return true;
}

static void print_help(const char *self)
{
    fprintf(stderr, "Usage:\n"
                    "    %s [-aAbBCdeGilmMnoOpRsSvz] [ClassName] [OverrideName] [BundleName] kernel [SymbolMap]\n"
                    "\n"
                    "Description:\n"
                    "    Extract and print C++ class information from an arm64 iOS kernel.\n"
                    "    Flags (those with the -) may be given in any order, the other arguments\n"
                    "    must be given in the order shown above. Class and bundle name filters\n"
                    "    need not be the full names, substrings will match too.\n"
                    "\n"
                    "Print options:\n"
                    "    -a  Synonym for -bmsv\n"
                    "    -A  Synonym for -bimosv\n"
                    "    -b  Print bundle identifier\n"
                    "    -i  Print inherited virtual methods (implies -o)\n"
                    "    -l  Print OSMetaClass subclasses\n"
                    "    -m  Print OSMetaClass addresses\n"
                    "    -M  Print symbol map (implies -o, takes precedence)\n"
                    "    -MM Same as above, and copy input map for missing classes\n"
                    "    -o  Print overridden/new virtual methods\n"
                    "    -R  Print symbols for radare2 (implies -lmov, takes precedence)\n"
                    "    -s  Print object sizes\n"
                    "    -v  Print object vtabs\n"
                    "    -z  Print mangled symbols\n"
                    "\n"
                    "Filter options:\n"
                    "    -B  Filter by bundle identifier (kext)\n"
                    "    -C  Filter by class name\n"
                    "    -e  Filter extending ClassName (implies -C)\n"
                    "    -O  Filter by name of overridden method\n"
                    "    -p  Filter parents of ClassName (implies -C)\n"
                    "\n"
                    "Other options:\n"
                    "    -d  Increase debug output level\n"
                    "    -G  Sort (group) by bundle identifier\n"
                    "    -n  Disable color output\n"
                    "    -S  Sort by class name\n"
                    , self);
}

int main(int argc, const char **argv)
{
    int r;
    opt_t opt =
    {
        .bundle    = 0,
        .bfilt     = 0,
        .cfilt     = 0,
        .bsort     = 0,
        .csort     = 0,
        .extend    = 0,
        .inherit   = 0,
        .meta      = 0,
        .metaclass = 0,
        .maxmap    = 0,
        .overrides = 0,
        .ofilt     = 0,
        .parent    = 0,
        .size      = 0,
        .symmap    = 0,
        .vtab      = 0,
        .mangle    = 0,
        ._reserved = 0,
    };
    const char *filt_class    = NULL,
               *filt_bundle   = NULL,
               *filt_override = NULL;
    print_t *print = NULL;

    int aoff = 1;
    for(; aoff < argc; ++aoff)
    {
        if(argv[aoff][0] != '-')
        {
            break;
        }
        for(size_t i = 1; argv[aoff][i] != '\0'; ++i)
        {
            switch(argv[aoff][i])
            {
                case 'd':
                {
                    ++debug;
                    break;
                }
                case 'a':
                {
                    opt.bundle = 1;
                    opt.meta   = 1;
                    opt.size   = 1;
                    opt.vtab   = 1;
                    break;
                }
                case 'A':
                {
                    opt.bundle    = 1;
                    opt.inherit   = 1;
                    opt.meta      = 1;
                    opt.overrides = 1;
                    opt.size      = 1;
                    opt.vtab      = 1;
                    break;
                }
                case 'b':
                {
                    opt.bundle = 1;
                    break;
                }
                case 'B':
                {
                    opt.bfilt = 1;
                    break;
                }
                case 'C':
                {
                    opt.cfilt = 1;
                    break;
                }
                case 'e':
                {
                    opt.extend = 1;
                    opt.cfilt  = 1;
                    break;
                }
                case 'G':
                {
                    opt.bsort = 1;
                    break;
                }
                case 'i':
                {
                    opt.inherit   = 1;
                    opt.overrides = 1;
                    break;
                }
                case 'l':
                {
                    opt.metaclass = 1;
                    break;
                }
                case 'm':
                {
                    opt.meta = 1;
                    break;
                }
                case 'M':
                {
                    if(opt.symmap)
                    {
                        opt.maxmap = 1;
                    }
                    opt.overrides = 1;
                    opt.symmap    = 1;
                    break;
                }
                case 'n':
                {
                    colorGray   = "";
                    colorRed    = "";
                    colorYellow = "";
                    colorBlue   = "";
                    colorPink   = "";
                    colorCyan   = "";
                    colorReset  = "";
                    break;
                }
                case 'o':
                {
                    opt.overrides = 1;
                    break;
                }
                case 'O':
                {
                    opt.ofilt = 1;
                    break;
                }
                case 'p':
                {
                    opt.parent = 1;
                    opt.cfilt  = 1;
                    break;
                }
                case 'R':
                {
                    if(print && print != &radare2_print)
                    {
                        ERR("TODO");
                        return -1;
                    }
                    print = &radare2_print;
                    opt.meta      = 1;
                    opt.metaclass = 1;
                    opt.overrides = 1;
                    opt.vtab      = 1;
                    break;
                }
                case 's':
                {
                    opt.size = 1;
                    break;
                }
                case 'S':
                {
                    opt.csort = 1;
                    break;
                }
                case 'v':
                {
                    opt.vtab = 1;
                    break;
                }
                case 'z':
                {
                    opt.mangle = 1;
                    break;
                }
                default:
                {
                    ERR("Unrecognised option: -%c", argv[aoff][i]);
                    fputs("\n", stderr);
                    print_help(argv[0]);
                    return -1;
                }
            }
        }
    }

    bool have_symmap = false;
    int wantargs = 1 + (opt.bfilt ? 1 : 0) + (opt.cfilt ? 1 : 0) + (opt.ofilt ? 1 : 0);
    if(argc - aoff == wantargs + 1)
    {
        ++wantargs;
        have_symmap = true;
    }
    if(argc - aoff != wantargs)
    {
        if(argc > 1)
        {
            ERR("Too %s arguments.", (argc - aoff < wantargs) ? "few" : "many");
            fputs("\n", stderr);
        }
        else
        {
            fprintf(stderr, "iometa"
#ifdef VERSION
                            " v" STRINGIFY(VERSION)
#endif
#ifdef TIMESTAMP
                            ", compiled on " STRINGIFY(TIMESTAMP)
#endif
                            "\n\n"
            );
        }
        print_help(argv[0]);
        return -1;
    }

    if(opt.symmap && (opt.bfilt || opt.cfilt || opt.ofilt || opt.bsort || opt.csort || opt.extend || opt.parent || opt.mangle))
    {
        ERR("Cannot use filters, sorting or mangling with -M.");
        return -1;
    }
    if(opt.symmap && print)
    {
        ERR("Only one of -M or -R may be given.");
        return -1;
    }
    if(opt.extend && opt.parent)
    {
        ERR("Only one of -e or -p may be given.");
        return -1;
    }
    if(opt.bsort && opt.csort)
    {
        ERR("Only one of -G or -S may be given.");
        return -1;
    }

    if(!opt.symmap && !print)
    {
        print = &iometa_print;
    }
    if(opt.cfilt)
    {
        filt_class = argv[aoff++];
    }
    if(opt.ofilt)
    {
        filt_override = argv[aoff++];
    }
    if(opt.bfilt)
    {
        filt_bundle = argv[aoff++];
    }
    bool want_vtabs = opt.vtab || opt.overrides || opt.ofilt;

    macho_t *macho = macho_open(argv[aoff++]);
    if(!macho) return -1;

    symmap_t symmap = { 0, NULL };
    if(have_symmap)
    {
        void *symmapMem = NULL;
        size_t symmmapLen = 0;
        r = map_file(argv[aoff++], PROT_READ | PROT_WRITE, &symmapMem, &symmmapLen);
        if(r != 0) return r;
        r = parse_symmap(symmapMem, symmmapLen, &symmap);
        if(r != 0) return r;
    }

    ARRDEF(kptr_t, aliases, NUM_KEXTS_EXPECT);
    ARRDEF(kptr_t, altaliases, NUM_KEXTS_EXPECT);

    // TODO: generalise OSObjectVtab & OSObjectGetMetaClass names?
    kptr_t OSMetaClassConstructor = 0,
           OSMetaClassAltConstructor = 0,
           OSMetaClassVtab = 0,
           OSObjectVtab = 0,
           OSObjectGetMetaClass = 0,
           pure_virtual = 0;

    if(macho_have_symbols(macho))
    {
        if(macho_is_kext(macho))
        {
            OSMetaClassConstructor    = macho_symbol(macho, "__ZN11OSMetaClassC2EPKcPKS_j.stub");
            OSMetaClassAltConstructor = macho_symbol(macho, "__ZN11OSMetaClassC2EPKcPKS_jPP4zoneS1_19zone_create_flags_t.stub");
        }
        else
        {
            OSMetaClassConstructor    = macho_symbol(macho, "__ZN11OSMetaClassC2EPKcPKS_j");
            OSMetaClassAltConstructor = macho_symbol(macho, "__ZN11OSMetaClassC2EPKcPKS_jPP4zoneS1_19zone_create_flags_t");
            OSMetaClassVtab           = macho_symbol(macho, "__ZTV11OSMetaClass");
            OSObjectVtab              = macho_symbol(macho, "__ZTV8OSObject");
            OSObjectGetMetaClass      = macho_symbol(macho, "__ZNK8OSObject12getMetaClassEv");
            if(OSMetaClassVtab)
            {
                OSMetaClassVtab += 2 * sizeof(kptr_t);
                DBG(1, "OSMetaClassVtab: " ADDR, OSMetaClassVtab);
            }
            if(OSObjectVtab)
            {
                OSObjectVtab += 2 * sizeof(kptr_t);
                DBG(1, "OSObjectVtab: " ADDR, OSObjectVtab);
            }
            if(OSObjectGetMetaClass)
            {
                DBG(1, "OSObjectGetMetaClass: " ADDR, OSObjectGetMetaClass);
            }
        }
        if(OSMetaClassConstructor)
        {
            DBG(1, "OSMetaClassConstructor: " ADDR, OSMetaClassConstructor);
        }
        if(OSMetaClassAltConstructor)
        {
            DBG(1, "OSMetaClassAltConstructor: " ADDR, OSMetaClassAltConstructor);
        }
    }

    if(!OSMetaClassConstructor)
    {
        if(macho_is_kext(macho))
        {
            DBG(1, "Failed to find OSMetaClassConstructor symbol, trying relocation instead.");
            OSMetaClassConstructor = find_stub_for_reloc(macho, "__ZN11OSMetaClassC2EPKcPKS_j");
        }
        else
        {
            DBG(1, "Failed to find OSMetaClassConstructor symbol, falling back to binary matching.");
            const char *strs[] = { "IORegistryEntry", "IOService", "IOUserClient" };
#define NSTRREF (sizeof(strs)/sizeof(strs[0]))
            ARRDECL(kptr_t, strrefs)[NSTRREF];
            for(size_t i = 0; i < NSTRREF; ++i)
            {
                ARRINIT(strrefs[i], 4);
                if(!find_str(macho, &strrefs[i], strs[i]))
                {
                    return -1;
                }
                if(strrefs[i].idx == 0)
                {
                    ERR("Failed to find string: %s", strs[i]);
                    return -1;
                }
            }
            ARRDECL(kptr_t, constrCand)[2];
            ARRINIT(constrCand[0], 4);
            ARRINIT(constrCand[1], 4);
            size_t constrIdx = 0;
#define constrCandPrev (constrCand[(constrIdx - 1) % 2])
#define constrCandCurr (constrCand[constrIdx % 2])
            for(size_t j = 0; j < NSTRREF; ++j)
            {
                ++constrIdx;
                constrCandCurr.idx = 0;
                OSMetaClassConstructor_args_t args =
                {
                    .macho = macho,
                    .prev = &constrCandPrev,
                    .cur = &constrCandCurr,
                    .strrefs = &strrefs[j],
                    .str = strs[j],
                    .first = j != 0,
                };
                if(!macho_foreach_map(macho, &OSMetaClassConstructor_cb, &args))
                {
                    return -1;
                }
            }
            if(constrCandCurr.idx > 1)
            {
                ERR("Found more than one possible OSMetaClassConstructor.");
                return -1;
            }
            else if(constrCandCurr.idx == 1)
            {
                OSMetaClassConstructor = constrCandCurr.val[0];
                ARRFREE(constrCand[0]);
                ARRFREE(constrCand[1]);
                for(size_t i = 0; i < NSTRREF; ++i)
                {
                    ARRFREE(strrefs[i]);
                }
            }
            // else fall through to below
#undef constrCandPrev
#undef constrCandCurr
#undef NSTRREF
        }
        if(!OSMetaClassConstructor)
        {
            ERR("Failed to find OSMetaClassConstructor.");
            return -1;
        }
        DBG(1, "OSMetaClassConstructor: " ADDR, OSMetaClassConstructor);
    }
    ARRPUSH(aliases, OSMetaClassConstructor);

    if(!find_imports(macho, &aliases, OSMetaClassConstructor))
    {
        return -1;
    }

    ARRDEF(metaclass_t, metas, NUM_METACLASSES_EXPECT);
    ARRDEF(metaclass_candidate_t, namelist, 2 * NUM_METACLASSES_EXPECT);
    metaclass_t *OSMetaClass = NULL;

    if(!find_meta_constructor_calls(macho, want_vtabs, &aliases, &metas, &namelist, &meta_constructor_cb, OSMetaClassAltConstructor ? NULL : &OSMetaClassAltConstructor))
    {
        return -1;
    }
    if(OSMetaClassAltConstructor)
    {
        ARRPUSH(altaliases, OSMetaClassAltConstructor);
        if(!find_imports(macho, &altaliases, OSMetaClassAltConstructor))
        {
            return -1;
        }
        if(!find_meta_constructor_calls(macho, want_vtabs, &altaliases, &metas, &namelist, &meta_alt_constructor_cb, NULL))
        {
            return -1;
        }
    }

    // This is a safety check to try and detect metaclass names that we see, but don't end up finding constructors for
    DBG(1, "Got %lu names (probably a ton of dupes)", namelist.idx);
    qsort(namelist.val, namelist.idx, sizeof(*namelist.val), &compare_meta_candidates);
    for(size_t i = 0; i < namelist.idx; ++i)
    {
        metaclass_candidate_t *current = &namelist.val[i];
        if(i > 0)
        {
            // compare_meta_candidates() sorts entries without fncall last, and we set it to NULL if it got us nowhere,
            // so if we have duplicate names and we either lack a fncall or prev still has its one, we can safely skip.
            metaclass_candidate_t *prev = &namelist.val[i - 1];
            if(strcmp(current->name, prev->name) == 0 && (prev->fncall || !current->fncall))
            {
                continue;
            }
        }
        for(size_t j = 0; j < metas.idx; ++j)
        {
            if(strcmp(current->name, metas.val[j].name) == 0)
            {
                goto onward;
            }
        }
        if(current->fncall)
        {
            void *sp = malloc(A64_EMU_SPSIZE),
                 *bitstr = malloc((A64_EMU_SPSIZE + 31) / 32);
            if(!sp || !bitstr)
            {
                ERR("malloc(sp) || malloc(bitstr)");
                return -1;
            }
            a64_state_t state;
            bool success = multi_call_emulate(macho, current->fncall, current->fncall, &state, sp, bitstr, 0xf, current->name);
            if(success)
            {
                kptr_t bladdr = macho_ptov(macho, current->fncall);
                if((state.wide & 0xf) != 0x7)
                {
                    WRN("Skipping constructor call with unexpected registers width (%x) at " ADDR, state.wide, bladdr);
                    // Fall through
                }
                else
                {
                    DBG(1, "Processing triaged constructor call at " ADDR " (%s)", bladdr, current->name);
                    add_metaclass(macho, &metas, &state, current->fncall, want_vtabs);
                    free(sp);
                    goto onward;
                }
            }
            free(sp);
            free(bitstr);
            current->fncall = NULL;
            // This is annoying now, but we need to make sure we only print one warning per class.
            if(i + 1 < namelist.idx)
            {
                metaclass_candidate_t *next = &namelist.val[i + 1];
                if(strcmp(current->name, next->name) == 0 && next->fncall)
                {
                    goto onward;
                }
            }
        }
        WRN("Failed to find MetaClass constructor for %s", current->name);
        onward:;
    }
    ARRFREE(namelist);

    DBG(1, "Got %lu metaclasses", metas.idx);
    for(size_t i = 0; i < metas.idx; ++i)
    {
        metaclass_t *meta = &metas.val[i];
        if(meta->parent == 0)
        {
            continue;
        }
        for(size_t j = 0; j < metas.idx; ++j)
        {
            metaclass_t *parent = &metas.val[j];
            if(parent->addr == meta->parent)
            {
                meta->parentP = parent;
                break;
            }
        }
        if(!meta->parentP)
        {
            ERR("Failed to find parent of %s (m: " ADDR ", p: " ADDR ")", meta->name, meta->addr, meta->parent);
            return -1;
        }
    }
    for(size_t i = 0; i < metas.idx; ++i)
    {
        metaclass_t *meta = &metas.val[i];
        if(meta->vtab != 0)
        {
            // Propagate through entire hierarchy
            for(metaclass_t *p = meta->parentP; p; p = p->parentP)
            {
                if(p->vtab || p->has_dependents)
                {
                    break;
                }
                p->has_dependents = 1;
            }
        }
    }

    if(want_vtabs)
    {
        metaclass_t *metaclassHandle = NULL;
        kptr_t OSMetaClassMetaClass = 0;
        for(size_t i = 0; i < metas.idx; ++i)
        {
            if(strcmp(metas.val[i].name, "OSMetaClass") == 0)
            {
                if(OSMetaClassVtab)
                {
                    metas.val[i].vtab = OSMetaClassVtab;
                }
                OSMetaClassMetaClass = metas.val[i].addr;
                metaclassHandle = &metas.val[i];
                break;
            }
        }

        if(macho_is_kext(macho))
        {
            size_t n = 0;
            const sym_t *sym = macho_symbols_for_prefix(macho, "__ZTV", &n);
            for(size_t i = 0; i < n; ++i)
            {
                // Despite all appearances, this is actually proper
                const char *ztv = sym[i].name + 5;
                size_t zlen = strlen(ztv);
                if(ztv[0] == 'N')
                {
                    if(zlen < 6 || ztv[zlen - 1] != 'E')
                    {
                        WRN("Bad vtab symbol name: %s", sym[i].name);
                        continue;
                    }
                    ++ztv;
                    zlen -= 2;
                }
                char buf[512];
                if(snprintf(buf, sizeof(buf), "__ZNK%.*s12getMetaClassEv", (int)zlen, ztv) >= sizeof(buf))
                {
                    WRN("Class name too big for buffer: %s", sym[i].name);
                    continue;
                }
                kptr_t znk = macho_symbol(macho, buf);
                if(!znk)
                {
                    continue;
                }
                OSObjectVtab = sym[i].addr + 2 * sizeof(kptr_t);
                OSObjectGetMetaClass = znk;
                DBG(1, "%s: " ADDR, sym[i].name, OSObjectVtab);
                DBG(1, "%s: " ADDR, buf, OSObjectGetMetaClass);
                break;
            }
        }
        else
        {
            if((metaclassHandle && !metaclassHandle->vtab) || !OSObjectVtab)
            {
                DBG(1, "Missing OSMetaClass vtab, falling back to binary matching.");
                const void *segptr = NULL;
                kptr_t segaddr = 0;
                size_t segsize = 0;
                if(!macho_segment_for_addr(macho, OSMetaClassConstructor, &segptr, &segaddr, &segsize, NULL))
                {
                    ERR("Failed to find segment containing OSMetaClassConstructor");
                    return -1;
                }
                kptr_t offset = OSMetaClassConstructor - segaddr;
                const uint32_t *start = (const uint32_t*)((uintptr_t)segptr + offset);
                STEP_MEM(uint32_t, mem, (uintptr_t)start, segsize - offset, 1)
                {
                    str_uoff_t *str = (str_uoff_t*)mem;
                    if(is_str_uoff(str) && get_str_uoff(str) == 0)
                    {
                        a64_state_t state;
                        for(size_t i = 0; i < 32; ++i)
                        {
                            state.x[i] = 0;
                            state.q[i] = 0;
                        }
                        state.flags = 0;
                        state.valid = 1;
                        state.qvalid = 0;
                        state.wide = 1;
                        state.host = 0;
                        if(a64_emulate(macho, &state, start, &a64cb_check_equal, (void*)mem, false, true, kEmuFnIgnore) == kEmuEnd)
                        {
                            if(!(state.valid & (1 << str->Rn)) || !(state.wide & (1 << str->Rn)) || !(state.valid & (1 << str->Rt)) || !(state.wide & (1 << str->Rt)))
                            {
                                DBG(1, "Bad valid/wide flags (%x/%x)", state.valid, state.wide);
                            }
                            else
                            {
                                OSMetaClassVtab = state.x[str->Rt];
                                DBG(1, "OSMetaClassVtab " ADDR, OSMetaClassVtab);
                                if(metaclassHandle && !metaclassHandle->vtab)
                                {
                                    metaclassHandle->vtab = OSMetaClassVtab;
                                }
                            }
                        }
                        break;
                    }
                    if(!is_linear_inst(mem))
                    {
                        DBG(1, "Bailing out due to non-linear instr at " ADDR, OSMetaClassConstructor + ((uintptr_t)mem - (uintptr_t)start));
                        break;
                    }
                }
            }
            if(!OSObjectVtab && !OSObjectGetMetaClass && OSMetaClassMetaClass) // Must happen together
            {
                DBG(1, "Missing OSObject vtab and OSObject::getMetaClass, falling back to binary matching.");

                // vtab
                OSObjectVtab = OSMetaClassVtab;

                // getMetaClass
                getMetaClass_args_t args =
                {
                    .OSMetaClassMetaClass = OSMetaClassMetaClass,
                    .OSObjectGetMetaClass = OSObjectGetMetaClass,
                };
                if(!macho_foreach_map(macho, &getMetaClass_cb, &args))
                {
                    return -1;
                }
                OSObjectGetMetaClass = args.OSObjectGetMetaClass;
                if(OSObjectGetMetaClass == -1)
                {
                    OSObjectGetMetaClass = 0;
                }
            }
        }
        size_t VtabGetMetaClassIdx = 0;
        // block for variable scoping
        {
            if(!OSObjectVtab)
            {
                ERR("Failed to find OSObjectVtab.");
                return -1;
            }
            if(!OSObjectGetMetaClass)
            {
                ERR("Failed to find OSObjectGetMetaClass.");
                return -1;
            }
            const kptr_t *ovtab = macho_vtop(macho, OSObjectVtab, 0);
            if(!ovtab)
            {
                ERR("OSObjectVtab is not in any segment.");
                return -1;
            }
            for(size_t i = 0; check_vtab_elem(macho, 0, ovtab, OSObjectVtab, i) == kVtabFunc; ++i)
            {
                bool bind = false;
                if(macho_fixup(macho, ovtab[i], &bind, NULL, NULL, NULL) == OSObjectGetMetaClass)
                {
                    if(bind)
                    {
                        continue;
                    }
                    VtabGetMetaClassIdx = i;
                    DBG(1, "VtabGetMetaClassIdx: 0x%lx", VtabGetMetaClassIdx);
                    break;
                }
            }
            if(!VtabGetMetaClassIdx)
            {
                ERR("Failed to find OSObjectGetMetaClass in OSObjectVtab.");
                return -1;
            }
        }

        size_t VtabAllocIdx = 0;
        if(!macho_is_kext(macho))
        {
            pure_virtual = macho_symbol(macho, "___cxa_pure_virtual");
            if(!pure_virtual)
            {
                ARRDEF(kptr_t, strref, 4);
                if(!find_str(macho, &strref, "__cxa_pure_virtual"))
                {
                    return -1;
                }
                if(strref.idx == 0)
                {
                    DBG(1, "Failed to find string: __cxa_pure_virtual");
                }
                else
                {
                    DBG(1, "Found \"__cxa_pure_virtual\" %lu times", strref.idx);
                    pure_virtual_args_t args =
                    {
                        .macho = macho,
                        .strref = &strref,
                        .pure_virtual = &pure_virtual,
                    };
                    if(!macho_foreach_map(macho, &pure_virtual_cb, &args))
                    {
                        return -1;
                    }
                }
            }
            if(pure_virtual == -1)
            {
                WRN("Multiple __cxa_pure_virtual candidates!");
                pure_virtual = 0;
            }
            else if(pure_virtual)
            {
                DBG(1, "__cxa_pure_virtual: " ADDR, pure_virtual);
            }
            else
            {
                WRN("Failed to find __cxa_pure_virtual");
            }

            if(pure_virtual && OSMetaClassVtab)
            {
                const kptr_t *ovtab = macho_vtop(macho, OSMetaClassVtab, 0);
                if(!ovtab)
                {
                    ERR("OSMetaClassVtab is not in any segment.");
                    return -1;
                }
                for(size_t i = 0; check_vtab_elem(macho, 0, ovtab, OSObjectVtab, i) == kVtabFunc; ++i)
                {
                    if(macho_fixup(macho, ovtab[i], NULL, NULL, NULL, NULL) == pure_virtual)
                    {
                        VtabAllocIdx = i;
                        DBG(1, "VtabAllocIdx: 0x%lx", VtabAllocIdx);
                        break;
                    }
                }
                if(!VtabAllocIdx)
                {
                    ERR("Failed to find OSMetaClassAlloc in OSMetaClassVtab.");
                    return -1;
                }
            }
        }

        //ARRDEF(kptr_t, candidates, 0x100);
        vtab_via_getMetaClass_args_t args =
        {
            .macho = macho,
            .metas = &metas,
            //.candidates = candidates,
            .VtabGetMetaClassIdx = VtabGetMetaClassIdx,
            .OSMetaClassMetaClass = OSMetaClassMetaClass,
        };
        if(!macho_foreach_map(macho, &vtab_via_getMetaClass_cb, &args))
        {
            return -1;
        }
        //ARRFREE(candidates);

        if(VtabAllocIdx)
        {
            for(size_t i = 0; i < metas.idx; ++i)
            {
                metaclass_t *meta = &metas.val[i];
                if((meta->vtab != 0 && meta->vtab != 1) || !meta->metavtab)
                {
                    continue;
                }

                DBG(1, "Attempting to get vtab via %s::MetaClass::alloc", meta->name);
                const kptr_t *ovtab = macho_vtop(macho, meta->metavtab, 0);
                if(!ovtab)
                {
                    ERR("Metavtab of %s is not in any segment.", meta->name);
                    return -1;
                }
                kptr_t func = macho_fixup(macho, ovtab[VtabAllocIdx], NULL, NULL, NULL, NULL);
                if(func == pure_virtual)
                {
                    continue;
                }
                DBG(1, "Got %s::MetaClass::alloc at " ADDR, meta->name, func);
                const void *segptr = NULL;
                kptr_t segaddr = 0;
                size_t segsize = 0;
                if(!macho_segment_for_addr(macho, func, &segptr, &segaddr, &segsize, NULL))
                {
                    ERR("%s::MetaClass::alloc is not in any segment.", meta->name);
                    return -1;
                }

                const uint32_t *end     = (const uint32_t*)((uintptr_t)segptr + segsize),
                               *fnstart = (const uint32_t*)((uintptr_t)segptr + (func - segaddr));
                void *sp      = malloc(A64_EMU_SPSIZE),
                     *bitstr  = malloc((A64_EMU_SPSIZE + 31) / 32),
                     *obj     = NULL,
                     *obitstr = NULL;
                if(!sp || !bitstr)
                {
                    ERR("malloc(sp) || malloc(bitstr)");
                    return -1;
                }
                bzero(sp, A64_EMU_SPSIZE);
                bzero(bitstr, (A64_EMU_SPSIZE + 31) / 32);
                uint32_t *m = NULL;
                a64_state_t state;
                for(size_t j = 0; j < 32; ++j)
                {
                    state.x[j] = 0;
                    state.q[j] = 0;
                }
                // "fakemeta", fake "this" ptr
                #define FAKEMETAPTR 0x6174656d656b6166
                state.x[ 0]  = FAKEMETAPTR;
                state.x[31]  = (uintptr_t)sp + A64_EMU_SPSIZE;
                state.flags  = 0;
                state.valid  = 0xfff80001;
                state.qvalid = 0x0000ff00;
                state.wide   = 0xfff80001;
                state.host   = 0;
                HOST_SET(&state, 31, 1);
                state.hostmem[0].min = (uintptr_t)sp;
                state.hostmem[0].max = (uintptr_t)sp + A64_EMU_SPSIZE;
                state.hostmem[0].bitstring = bitstr;
                emu_ret_t emuret = a64_emulate(macho, &state, fnstart, &a64cb_check_bl, &m, false, true, kEmuFnIgnore);
            reswitch:;
                switch(emuret)
                {
                    case kEmuRet:
                        if((state.valid & 0x1) == 0x1 && (state.wide & 0x1) == 0x1 && state.x[0] == 0x0)
                        {
                            DBG(1, "Ignoring %s::MetaClass::alloc that returns NULL", meta->name);
                        }
                        else
                        {
                            WRN("Unexpected ret in %s::MetaClass::alloc", meta->name);
                        }
                        break;

                    case kEmuEnd:
                        {
                            if((state.valid & 0xff) == 0x1 && (state.wide & 0x1) == 0x1 && HOST_GET(&state, 0) == 0 && state.x[0] == FAKEMETAPTR) // OSValueObject indirection
                            {
                                DBG(1, "Hit OSValueObject, stepping into bl");
                                emuret = a64_emulate(macho, &state, m, &a64cb_check_equal, m + 1, false, true, kEmuFnEnter);
                                if(emuret == kEmuEnd)
                                {
                                    emuret = a64_emulate(macho, &state, m + 1, &a64cb_check_bl, &m, false, true, kEmuFnIgnore);
                                }
                                if(emuret != kEmuEnd)
                                {
                                    goto reswitch;
                                }
                            }
                            kptr_t allocsz;
                            if((state.valid & 0xff) == 0x7 && (state.wide & 0x7) == 0x5 && HOST_GET(&state, 0) == 1) // kalloc
                            {
                                allocsz = *(kptr_t*)state.x[0];
                            }
                            else if((state.valid & 0xff) == 0x1 && HOST_GET(&state, 0) == 0) // new
                            {
                                allocsz = state.x[0];
                            }
                            else if((state.valid & 0xff) == 0x3 && (state.wide & 0x3) == 0x1 && HOST_GET(&state, 0) == 0) // typed new
                            {
                                allocsz = state.x[1];
                                // TODO: check if x0 in __DATA_CONST.__kalloc_type
                                if(allocsz == 0x4) // kalloc type impl
                                {
                                    const struct
                                    {
                                        kptr_t zv_zone;
                                        kptr_t zv_stats;
                                        kptr_t zv_name;
                                        kptr_t zv_next;
                                        kptr_t kt_signature;
                                        uint32_t kt_flags;
                                        uint32_t kt_size;
                                        kptr_t unused1;
                                        kptr_t unused2;
                                    } *kt = macho_vtop(macho, state.x[0], sizeof(*kt));
                                    if(!kt)
                                    {
                                        WRN("kalloc type struct not in any segment in %s::MetaClass::alloc (" ADDR ")", meta->name, state.x[0]);
                                        break;
                                    }
                                    allocsz = kt->kt_size;
                                }
                            }
                            else if((state.valid & 0xff) == 0xf && (state.wide & 0xf) == 0x9 && HOST_GET(&state, 0) == 0) // hell do I know
                            {
                                allocsz = state.x[1];
                            }
                            else
                            {
                                //if(meta->vtab == -1)
                                {
                                    WRN("Bad pre-bl state in %s::MetaClass::alloc (%08x %08x %016llx)", meta->name, state.valid, state.wide, state.host);
                                }
                                break;
                            }
                            if(allocsz != meta->objsize)
                            {
                                //if(meta->vtab == -1)
                                {
                                    WRN("Alloc has wrong size in %s::MetaClass::alloc (0x%llx vs 0x%x)", meta->name, allocsz, meta->objsize);
                                }
                                break;
                            }
                            if(a64_emulate(macho, &state, m, &a64cb_check_equal, m + 1, false, true, kEmuFnIgnore) != kEmuEnd)
                            {
                                break;
                            }
                            obj = malloc(allocsz);
                            obitstr = malloc((allocsz + 31) / 32);
                            if(!obj || !obitstr)
                            {
                                ERR("malloc(obj) || malloc(obitstr)");
                                return -1;
                            }
                            bzero(obj, allocsz);
                            bzero(obitstr, (allocsz + 31) / 32);
                            state.x[0] = (uintptr_t)obj;
                            state.valid |= 0x1;
                            state.wide  |= 0x1;
                            HOST_SET(&state, 0, 2);
                            state.hostmem[1].min = (uintptr_t)obj;
                            state.hostmem[1].max = (uintptr_t)obj + allocsz;
                            state.hostmem[1].bitstring = obitstr;
                            uint32_t *e = m + 1;
                            for(; e < end; ++e)
                            {
                                if(is_ret(e))
                                {
                                    break;
                                }
                            }
                            if(a64_emulate(macho, &state, m + 1, &a64cb_check_equal, e, false, true, kEmuFnEnter) != kEmuEnd)
                            {
                                break;
                            }
                            if(!(state.valid & 0x1) || !(state.wide & 0x1) || !HOST_GET(&state, 0))
                            {
                                WRN("Bad end state in %s::MetaClass::alloc (%08x %08x %016llx)", meta->name, state.valid, state.wide, state.host);
                                break;
                            }
                            kptr_t vt = *(kptr_t*)state.x[0];
                            if(!vt)
                            {
                                WRN("Failed to capture vtab via %s::MetaClass::alloc", meta->name);
                                break;
                            }
                            meta->vtab = vt;
                        }
                        break;

                    default:
                        break;
                }
                if(obj) free(obj);
                if(obitstr) free(obitstr);
                free(sp);
                free(bitstr);
            }
        }
        for(size_t i = 0; i < metas.idx; ++i)
        {
            if(metas.val[i].vtab == -1)
            {
                WRN("Multiple vtab candidates for %s", metas.val[i].name);
            }
        }

        if(opt.overrides || opt.ofilt)
        {
            for(size_t i = 0; i < metas.idx; ++i)
            {
            again:;
                bool do_again = false;
                metaclass_t *meta = &metas.val[i],
                            *parent = meta->parentP;
                if(meta->methods_done || meta->methods_err)
                {
                    goto done;
                }
                if(parent)
                {
                    while(!parent->methods_err && !parent->methods_done)
                    {
                        do_again = true;
                        meta = parent;
                        parent = meta->parentP;
                        if(!parent)
                        {
                            break;
                        }
                    }
                    if(parent && parent->methods_err)
                    {
                        WRN("Skipping class %s because parent class was skipped.", meta->name);
                        meta->methods_err = 1;
                        goto done;
                    }
                    while(parent && parent->vtab == 0) // Fall through on abstract classes
                    {
                        parent = parent->parentP;
                    }
                }
                if(symmap.map)
                {
                    symmap_class_t *symcls = bsearch(meta->name, symmap.map, symmap.num, sizeof(*symmap.map), &compare_symclass_name);
                    if(symcls)
                    {
                        while(symcls->duplicate)
                        {
                            --symcls;
                        }
                        if(symcls->metaclass)
                        {
                            DBG(1, "Symmap entry for %s has metaclass set already (%s).", meta->name, symcls->metaclass->name);
                        }
                        else
                        {
                            symcls->metaclass = meta;
                        }
                        meta->symclass = symcls;
                    }
                }
                if(meta->vtab == 0)
                {
                    meta->methods_done = 1;
                    // If the symmap has methods for this class (which has no vtab), then there are two possibilities:
                    // - The class has children, in which case the symmap is always wrong.
                    // - The class has no children, in which case it's unused and the compiler presumably optimised the vtab out.
                    //   In that case we wanna silence this warning, because if it had children, the symmap would probably be right.
                    if(meta->symclass && meta->symclass->num != 0 && meta->has_dependents)
                    {
                        WRN("Symmap entry for %s has %lu methods, but class has no vtab.", meta->name, meta->symclass->num);
                    }
                    goto done;
                }
                if(meta->vtab == -1)
                {
                    WRN("Skipping class %s because vtable is missing.", meta->name);
                    meta->methods_err = 1;
                    goto done;
                }
                // Parent is guaranteed to either be NULL or have a valid vtab here
                const void *segptr = NULL;
                kptr_t segaddr = 0;
                size_t segsize = 0;
                if(!macho_segment_for_addr(macho, meta->vtab, &segptr, &segaddr, &segsize, NULL))
                {
                    ERR("%s vtab is not in any segment.", meta->name);
                    return -1;
                }
                const kptr_t *mvtab = (const kptr_t*)((uintptr_t)segptr + (meta->vtab - segaddr));
                if((meta->vtab - segaddr) < sizeof(kptr_t) * 2 || mvtab[-1] != 0x0 || mvtab[-2] != 0x0) // offset-to-top and rtti, should always be zero for OSMetaClassBase-derived objects
                {
                    ERR("%s vtab not preceded by zero ptrs.", meta->name);
                    return -1;
                }
                size_t nmeth = 0;
                while(1)
                {
                    vtab_check_t status = check_vtab_elem(macho, meta->objsize, mvtab, meta->vtab, nmeth);
                    if(status == kVtabEnd)
                    {
                        break;
                    }
                    if(status == kVtabFunc)
                    {
                        ++nmeth;
                        continue;
                    }
                    // TODO: handle multiple inheritance
                    if(status == kVtabChunk)
                    {
                        break;
                    }
                    ERR("check_vtab_elem returned bad value. This should be impossible.");
                    return -1;
                }
                size_t pnmeth = parent ? parent->nmethods : 0;
                if(nmeth < pnmeth)
                {
                    WRN("%s has fewer methods than its parent (%lu vs %lu).", meta->name, nmeth, pnmeth);
                    meta->methods_err = 1;
                    goto done;
                }
                meta->methods = malloc(nmeth * sizeof(*meta->methods));
                if(!meta->methods)
                {
                    ERRNO("malloc(methods)");
                    return -1;
                }
                meta->nmethods = nmeth;
                bool ignore_symmap = false;
                if(meta->symclass)
                {
                    symmap_class_t *symcls = meta->symclass;
                    if(macho_is_kext(macho))
                    {
                        if(symcls->num > nmeth)
                        {
                            WRN("Symmap entry for %s has %lu methods, vtab has %lu.", meta->name, symcls->num, nmeth);
                            ignore_symmap = true;
                        }
                        else
                        {
                            pnmeth = nmeth - symcls->num;
                        }
                    }
                    else if(symcls->num + pnmeth != nmeth)
                    {
                        WRN("Symmap entry for %s has %lu methods, vtab has %lu.", meta->name, symcls->num, nmeth - pnmeth);
                        ignore_symmap = true;
                    }
                }
                for(size_t idx = 0; idx < nmeth; ++idx)
                {
                    vtab_entry_t *ent   = &meta->methods[idx],
                                 *pent  = (parent && idx < parent->nmethods) ? &parent->methods[idx] : NULL,
                                 *chain = NULL;
                    kptr_t func  = 0;
                    uint16_t pac = 0;
                    size_t nsyms = 0;
                    const sym_t *syms = NULL;
                    const char *cxx_sym = NULL,
                               *class   = NULL,
                               *method  = NULL;
                    bool structor      = false,
                         authoritative = false,
                         overrides     = false,
                         auth          = false,
                         is_in_exreloc = false;

                    kptr_t loc = meta->vtab + sizeof(kptr_t) * idx;
                    // TODO: handle multiple symbols for same addr
                    cxx_sym = macho_reloc_for_addr(macho, loc);
                    if(cxx_sym)
                    {
                        is_in_exreloc = true;
                        // TODO: why was this if'ed?
                        //if(fixupKind == DYLD_CHAINED_PTR_ARM64E_KERNEL)
                        {
                            bool bind = false;
                            bool a = false;
                            uint16_t p = false;
                            macho_fixup(macho, mvtab[idx], &bind, &a, &p, NULL);
                            if(bind)
                            {
                                auth = a;
                                pac  = p;
                            }
                        }
                    }
                    else
                    {
                        func = macho_fixup(macho, mvtab[idx], NULL, &auth, &pac, NULL);
                        syms = macho_symbols_for_addr(macho, func, &nsyms);
                        if(syms)
                        {
                            // TODO
                            cxx_sym = syms[0].name;
                        }
                        overrides = !pent || func != pent->addr;
                    }
                    if((cxx_sym && strcmp(cxx_sym, "___cxa_pure_virtual") == 0) || (pure_virtual && func == pure_virtual))
                    {
                        func = -1;
                    }
                    else if(cxx_sym)
                    {
                        DBG(1, "Got symbol for virtual function " ADDR ": %s", func, cxx_sym);
                        if(cxx_demangle(cxx_sym, &class, &method, &structor))
                        {
                            authoritative = true;
                        }
                        else if(is_in_exreloc)
                        {
                            WRN("Failed to demangle symbol: %s (from reloc)", cxx_sym);
                        }
                        else
                        {
                            WRN("Failed to demangle symbol: %s (from symtab, addr " ADDR ")", cxx_sym, func);
                        }
                    }
                    if(!ignore_symmap && idx >= pnmeth && meta->symclass)
                    {
                        symmap_method_t *smeth = &meta->symclass->methods[idx - pnmeth];
                        if(smeth->method)
                        {
                            if(method && !smeth->structor && (strcmp(class, smeth->class) != 0 || strcmp(method, smeth->method) != 0))
                            {
                                WRN("Overriding %s::%s from symtab with %s::%s from symmap", class, method, smeth->class, smeth->method);
                                // Clear symbol
                                cxx_sym = NULL;
                            }
                            class = smeth->class;
                            method = smeth->method;
                            structor = smeth->structor;
                            authoritative = true;
                        }
                    }
                    // Ok, this is a nasty thing now. We wanna verify that the method's PAC diversifier
                    // matches that of the parent class, if existent. There is only one case where it
                    // will not match, and literally all of the complexity below is due to that:
                    // If class A has a pure virtual method and B inherits from A but does not override
                    // said method, the compiler will give B's vtable a diversifier as if B had declared
                    // the method, not A. This means that we have to traverse the class hierarchy until
                    // we either find a method entry that is not pure virtual, or we reach the first
                    // class with such a method entry. Then however, if that entry is still pure virtual
                    // and the class'es direct parent class has no vtable (i.e. the compiler optimised
                    // it out), we have to skip the check altogether because it is possible that the
                    // parent class declared the method, in which case the entry we found will have the
                    // wrong diversifier. And this really occurs in practice, for example in the
                    // N104AP kernel for 18A5373a (iPhone 11, iOS 14.0 beta 8).
                    if(macho_has_pac(macho) && !is_in_exreloc && pent && func != -1)
                    {
                        metaclass_t  *bcls = parent;
                        vtab_entry_t *bent = pent;
                        // Skip while pure virtual
                        while(bent->addr == -1)
                        {
                            bcls = bcls->parentP;
                            // Skip while missing vtab
                            while(bcls && bcls->vtab == 0)
                            {
                                bcls = bcls->parentP;
                            }
                            if(!bcls || idx >= bcls->nmethods)
                            {
                                bent = NULL;
                                break;
                            }
                            bent = &bcls->methods[idx];
                        }
                        if(bent && pac != bent->pac)
                        {
                            WRN("PAC mismatch method 0x%lx: %s 0x%04hx vs 0x%04hx %s", idx * sizeof(kptr_t), meta->name, pac, bent->pac, bcls->name);
                        }
                    }

                    if(!method && pent)
                    {
                        method = pent->method;
                        if(!pent->structor)
                        {
                            class = overrides ? meta->name : pent->class;
                            authoritative = pent->authoritative;
                            if(!authoritative)
                            {
                                chain = pent->chain;
                                pent->chain = ent;
                            }
                        }
                        else
                        {
                            const char *cls = pent->class,
                                       *mth = method;
                            bool dest = mth[0] == '~';
                            if(dest)
                            {
                                ++mth;
                            }
                            size_t clslen = strlen(cls);
                            if(strncmp(mth, cls, clslen) != 0)
                            {
                                WRN("Bad %sstructor: %s::%s", dest ? "de" : "con", cls, method);
                                method = NULL;
                            }
                            else
                            {
                                const char *strname = meta->name;
                                size_t slen = strlen(strname);
                                if(!cxx_class_basename(&strname, &slen))
                                {
                                    ERR("cxx_class_basename() failed. Something is very broken.");
                                    return -1;
                                }
                                mth += clslen;
                                char *meth = NULL;
                                asprintf(&meth, "%s%.*s%s", dest ? "~" : "", (int)slen, strname, mth);
                                if(!meth)
                                {
                                    ERRNO("asprintf(structor)");
                                    return -1;
                                }
                                method = meth;
                                class = meta->name;
                                structor = true;
                                authoritative = false;
                            }
                        }
                    }
                    if(!method)
                    {
                        char *meth = NULL;
                        asprintf(&meth, "fn_0x%lx()", idx * sizeof(kptr_t));
                        if(!meth)
                        {
                            ERRNO("asprintf(method)");
                            return -1;
                        }
                        method = meth;
                    }
                    if(!class)
                    {
                        class = meta->name;
                    }

                    if(pent && pent->auth != auth)
                    {
                        WRN("Auth mismatch: %s::%s is %s, but %s::%s is %s", pent->class, pent->method, pent->auth ? "auth" : "unauth", class, method, auth ? "auth" : "unauth");
                    }

                    // If we're on arm64e and have a symbol that we believe should be correct, we can check if it matches the PAC diversifier.
                    // In order to avoid duplicate work, we wanna skip this if we already did for the parent, but determining if we did that is a bit of a pain.
                    // We also need to outright skip kexts, because there will always be classes whose superclass isn't in the kext,
                    // so we have absolutely no way of determining where any given method of such classes was declared. :|
                    if(auth && macho_has_pac(macho) && !macho_is_kext(macho) && !is_in_exreloc && authoritative && (!pent || !pent->authoritative))
                    {
                        // The PAC diversifier is a hash of the mangled symbol of the method in the first class that declares it. Since the symbol contains
                        // the class name, we have to traverse the hierarchy here. In theory we'd just seek down to the first class with a large enough vtable
                        // to contain the current method index, and substitute the class name for the one of that class, and hash the resulting symbol.
                        // But with abstract classes involved, if we don't get a match there, then we have to keep going as long as the parent classes
                        // have no vtable, because any one of them could have been the one to declare the method.
                        // Further, there are two exceptions:
                        // - If we get to the bottom of the hierarchy, then we still have to try "OSMetaClassBase" as class name,
                        //   since that is the true parent class in source, but it isn't captures by the metaclass system.
                        // - If we're at the current class, then we use the provided class name from symbol/symmap rather than the actual class name.

                        if(cxx_sym)
                        {
                            DBG(1, "Checking diversifier of %s::%s (class: %s, sym: %s)", class, method, meta->name, cxx_sym);
                        }
                        else
                        {
                            DBG(1, "Checking diversifier of %s::%s (class: %s)", class, method, meta->name);
                        }

                        // If we have no parent method entry, we can skip seeking here
                        metaclass_t *checkClass = meta;
                        if(pent)
                        {
                            for(metaclass_t *curClass = parent; curClass; curClass = curClass->parentP)
                            {
                                if(curClass->vtab == 0)
                                {
                                    continue;
                                }
                                if(idx >= curClass->nmethods)
                                {
                                    break;
                                }
                                checkClass = curClass;
                            }
                        }
                        metaclass_t *p = checkClass;
                        do
                        {
                            const char *className = p == meta ? class
                                                  : p != NULL ? p->name
                                                  : "OSMetaClassBase";
                            char *sym = NULL;
                            if(structor)
                            {
                                char *tmp = cxx_mangle(className, NULL);
                                if(!tmp)
                                {
                                    WRN("Failed to mangle %s", className);
                                    break;
                                }
                                // TODO: Everywhere else I support both con- and destructors and don't make any assumptions about indices.
                                //       But both destructors look exactly the same de-mangled, so this is the only indicator I have, at least for now.
                                //       I guess this will at least spew a warning if things ever break. :|
                                if(tmp[3] == 'N')
                                {
                                    tmp[strlen(tmp)-1] = '\0';
                                    asprintf(&sym, "%sD%zuEv", tmp, 1 - idx);
                                }
                                else
                                {
                                    asprintf(&sym, "__ZN%sD%zuEv", tmp + 3, 1 - idx);
                                }
                                if(!sym)
                                {
                                    ERRNO("asprintf(sym)");
                                    return -1;
                                }
                                free(tmp);
                            }
                            else
                            {
                                sym = cxx_mangle(className, method);
                                if(!sym)
                                {
                                    WRN("Failed to mangle %s::%s", className, method);
                                    break;
                                }
                            }

                            uint16_t div = 0;
                            if(!cxx_compute_pac(sym, &div))
                            {
                                ERR("Failed to compute PAC diversifier. This means something is very broken.");
                                return -1;
                            }
                            DBG(1, "Computed PAC 0x%04hx for symbol %s", div, sym);

                            // Optimisation: if we computed the symbol for the current class and don't have one yet,
                            // we may as well keep it. Otherwise this may be done later, but no need to duplicate work.
                            if(p == meta && !cxx_sym)
                            {
                                cxx_sym = sym;
                            }
                            else
                            {
                                free(sym);
                            }

                            if(div == pac)
                            {
                                break;
                            }
                            if(p && (!(p = p->parentP) || !p->vtab))
                            {
                                continue;
                            }
                            WRN("PAC verification failed for %s::%s", checkClass == meta ? class : checkClass->name, method);
                            break;
                        } while(1);
                    }

                    ent->chain = chain;
                    ent->mangled = cxx_sym;
                    ent->class = class;
                    ent->method = method;
                    ent->addr = func;
                    ent->pac = pac;
                    ent->structor = !!structor;
                    ent->authoritative = !!authoritative;
                    ent->overrides = !!overrides;
                    ent->auth = !!auth;
                    ent->reserved = 0;

                    if(authoritative && !structor && pent && !pent->authoritative)
                    {
                        metaclass_t *cls = meta;
                        for(metaclass_t *c = cls->parentP; c && (idx < c->nmethods || !c->vtab); c = c->parentP)
                        {
                            if(c->vtab)
                            {
                                cls = c;
                            }
                        }
                        if(cls)
                        {
                            vtab_entry_t *start = &cls->methods[idx];
                            if(start->authoritative)
                            {
                                WRN("Authoritativity mismatch: %s::%s says no, but %s::%s says yes?!", parent->name, pent->method, cls->name, start->method);
                            }
                            else
                            {
                                for(vtab_entry_t *next = start; next != NULL; )
                                {
                                    next->method = method;
                                    next->authoritative = true;
                                    vtab_entry_t *tmp = next;
                                    next = next->chain;
                                    tmp->chain = NULL;
                                }
                            }
                        }
                    }
                }
                meta->methods_done = 1;
            done:;
                if(do_again)
                {
                    goto again;
                }
            }

            if(opt.metaclass)
            {
                DBG(1, "Populating MetaClass vtabs...");
                symmap_class_t *symcls = NULL;
                size_t nmetameth = -1;
                if(!macho_is_kext(macho))
                {
                    for(size_t i = 0; i < metas.idx; ++i)
                    {
                        metaclass_t *meta = &metas.val[i];
                        if(strcmp(meta->name, "OSMetaClass") == 0)
                        {
                            if(!meta->methods_done || meta->methods_err || meta->vtab == 0)
                            {
                                WRN("Bad OSMetaClass state: %u/%u/" ADDR, meta->methods_done, meta->methods_err, meta->vtab);
                            }
                            else
                            {
                                OSMetaClass = meta;
                                nmetameth = meta->nmethods;
                            }
                            break;
                        }
                    }
                }
                else if(symmap.map)
                {
                    symcls = bsearch("OSMetaClass", symmap.map, symmap.num, sizeof(*symmap.map), &compare_symclass_name);
                    if(symcls)
                    {
                        while(symcls->duplicate)
                        {
                            --symcls;
                        }
                        nmetameth = symcls->num;
                    }
                }
                for(size_t i = 0; i < metas.idx; ++i)
                {
                    metaclass_t *meta = &metas.val[i];
                    DBG(1, "Populating vtab for %s::MetaClass", meta->name);
                    const void *segptr = NULL;
                    kptr_t segaddr = 0;
                    size_t segsize = 0;
                    if(!macho_segment_for_addr(macho, meta->metavtab, &segptr, &segaddr, &segsize, NULL))
                    {
                        ERR("Vtab of %s::MetaClass is not in any segment.", meta->name);
                        return -1;
                    }
                    const kptr_t *mvtab = (const kptr_t*)((uintptr_t)segptr + (meta->metavtab - segaddr));
                    if((meta->metavtab - segaddr) < sizeof(kptr_t) * 2 || mvtab[-1] != 0x0 || mvtab[-2] != 0x0)
                    {
                        ERR("Vtab of %s::MetaClass not preceded by zero ptrs.", meta->name);
                        return -1;
                    }
                    size_t nmeth = 0;
                    while(1)
                    {
                        vtab_check_t status = check_vtab_elem(macho, 0, mvtab, meta->metavtab, nmeth);
                        if(status == kVtabEnd)
                        {
                            break;
                        }
                        if(status == kVtabFunc)
                        {
                            ++nmeth;
                            continue;
                        }
                        ERR("check_vtab_elem(meta) returned bad value. This should be impossible.");
                        return -1;
                    }
                    if(nmetameth != -1 && nmeth != nmetameth)
                    {
                        WRN("%s::MetaClass has a different amount of methods than the base class (%lu vs %lu).", meta->name, nmeth, nmetameth);
                        goto done;
                    }
                    meta->metamethods = malloc(nmeth * sizeof(*meta->metamethods));
                    if(!meta->metamethods)
                    {
                        ERRNO("malloc(metamethods)");
                        return -1;
                    }
                    meta->nmetamethods = nmeth;
                    char *mname = NULL;
                    asprintf(&mname, "%s::MetaClass", meta->name);
                    if(!mname)
                    {
                        ERRNO("asprintf(mname)");
                        return -1;
                    }
                    for(size_t idx = 0; idx < nmeth; ++idx)
                    {
                        // TODO: There is a LOT of code duplication here :/
                        vtab_entry_t *ent  = &meta->metamethods[idx],
                                     *pent = (OSMetaClass && idx < OSMetaClass->nmethods) ? &OSMetaClass->methods[idx] : NULL;
                        kptr_t func  = 0;
                        uint16_t pac = 0;
                        size_t nsyms = 0;
                        const sym_t *syms = NULL;
                        const char *cxx_sym = NULL,
                                   *class   = NULL,
                                   *method  = NULL;
                        bool structor      = false,
                             authoritative = false,
                             overrides     = false,
                             auth          = false,
                             is_in_exreloc = false;

                        kptr_t loc = meta->metavtab + sizeof(kptr_t) * idx;
                        cxx_sym = macho_reloc_for_addr(macho, loc);
                        if(cxx_sym)
                        {
                            is_in_exreloc = true;
                            // TODO
                            //if(fixupKind == DYLD_CHAINED_PTR_ARM64E_KERNEL)
                            {
                                bool bind = false;
                                bool a = false;
                                uint16_t p = false;
                                macho_fixup(macho, mvtab[idx], &bind, &a, &p, NULL);
                                if(bind)
                                {
                                    auth = a;
                                    pac  = p;
                                }
                            }
                        }
                        else
                        {
                            func = macho_fixup(macho, mvtab[idx], NULL, &auth, &pac, NULL);
                            syms = macho_symbols_for_addr(macho, func, &nsyms);
                            if(syms)
                            {
                                // TODO
                                cxx_sym = syms[0].name;
                            }
                            overrides = !pent || func != pent->addr;
                        }
                        if((cxx_sym && strcmp(cxx_sym, "___cxa_pure_virtual") == 0) || (pure_virtual && func == pure_virtual))
                        {
                            func = -1;
                        }
                        else if(cxx_sym)
                        {
                            DBG(1, "Got symbol for virtual function " ADDR ": %s", func, cxx_sym);
                            if(cxx_demangle(cxx_sym, &class, &method, &structor))
                            {
                                authoritative = true;
                            }
                            else if(is_in_exreloc)
                            {
                                WRN("Failed to demangle symbol: %s (from reloc)", cxx_sym);
                            }
                            else
                            {
                                WRN("Failed to demangle symbol: %s (from symtab, addr " ADDR ")", cxx_sym, func);
                            }
                        }
                        if(!method && symcls && idx < symcls->num)
                        {
                            symmap_method_t *smeth = &symcls->methods[idx];
                            if(!overrides)
                            {
                                class = smeth->class;
                            }
                            method = smeth->method;
                            structor = smeth->structor;
                            if(method)
                            {
                                authoritative = true;
                            }
                        }
                        if(!method && pent)
                        {
                            method = pent->method;
                            if(!pent->structor)
                            {
                                class = overrides ? mname : pent->class;
                                authoritative = pent->authoritative;
                            }
                            else
                            {
                                const char *cls = pent->class,
                                           *mth = method;
                                bool dest = mth[0] == '~';
                                if(dest)
                                {
                                    ++mth;
                                }
                                size_t clslen = strlen(cls);
                                if(strncmp(mth, cls, clslen) != 0)
                                {
                                    WRN("Bad %sstructor: %s::%s", dest ? "de" : "con", cls, method);
                                    method = NULL;
                                }
                                else
                                {
                                    const char *strname = mname;
                                    size_t slen = strlen(strname);
                                    if(!cxx_class_basename(&strname, &slen))
                                    {
                                        ERR("cxx_class_basename() failed. Something is very broken.");
                                        return -1;
                                    }
                                    mth += clslen;
                                    char *meth = NULL;
                                    asprintf(&meth, "%s%.*s%s", dest ? "~" : "", (int)slen, strname, mth);
                                    if(!meth)
                                    {
                                        ERRNO("asprintf(structor)");
                                        return -1;
                                    }
                                    method = meth;
                                    class = mname;
                                    structor = true;
                                    authoritative = false;
                                }
                            }
                        }
                        if(!method)
                        {
                            char *meth = NULL;
                            asprintf(&meth, "fn_0x%lx()", idx * sizeof(kptr_t));
                            if(!meth)
                            {
                                ERRNO("asprintf(method)");
                                return -1;
                            }
                            method = meth;
                        }
                        if(!class)
                        {
                            class = mname;
                        }
                        // Don't bother with PAC verification here. We expect to mostly override abstract methods,
                        // and those are precisely the ones we'd have to skip anyway, so...

                        ent->chain = NULL;
                        ent->mangled = cxx_sym;
                        ent->class = class;
                        ent->method = method;
                        ent->addr = func;
                        ent->pac = pac;
                        ent->structor = !!structor;
                        ent->authoritative = !!authoritative;
                        ent->overrides = !!overrides;
                        ent->auth = !!auth;
                        ent->reserved = 0;
                    }
                }
            }

            if(opt.mangle)
            {
                for(size_t i = 0; i < metas.idx; ++i)
                {
                    metaclass_t *meta = &metas.val[i];
                    for(size_t idx = 0; idx < meta->nmethods; ++idx)
                    {
                        vtab_entry_t *ent = &meta->methods[idx];
                        if(!ent->mangled)
                        {
                            if(ent->structor)
                            {
                                char *tmp = cxx_mangle(ent->class, NULL);
                                if(!tmp)
                                {
                                    ERR("Failed to mangle %s", ent->class);
                                    return -1;
                                }
                                // TODO: See above
                                char *sym = NULL;
                                if(tmp[3] == 'N')
                                {
                                    tmp[strlen(tmp)-1] = '\0';
                                    asprintf(&sym, "%sD%zuEv", tmp, 1 - idx);
                                }
                                else
                                {
                                    asprintf(&sym, "__ZN%sD%zuEv", tmp + 3, 1 - idx);
                                }
                                if(!sym)
                                {
                                    ERRNO("asprintf(ent->mangled)");
                                    return -1;
                                }
                                free(tmp);
                                ent->mangled = sym;
                            }
                            else
                            {
                                ent->mangled = cxx_mangle(ent->class, ent->method);
                                if(!ent->mangled)
                                {
                                    ERR("Failed to mangle %s::%s", ent->class, ent->method);
                                    return -1;
                                }
                            }
                        }
                    }
                    if(opt.metaclass)
                    {
                        for(size_t idx = 0; idx < meta->nmetamethods; ++idx)
                        {
                            vtab_entry_t *ent = &meta->metamethods[idx];
                            if(!ent->mangled)
                            {
                                if(ent->structor)
                                {
                                    char *tmp = cxx_mangle(ent->class, NULL);
                                    if(!tmp)
                                    {
                                        ERR("Failed to mangle %s", ent->class);
                                        return -1;
                                    }
                                    // TODO: See above
                                    char *sym = NULL;
                                    if(tmp[3] == 'N')
                                    {
                                        tmp[strlen(tmp)-1] = '\0';
                                        asprintf(&sym, "%sD%zuEv", tmp, 1 - idx);
                                    }
                                    else
                                    {
                                        asprintf(&sym, "__ZN%sD%zuEv", tmp + 3, 1 - idx);
                                    }
                                    if(!sym)
                                    {
                                        ERRNO("asprintf(ent->mangled)");
                                        return -1;
                                    }
                                    free(tmp);
                                    ent->mangled = sym;
                                }
                                else
                                {
                                    ent->mangled = cxx_mangle(ent->class, ent->method);
                                    if(!ent->mangled)
                                    {
                                        ERR("Failed to mangle %s::%s", ent->class, ent->method);
                                        return -1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    const char **filter = NULL;
    if(opt.bundle || opt.bfilt)
    {
        for(size_t i = 0; i < metas.idx; ++i)
        {
            metaclass_t *meta = &metas.val[i];
            meta->bundle = macho_bundle_for_addr(macho, meta->callsite);
            if(!meta->bundle)
            {
                return -1;
            }
        }
        if(filt_bundle)
        {
            size_t nbundles = 0;
            const char * const *bundles = macho_bundles(macho, &nbundles);
            if(!bundles)
            {
                return -1;
            }
            // Exact match
            for(size_t i = 0; i < nbundles; ++i)
            {
                if(strcmp(bundles[i], filt_bundle) == 0)
                {
                    filter = malloc(sizeof(*filter) * 2);
                    if(!filter)
                    {
                        ERRNO("malloc(filter)");
                        return -1;
                    }
                    // Since these are strings, we can unique them even if there was more than one exact match
                    filter[0] = filt_bundle;
                    filter[1] = NULL;
                    break;
                }
            }
            // Partial match
            if(!filter)
            {
                size_t num = 0;
                for(size_t i = 0; i < nbundles; ++i)
                {
                    if(strstr(bundles[i], filt_bundle))
                    {
                        ++num;
                    }
                }
                if(num)
                {
                    filter = malloc((num + 1) * sizeof(*filter));
                    if(!filter)
                    {
                        ERRNO("malloc(filter)");
                        return -1;
                    }
                    filter[num] = NULL;
                    num = 0;
                    for(size_t i = 0; i < nbundles; ++i)
                    {
                        if(strstr(bundles[i], filt_bundle))
                        {
                            filter[num++] = bundles[i];
                        }
                    }
                }
            }
            if(!filter)
            {
                ERR("No bundle matching %s.", filt_bundle);
                return -1;
            }
        }
    }

    // If this is a kext, then all of these are fake, so remove them before printing.
    if(macho_is_kext(macho))
    {
        pure_virtual = 0;
        OSMetaClassConstructor = 0;
        OSMetaClassAltConstructor = 0;
    }
    // Symmap will always need special handling due to maxmap
    bool ok = opt.symmap ? print_symmap(&metas, &symmap, opt) : print_all(&metas, opt, OSMetaClass, filt_class, filt_override, filter, pure_virtual, OSMetaClassConstructor, OSMetaClassAltConstructor, print);
    if(!ok)
    {
        return -1;
    }

    macho_close(macho);

    return 0;
}
