/* Copyright (c) 2018-2024 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#include <stdbool.h>
#include <stddef.h>             // size_t
#include <stdint.h>

#include "a64.h"
#include "a64emu.h"
#include "macho.h"
#include "util.h"

bool is_linear_inst(const void *ptr)
{
    return is_adr(ptr)         ||
           is_adrp(ptr)        ||
           is_add_imm(ptr)     ||
           is_sub_imm(ptr)     ||
           is_adds_imm(ptr)    ||
           is_subs_imm(ptr)    ||
           is_add_reg(ptr)     ||
           is_sub_reg(ptr)     ||
           is_adds_reg(ptr)    ||
           is_subs_reg(ptr)    ||
           is_madd(ptr)        ||
           is_ldr_uoff(ptr)    ||
           is_ldr_pre(ptr)     ||
           is_ldr_post(ptr)    ||
           is_ldr_lit(ptr)     ||
           is_ldp_pre(ptr)     ||
           is_ldp_post(ptr)    ||
           is_ldp_uoff(ptr)    ||
           is_ldxr(ptr)        ||
           is_ldadd(ptr)       ||
           is_ldur(ptr)        ||
           is_ldr_fp_uoff(ptr) ||
           is_ldur_fp(ptr)     ||
           is_ldp_fp_pre(ptr)  ||
           is_ldp_fp_post(ptr) ||
           is_ldp_fp_uoff(ptr) ||
           is_bl(ptr)          ||
           is_movz(ptr)        ||
           is_movk(ptr)        ||
           is_movn(ptr)        ||
           is_movi(ptr)        ||
           is_and(ptr)         ||
           is_ands(ptr)        ||
           is_orr(ptr)         ||
           is_eor(ptr)         ||
           is_and_reg(ptr)     ||
           is_ands_reg(ptr)    ||
           is_orr_reg(ptr)     ||
           is_eor_reg(ptr)     ||
           is_str_pre(ptr)     ||
           is_str_post(ptr)    ||
           is_str_uoff(ptr)    ||
           is_stp_pre(ptr)     ||
           is_stp_post(ptr)    ||
           is_stp_uoff(ptr)    ||
           is_stxr(ptr)        ||
           is_stur(ptr)        ||
           is_str_fp_uoff(ptr) ||
           is_stur_fp(ptr)     ||
           is_stp_fp_pre(ptr)  ||
           is_stp_fp_post(ptr) ||
           is_stp_fp_uoff(ptr) ||
           is_ldrb_uoff(ptr)   ||
           is_ldrh_uoff(ptr)   ||
           is_ldrsb_uoff(ptr)  ||
           is_ldrsh_uoff(ptr)  ||
           is_ldrsw_uoff(ptr)  ||
           is_strb_uoff(ptr)   ||
           is_strh_uoff(ptr)   ||
           is_pac(ptr)         ||
           is_pacsys(ptr)      ||
           is_pacga(ptr)       ||
           is_aut(ptr)         ||
           is_autsys(ptr)      ||
           is_mrs(ptr)         ||
           is_dc_zva(ptr)      ||
           is_bti(ptr)         ||
           is_nop(ptr)         ;
}

// This is quite possibly the trickiest part: finding the start of the function.
// At first glance it seems simple: just find the function prologue. But how do you
// actually detect the first instruction of the prologue? On arm64e kernels there
// should be a "pacibsp", but on arm64? Is "sub sp, sp, 0x..." or a pre-index store
// enough? But either way, there are functions that just rearrange some args and
// then do a tail call - these functions have no stack frame whatsoever. And
// at some point clang also started what I call "late stack frames" which only
// happen after some early-exit conditions have been passed already, so the prologue
// is no longer guaranteed to constitute the start of the function.
// The other approach would be to just seek backwards as long as we hit "linear"
// instructions, as that would at least constitute one *possible* call path.
// The nasty issue with that are "noreturn" functions like panic and __stack_chk_fail.
// Those are excruciatingly often ordered right before the following function like so:
//
//      ldp x29, x30, [sp, 0x10]
//      add sp, sp, 0x20
//      ret
//      adrp x0, 0x...
//      add x0, x0, 0x...
//      bl sym.panic
//      sub sp, sp, 0x20
//      stp x29, x30, [sp, 0x10]
//      add x29, sp, 0x10
//
// Without more information on the function called by such a "bl", we simply don't know
// whether that function can/will return or not. There is but one assumption we can make:
// We can assume function calls are only made inside stack frames, because "bl" will
// otherwise corrupt x30. So we simply keep track of whether we have a stack frame
// (or more precisely, whether x30 was stashed away) by looking out for "ldp/stp x29, x30"
// when seeking backwards. As long as we're inside a stack frame, "bl" are assumed to be
// part of the function, once we leave it, they are no longer considered to be "linear".
// We also always start seeking backwards from a function call, and in the case of "bl"
// we assume we have a stack frame, in the case of "b" we assume we do not.
const uint32_t* find_function_start(macho_t *macho, const char *name, const uint32_t *fnstart, const uint32_t *bound, bool have_stack_frame)
{
    while(1)
    {
        --fnstart;
        if(fnstart < bound)
        {
            ++fnstart;
            // If we expect a stack frame, this is fatal.
            if(have_stack_frame)
            {
                WRN("Hit start of segment at " ADDR " for %s", macho_ptov(macho, fnstart), name);
                return NULL;
            }
            // Otherwise ehh whatever.
            DBG(1, "Hit start of segment at " ADDR " for %s", macho_ptov(macho, fnstart), name);
            break;
        }
        if(!is_linear_inst(fnstart) || (is_bl((bl_t*)fnstart) && !have_stack_frame))
        {
            ++fnstart;
            break;
        }
        const stp_t *stp = (const stp_t*)fnstart;
        const ldp_t *ldp = (const ldp_t*)fnstart;
        if((is_stp_pre(stp) || is_stp_uoff(stp)) && stp->Rt == 29 && stp->Rt2 == 30)
        {
            have_stack_frame = false;
        }
        else if((is_ldp_post(ldp) || is_ldp_uoff(ldp)) && ldp->Rt == 29 && ldp->Rt2 == 30)
        {
            have_stack_frame = true;
        }
    }
    return fnstart;
}

bool a64cb_check_equal(const uint32_t *pos, void *arg)
{
    return pos != (const uint32_t*)arg;
}

bool a64cb_check_bl(const uint32_t *pos, void *arg)
{
    if(is_bl((const bl_t*)pos))
    {
        *(const uint32_t**)arg = pos;
        return false;
    }
    return true;
}

static inline uint8_t host_idx_get(a64_state_t *state, uint8_t idx, uint64_t addr)
{
    uint64_t off = addr - state->hostmem[idx].min;
    if(off % 8 != 0)
    {
        return 0;
    }
    off /= 8;
    return (state->hostmem[idx].bitstring[off / 4] >> ((off & 0x3) << 1)) & 0x3;
}

static inline void host_idx_set(a64_state_t *state, uint8_t idx, uint64_t addr, uint32_t size, uint8_t val)
{
    uint64_t off = addr - state->hostmem[idx].min;
    if(off % 8 != 0)
    {
        bool nextToo = ((off & 0x7) + size) > 8;
        off /= 8;
        state->hostmem[idx].bitstring[off / 4] &= ~(3 << ((off & 0x3) << 1));
        if(nextToo)
        {
            ++off;
            state->hostmem[idx].bitstring[off / 4] &= ~(3 << ((off & 0x3) << 1));
        }
    }
    else
    {
        off /= 8;
        val &= 3;
        if(size != 8) val = 0;
        state->hostmem[idx].bitstring[off / 4] = (state->hostmem[idx].bitstring[off / 4] & ~(3 << ((off & 0x3) << 1))) | (val << ((off & 0x3) << 1));
    }
}

static inline void update_nzcv(a64_state_t *state, uint64_t Rd, uint64_t Rn, uint64_t Rm, bool wide)
{
    uint32_t topN = (Rn >> (wide ? 63 : 31)) & 0x1;
    uint32_t topM = (Rm >> (wide ? 63 : 31)) & 0x1;
    uint32_t topD = (Rd >> (wide ? 63 : 31)) & 0x1;
    state->n = topD;
    state->z = Rd == 0;
    state->c = Rd < (wide ? Rn : (Rn & 0xffffffffULL));
    state->v = (topN^topM^1) & (topN^topD);
    state->nzcv_valid = 1;
}

#define HOST_IN_RANGE(state, idx, addr, size) ((uint64_t)(addr) >= (state)->hostmem[(idx)].min && (uint64_t)(addr) <= (state)->hostmem[(idx)].max - (size))

// Best-effort emulation: halt on unknown instructions, keep track of which registers
// hold known values and only operate on those. Ignore non-static memory unless
// it is specifically marked as "host memory".
emu_ret_t a64_emulate(macho_t *macho, a64_state_t *state, const uint32_t *from, a64cb_t check, void *arg, bool init, bool warnUnknown, emu_fn_behaviour_t fn_behaviour)
{
    // TODO for the entire func:
    // - refactor flags
    // - add explicit flag to ignore non-host memory stores
    if(init)
    {
        for(size_t i = 0; i < 32; ++i)
        {
            state->x[i] = 0;
            state->q[i] = 0;
        }
        state->flags  = 0;
        state->valid  = 0;
        state->qvalid = 0;
        state->wide   = 0;
        state->host   = 0;
    }
    for(; check(from, arg); ++from)
    {
        const void *ptr = from;
        kptr_t addr = macho_ptov(macho, from);
        DBG(4, "a64emu trace: 0x%08x " ADDR, *(const uint32_t*)ptr, addr);
        DBG(5, "%08x %08x %016llx %c %c%c%c%c", state->valid, state->wide, state->host, state->nzcv_valid ? 'y' : 'n', state->n ? 'n' : '-', state->z ? 'z' : '-', state->c ? 'c' : '-', state->v ? 'v' : '-');
        DBG(5, " x0: 0x%016llx  x1: 0x%016llx  x2: 0x%016llx  x3: 0x%016llx", state->x[ 0], state->x[ 1], state->x[ 2], state->x[3]);
        DBG(5, " x4: 0x%016llx  x5: 0x%016llx  x6: 0x%016llx  x7: 0x%016llx", state->x[ 4], state->x[ 5], state->x[ 6], state->x[7]);
        DBG(5, " x8: 0x%016llx  x9: 0x%016llx x10: 0x%016llx x11: 0x%016llx", state->x[ 8], state->x[ 9], state->x[10], state->x[11]);
        DBG(5, "x12: 0x%016llx x13: 0x%016llx x14: 0x%016llx x15: 0x%016llx", state->x[12], state->x[13], state->x[14], state->x[15]);
        DBG(5, "x16: 0x%016llx x17: 0x%016llx x18: 0x%016llx x19: 0x%016llx", state->x[16], state->x[17], state->x[18], state->x[19]);
        DBG(5, "x20: 0x%016llx x21: 0x%016llx x22: 0x%016llx x23: 0x%016llx", state->x[20], state->x[21], state->x[22], state->x[23]);
        DBG(5, "x24: 0x%016llx x25: 0x%016llx x26: 0x%016llx x27: 0x%016llx", state->x[24], state->x[25], state->x[26], state->x[27]);
        DBG(5, "x28: 0x%016llx x29: 0x%016llx x30: 0x%016llx  sp: 0x%016llx", state->x[28], state->x[29], state->x[30], state->x[31]);
        if(is_nop(ptr) || is_pac(ptr) || is_pacsys(ptr) || is_pacga(ptr) || is_aut(ptr) || is_autsys(ptr) || is_bti(ptr))
        {
            // Ignore/no change
        }
        else if(is_mrs(ptr))
        {
            const sys_t *mrs = ptr;
            if(mrs->Rt != 31)
            {
                // We have no concept of system registers, so just threat them as invalid
                state->valid &= ~(1 << mrs->Rt);
            }
        }
        else if(is_dc_zva(ptr))
        {
            const sys_t *dc = ptr;
            if(dc->Rt != 31 && state->valid & (1 << dc->Rt))
            {
                kptr_t zaddr = state->x[dc->Rt] & ~(CACHELINE_SIZE - 1);
                uint8_t idx = HOST_GET(state, dc->Rt);
                if(idx)
                {
                    --idx;
                    if(HOST_IN_RANGE(state, idx, zaddr, CACHELINE_SIZE))
                    {
                        bzero((void*)zaddr, CACHELINE_SIZE);
                    }
                }
            }
        }
        else if(is_str_pre(ptr) || is_str_post(ptr))
        {
            const str_imm_t *str = ptr;
            if(state->valid & (1 << str->Rn)) // Only if valid
            {
                kptr_t staddr = state->x[str->Rn] + get_str_imm(str);
                if(is_str_pre(str))
                {
                    state->x[str->Rn] = staddr;
                }
                else if(is_str_post(str))
                {
                    kptr_t tmp = state->x[str->Rn];
                    state->x[str->Rn] = staddr;
                    staddr = tmp;
                }
                uint8_t idx = HOST_GET(state, str->Rn);
                if(idx)
                {
                    if(str->Rt != 31 && !(state->valid & (1 << str->Rt)))
                    {
                        if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                        else         DBG(1, "Cannot store invalid value to host mem at " ADDR, addr);
                        return kEmuUnknown;
                    }
                    --idx;
                    if(HOST_IN_RANGE(state, idx, staddr, str->sf ? 8 : 4))
                    {
                        uint64_t val = str->Rt == 31 ? 0 : state->x[str->Rt];
                        if(str->sf)
                        {
                            *(uint64_t*)staddr = val;
                            host_idx_set(state, idx, staddr, 8, str->Rt == 31 ? 0 : HOST_GET(state, str->Rt));
                        }
                        else
                        {
                            *(uint32_t*)staddr = (uint32_t)val;
                            host_idx_set(state, idx, staddr, 4, 0);
                        }
                    }
                }
            }
        }
        else if(is_str_uoff(ptr) || is_stur(ptr) || is_strb_uoff(ptr) || is_strh_uoff(ptr))
        {
            uint32_t Rt, Rn, size;
            int64_t off;
            if(is_str_uoff(ptr))
            {
                const str_uoff_t *str = ptr;
                Rt = str->Rt;
                Rn = str->Rn;
                size = 4 << str->sf;
                off = get_str_uoff(str);
            }
            else if(is_stur(ptr))
            {
                const stur_t *stur = ptr;
                Rt = stur->Rt;
                Rn = stur->Rn;
                size = 4 << stur->sf;
                off = get_stur_off(stur);
            }
            else if(is_strb_uoff(ptr))
            {
                const strb_uoff_t *strb = ptr;
                Rt = strb->Rt;
                Rn = strb->Rn;
                size = 1;
                off = get_strb_uoff(strb);
            }
            else if(is_strh_uoff(ptr))
            {
                const strh_uoff_t *strh = ptr;
                Rt = strh->Rt;
                Rn = strh->Rn;
                size = 2;
                off = get_strh_uoff(strh);
            }
            else
            {
                ERR("Bug in a64_emulate (case str_uoff) at " ADDR, addr);
                __builtin_trap();
            }
            uint8_t idx;
            if((state->valid & (1 << Rn)) && (idx = HOST_GET(state, Rn)))
            {
                if(Rt != 31 && !(state->valid & (1 << Rt)))
                {
                    if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                    else         DBG(1, "Cannot store invalid value to host mem at " ADDR, addr);
                    return kEmuUnknown;
                }
                --idx;
                kptr_t staddr = state->x[Rn] + off;
                if(HOST_IN_RANGE(state, idx, staddr, size))
                {
                    uint64_t val = Rt == 31 ? 0 : state->x[Rt];
                    switch(size)
                    {
                        case 1: *(uint8_t *)staddr = (uint8_t )val; break;
                        case 2: *(uint16_t*)staddr = (uint16_t)val; break;
                        case 4: *(uint32_t*)staddr = (uint32_t)val; break;
                        case 8: *(uint64_t*)staddr = (uint64_t)val; break;
                        default:
                            ERR("Bug in a64_emulate: str_uoff with invalid size at " ADDR, addr);
                            __builtin_trap();
                    }
                    host_idx_set(state, idx, staddr, size, size == 8 && Rt != 31 ? HOST_GET(state, Rt) : 0);
                }
            }
        }
        else if(is_stp_pre(ptr) || is_stp_post(ptr) || is_stp_uoff(ptr))
        {
            const stp_t *stp = ptr;
            if(state->valid & (1 << stp->Rn)) // Only if valid
            {
                kptr_t staddr = state->x[stp->Rn] + get_ldp_stp_off(stp);
                if(is_stp_pre(stp))
                {
                    state->x[stp->Rn] = staddr;
                }
                else if(is_stp_post(stp))
                {
                    kptr_t tmp = state->x[stp->Rn];
                    state->x[stp->Rn] = staddr;
                    staddr = tmp;
                }
                uint8_t idx = HOST_GET(state, stp->Rn);
                if(idx)
                {
                    if((stp->Rt != 31 && !(state->valid & (1 << stp->Rt))) || (stp->Rt2 != 31 && !(state->valid & (1 << stp->Rt2))))
                    {
                        if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                        else         DBG(1, "Cannot store invalid value to host mem at " ADDR, addr);
                        return kEmuUnknown;
                    }
                    --idx;
                    uint64_t val  = stp->Rt  == 31 ? 0 : state->x[stp->Rt];
                    uint64_t val2 = stp->Rt2 == 31 ? 0 : state->x[stp->Rt2];
                    if(stp->sf)
                    {
                        uint64_t *p = (uint64_t*)staddr;
                        if(HOST_IN_RANGE(state, idx, staddr, 8))
                        {
                            p[0] = val;
                            host_idx_set(state, idx, staddr, 8, stp->Rt == 31 ? 0 : HOST_GET(state, stp->Rt));
                        }
                        if(HOST_IN_RANGE(state, idx, staddr + 8, 8))
                        {
                            p[1] = val2;
                            host_idx_set(state, idx, staddr + 8, 8, stp->Rt2 == 31 ? 0 : HOST_GET(state, stp->Rt2));
                        }
                    }
                    else
                    {
                        uint32_t *p = (uint32_t*)staddr;
                        if(HOST_IN_RANGE(state, idx, staddr, 4))
                        {
                            p[0] = (uint32_t)val;
                            host_idx_set(state, idx, staddr, 4, 0);
                        }
                        if(HOST_IN_RANGE(state, idx, staddr + 4, 4))
                        {
                            p[1] = (uint32_t)val2;
                            host_idx_set(state, idx, staddr + 4, 4, 0);
                        }
                    }
                }
            }
        }
        else if(is_stxr(ptr))
        {
            const stxr_t *stxr = ptr;
            if(stxr->Rs != 31)
            {
                // Always set success
                state->x[stxr->Rs] = 0;
                state->valid  |= 1 << stxr->Rs;
                state->wide &= ~(1 << stxr->Rs);
                HOST_SET(state, stxr->Rs, 0);
            }
            uint8_t idx;
            if((state->valid & (1 << stxr->Rn)) && (idx = HOST_GET(state, stxr->Rn))) // Only if valid & host
            {
                if(stxr->Rt != 31 && !(state->valid & (1 << stxr->Rt)))
                {
                    if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                    else         DBG(1, "Cannot store invalid value to host mem at " ADDR, addr);
                    return kEmuUnknown;
                }
                --idx;
                kptr_t staddr = state->x[stxr->Rn];
                if(HOST_IN_RANGE(state, idx, staddr, stxr->sf ? 8 : 4))
                {
                    if(stxr->sf)
                    {
                        *(uint64_t*)staddr = stxr->Rt == 31 ? 0 : state->x[stxr->Rt];
                        host_idx_set(state, idx, staddr, 8, stxr->Rt == 31 ? 0 : HOST_GET(state, stxr->Rt));
                    }
                    else
                    {
                        *(uint32_t*)staddr = stxr->Rt == 31 ? 0 : (uint32_t)state->x[stxr->Rt];
                        host_idx_set(state, idx, staddr, 4, 0);
                    }
                }
            }
        }
        else if(is_adr(ptr) || is_adrp(ptr))
        {
            const adr_t *adr = ptr;
            if(adr->Rd != 31)
            {
                state->x[adr->Rd] = (adr->op1 ? (addr & ~0xfff) : addr) + get_adr_off(adr);
                state->valid |= 1 << adr->Rd;
                state->wide  |= 1 << adr->Rd;
                HOST_SET(state, adr->Rd, 0);
            }
        }
        else if(is_add_imm(ptr) || is_sub_imm(ptr) || is_adds_imm(ptr) || is_subs_imm(ptr))
        {
            // Immediate can always use sp as source, but only target it in the non-nzcv variant
            bool want_nzcv = is_adds_imm(ptr) || is_subs_imm(ptr);
            const add_imm_t *add = ptr;
            if(!(state->valid & (1 << add->Rn))) // Unset validity
            {
                if(!want_nzcv || add->Rd != 31)
                {
                    state->valid &= ~(1 << add->Rd);
                }
                if(want_nzcv)
                {
                    state->nzcv_valid = 0;
                }
            }
            else
            {
                uint64_t Rm = get_add_sub_imm(add);
                uint64_t Rn = state->x[add->Rn];
                if(is_sub_imm(ptr) || is_subs_imm(ptr))
                {
                    Rm = -Rm;
                }
                uint64_t Rd = Rn + Rm;
                Rd = add->sf ? Rd : (Rd & 0xffffffffULL);
                if(want_nzcv)
                {
                    update_nzcv(state, Rd, Rn, Rm, !!add->sf);
                }
                if(!want_nzcv || add->Rd != 31)
                {
                    state->x[add->Rd] = Rd;
                    state->valid |= 1 << add->Rd;
                    state->wide = (state->wide & ~(1 << add->Rd)) | (add->sf << add->Rd);
                    HOST_SET(state, add->Rd, HOST_GET(state, add->Rn));
                }
            }
        }
        else if(is_add_reg(ptr) || is_sub_reg(ptr) || is_adds_reg(ptr) || is_subs_reg(ptr))
        {
            // Shifted reg never uses sp as source or target
            bool want_nzcv = is_adds_reg(ptr) || is_subs_reg(ptr);
            const add_reg_t *add = ptr;
            if
            (
                (add->Rn != 31 && !(state->valid & (1 << add->Rn))) ||
                (add->Rm != 31 && !(state->valid & (1 << add->Rm)))
            )
            {
                // Unset validity
                if(add->Rd != 31)
                {
                    state->valid &= ~(1 << add->Rd);
                }
                if(want_nzcv)
                {
                    state->nzcv_valid = 0;
                }
            }
            else
            {
                uint64_t Rn = add->Rn == 31 ? 0 : state->x[add->Rn];
                uint64_t Rm = add->Rm == 31 ? 0 : state->x[add->Rm];
                switch(add->shift)
                {
                    case 0b00: Rm =          Rm << add->imm; break; // LSL
                    case 0b01: Rm =          Rm >> add->imm; break; // LSR
                    case 0b10: Rm = (int64_t)Rm >> add->imm; break; // ASR
                    default:
                        WRN("Bad add/sub shift at " ADDR, addr);
                        return kEmuErr;
                }
                if(is_sub_reg(ptr) || is_subs_reg(ptr))
                {
                    Rm = -Rm;
                }
                uint64_t Rd = Rn + Rm;
                Rd = add->sf ? Rd : (Rd & 0xffffffffULL);
                if(want_nzcv)
                {
                    update_nzcv(state, Rd, Rn, Rm, !!add->sf);
                }
                if(add->Rd != 31)
                {
                    state->x[add->Rd] = Rd;
                    state->valid |= 1 << add->Rd;
                    state->wide = (state->wide & ~(1 << add->Rd)) | (add->sf << add->Rd);
                    // Weird case: we only wanna keep the host flag if exactly one of the source registers has it.
                    // If both have it, then we're doing pointer arithmetic, so we have a scalar value now.
                    uint64_t RnIdx = add->Rn == 31 ? 0 : HOST_GET(state, add->Rn);
                    uint64_t RmIdx = add->Rm == 31 ? 0 : HOST_GET(state, add->Rm);
                    if((RnIdx == 0 && RmIdx == 0) || (RnIdx != 0 && RmIdx != 0))
                    {
                        HOST_SET(state, add->Rd, 0);
                    }
                    else
                    {
                        HOST_SET(state, add->Rd, RnIdx | RmIdx);
                    }
                }
            }
        }
        else if(is_madd(ptr))
        {
            const madd_t *madd = ptr;
            if(madd->Rd != 31)
            {
                if
                (
                    (madd->Rn != 31 && !(state->valid & (1 << madd->Rn))) ||
                    (madd->Rm != 31 && !(state->valid & (1 << madd->Rm))) ||
                    (madd->Ra != 31 && !(state->valid & (1 << madd->Ra)))
                )
                {
                    // Unset validity
                    state->valid &= ~(1 << madd->Rd);
                }
                else
                {
                    uint64_t Rn = madd->Rn == 31 ? 0 : state->x[madd->Rn];
                    uint64_t Rm = madd->Rm == 31 ? 0 : state->x[madd->Rm];
                    uint64_t Ra = madd->Ra == 31 ? 0 : state->x[madd->Ra];
                    uint64_t Rd = Rn * Rm + Ra;
                    Rd = madd->sf ? Rd : (Rd & 0xffffffffULL);
                    state->x[madd->Rd] = Rd;
                    state->valid |= 1 << madd->Rd;
                    state->wide = (state->wide & ~(1 << madd->Rd)) | (madd->sf << madd->Rd);
                    HOST_SET(state, madd->Rd, (!madd->sf || madd->Ra == 31) ? 0 : HOST_GET(state, madd->Ra));
                }
            }
        }
        else if(is_ldr_uoff(ptr) || is_ldur(ptr) || is_ldrb_uoff(ptr) || is_ldrh_uoff(ptr) || is_ldrsb_uoff(ptr) || is_ldrsh_uoff(ptr) || is_ldrsw_uoff(ptr) || is_ldr_pre(ptr) || is_ldr_post(ptr))
        {
            bool sign = false;
            uint32_t Rt, Rn, sf, size;
            int64_t off,
                    wboff = 0;
            if(is_ldr_uoff(ptr))
            {
                const ldr_uoff_t *ldr = ptr;
                Rt = ldr->Rt;
                Rn = ldr->Rn;
                sf = ldr->sf;
                size = 4 << ldr->sf;
                off = get_ldr_uoff(ldr);
            }
            else if(is_ldur(ptr))
            {
                const ldur_t *ldur = ptr;
                Rt = ldur->Rt;
                Rn = ldur->Rn;
                sf = ldur->sf;
                size = 4 << ldur->sf;
                off = get_ldur_off(ldur);
            }
            else if(is_ldrb_uoff(ptr))
            {
                const ldrb_uoff_t *ldrb = ptr;
                Rt = ldrb->Rt;
                Rn = ldrb->Rn;
                sf = 0;
                size = 1;
                off = get_ldrb_uoff(ldrb);
            }
            else if(is_ldrh_uoff(ptr))
            {
                const ldrh_uoff_t *ldrh = ptr;
                Rt = ldrh->Rt;
                Rn = ldrh->Rn;
                sf = 0;
                size = 2;
                off = get_ldrh_uoff(ldrh);
            }
            else if(is_ldrsb_uoff(ptr))
            {
                const ldrsb_uoff_t *ldrsb = ptr;
                Rt = ldrsb->Rt;
                Rn = ldrsb->Rn;
                sf = ldrsb->sf;
                size = 1;
                off = get_ldrsb_uoff(ldrsb);
                sign = true;
            }
            else if(is_ldrsh_uoff(ptr))
            {
                const ldrsh_uoff_t *ldrsh = ptr;
                Rt = ldrsh->Rt;
                Rn = ldrsh->Rn;
                sf = ldrsh->sf;
                size = 2;
                off = get_ldrsh_uoff(ldrsh);
                sign = true;
            }
            else if(is_ldrsw_uoff(ptr))
            {
                const ldrsw_uoff_t *ldrsw = ptr;
                Rt = ldrsw->Rt;
                Rn = ldrsw->Rn;
                sf = 1;
                size = 4;
                off = get_ldrsw_uoff(ldrsw);
                sign = true;
            }
            else if(is_ldr_pre(ptr))
            {
                const ldr_imm_t *ldr = ptr;
                Rt = ldr->Rt;
                Rn = ldr->Rn;
                sf = ldr->sf;
                size = 4 << ldr->sf;
                off = get_ldr_imm(ldr);
                wboff = off;
            }
            else if(is_ldr_post(ptr))
            {
                const ldr_imm_t *ldr = ptr;
                Rt = ldr->Rt;
                Rn = ldr->Rn;
                sf = ldr->sf;
                size = 4 << ldr->sf;
                off = 0;
                wboff = get_ldr_imm(ldr);
            }
            else
            {
                ERR("Bug in a64_emulate (case ldr_imm_uoff) at " ADDR, addr);
                __builtin_trap();
            }
            if(!(state->valid & (1 << Rn))) // Unset validity
            {
                state->valid &= ~(1 << Rt);
            }
            else
            {
                if(Rt != 31)
                {
                    kptr_t laddr = state->x[Rn] + off;
                    uint8_t idx = HOST_GET(state, Rn);
                    const void *ldr_addr = idx ? (HOST_IN_RANGE(state, idx-1, laddr, size) ? (const void*)laddr : NULL) : macho_vtop(macho, laddr, size);
                    if(!ldr_addr)
                    {
                        if(idx)
                        {
                            WRN("Load address outside of host mem at " ADDR, addr);
                        }
                        else
                        {
                            WRN("Load address outside of all segments at " ADDR " (" ADDR ")", addr, laddr);
                        }
                        return kEmuErr;
                    }
                    uint64_t val;
                    switch(size)
                    {
                        case 1: val = *(const uint8_t *)ldr_addr; break;
                        case 2: val = *(const uint16_t*)ldr_addr; break;
                        case 4: val = *(const uint32_t*)ldr_addr; break;
                        case 8: val = *(const uint64_t*)ldr_addr; break;
                        default:
                            ERR("Bug in a64_emulate: ldr_uoff with invalid size at " ADDR, addr);
                            __builtin_trap();
                    }
                    if(sign)
                    {
                        switch(size)
                        {
                            case 1: val = ((int64_t)val << 56) >> 56; break;
                            case 2: val = ((int64_t)val << 48) >> 48; break;
                            case 4: val = ((int64_t)val << 32) >> 32; break;
                            default:
                                ERR("Bug in a64_emulate: ldr_uoff with invalid signed size at " ADDR, addr);
                                __builtin_trap();
                        }
                        if(!sf)
                        {
                            val &= 0xffffffff;
                        }
                    }
                    if(size == 8)
                    {
                        if(idx)
                        {
                            HOST_SET(state, Rt, host_idx_get(state, idx-1, laddr));
                        }
                        else
                        {
                            if(macho_is_ptr(macho, ldr_addr))
                            {
                                bool bind = false;
                                val = macho_fixup(macho, val, &bind, NULL, NULL, NULL);
                                if(bind) val = 0;
                            }
                            HOST_SET(state, Rt, 0);
                        }
                    }
                    else
                    {
                        HOST_SET(state, Rt, 0);
                    }
                    state->x[Rt] = val;
                    state->valid |= 1 << Rt;
                    state->wide = (state->wide & ~(1 << Rt)) | (sf << Rt);
                }
                state->x[Rn] += wboff;
            }
        }
        else if(is_ldr_lit(ptr))
        {
            const ldr_lit_t *ldr = ptr;
            if(ldr->Rt != 31)
            {
                kptr_t laddr = addr + get_ldr_lit_off(ldr);
                const void *ldr_addr = macho_vtop(macho, laddr, ldr->sf ? 8 : 4);
                if(!ldr_addr)
                {
                    WRN("Load address outside of all segments at " ADDR " (" ADDR ")", addr, laddr);
                    return kEmuErr;
                }
                kptr_t val;
                if(ldr->sf)
                {
                    val = *(const uint64_t*)ldr_addr;
                    if(macho_is_ptr(macho, ldr_addr))
                    {
                        bool bind = false;
                        val = macho_fixup(macho, val, &bind, NULL, NULL, NULL);
                        if(bind) val = 0;
                    }
                }
                else
                {
                    val = *(const uint32_t*)ldr_addr;
                }
                state->x[ldr->Rt] = val;
                state->valid |= 1 << ldr->Rt;
                state->wide = (state->wide & ~(1 << ldr->Rt)) | (ldr->sf << ldr->Rt);
                HOST_SET(state, ldr->Rt, 0);
            }
        }
        else if(is_ldp_pre(ptr) || is_ldp_post(ptr) || is_ldp_uoff(ptr))
        {
            const ldp_t *ldp = ptr;
            if(!(state->valid & (1 << ldp->Rn))) // Unset validity
            {
                state->valid &= ~((1 << ldp->Rt) | (1 << ldp->Rt2));
            }
            else if(ldp->Rt != 31 || ldp->Rt2 != 31)
            {
                kptr_t laddr = state->x[ldp->Rn] + get_ldp_stp_off(ldp);
                if(is_ldp_pre(ldp))
                {
                    state->x[ldp->Rn] = laddr;
                }
                else if(is_ldp_post(ldp))
                {
                    kptr_t tmp = state->x[ldp->Rn];
                    state->x[ldp->Rn] = laddr;
                    laddr = tmp;
                }
                uint8_t idx = HOST_GET(state, ldp->Rn);
                size_t size = ldp->sf ? 16 : 8;
                const void *ldr_addr = idx ? (HOST_IN_RANGE(state, idx-1, laddr, size) ? (const void*)laddr : NULL) : macho_vtop(macho, laddr, size);
                if(!ldr_addr)
                {
                    if(idx)
                    {
                        WRN("Load address outside of host mem at " ADDR, addr);
                    }
                    else
                    {
                        WRN("Load address outside of all segments at " ADDR " (" ADDR ")", addr, laddr);
                    }
                    return kEmuErr;
                }
                if(ldp->sf)
                {
                    const uint64_t *p = ldr_addr;
                    uint64_t v1 = p[0];
                    uint64_t v2 = p[1];
                    uint8_t RtIdx, Rt2Idx;
                    if(idx)
                    {
                        RtIdx  = host_idx_get(state, idx-1, laddr    );
                        Rt2Idx = host_idx_get(state, idx-1, laddr + 8);
                    }
                    else
                    {
                        if(macho_is_ptr(macho, ldr_addr))
                        {
                            bool bind = false;
                            v1 = macho_fixup(macho, v1, &bind, NULL, NULL, NULL);
                            if(bind) v1 = 0;
                        }
                        if(macho_is_ptr(macho, ldr_addr + 1))
                        {
                            bool bind = false;
                            v2 = macho_fixup(macho, v2, &bind, NULL, NULL, NULL);
                            if(bind) v2 = 0;
                        }
                        RtIdx  = 0;
                        Rt2Idx = 0;
                    }
                    if(ldp->Rt != 31)
                    {
                        state->x[ldp->Rt] = v1;
                        HOST_SET(state, ldp->Rt, RtIdx);
                        state->wide |= 1 << ldp->Rt;
                    }
                    if(ldp->Rt2 != 31)
                    {
                        state->x[ldp->Rt2] = v2;
                        HOST_SET(state, ldp->Rt2, Rt2Idx);
                        state->wide |= 1 << ldp->Rt2;
                    }
                }
                else
                {
                    const uint32_t *p = ldr_addr;
                    if(ldp->Rt != 31)
                    {
                        state->x[ldp->Rt] = p[0];
                        HOST_SET(state, ldp->Rt, 0);
                        state->wide &= ~(1 << ldp->Rt);
                    }
                    if(ldp->Rt2 != 31)
                    {
                        state->x[ldp->Rt2] = p[1];
                        HOST_SET(state, ldp->Rt2, 0);
                        state->wide &= ~(1 << ldp->Rt2);
                    }
                }
                if(ldp->Rt  != 31) state->valid |= (1 << ldp->Rt);
                if(ldp->Rt2 != 31) state->valid |= (1 << ldp->Rt2);
            }
        }
        else if(is_ldxr(ptr))
        {
            const ldxr_t *ldxr = ptr;
            if(!(state->valid & (1 << ldxr->Rn))) // Unset validity
            {
                state->valid &= ~(1 << ldxr->Rt);
            }
            else if(ldxr->Rt != 31)
            {
                kptr_t laddr = state->x[ldxr->Rn];
                uint8_t idx = HOST_GET(state, ldxr->Rn);
                size_t size = ldxr->sf ? 8 : 4;
                const void *ldr_addr = idx ? (HOST_IN_RANGE(state, idx-1, laddr, size) ? (const void*)laddr : NULL) : macho_vtop(macho, laddr, size);
                if(!ldr_addr)
                {
                    if(idx)
                    {
                        WRN("Load address outside of host mem at " ADDR, addr);
                    }
                    else
                    {
                        WRN("Load address outside of all segments at " ADDR " (" ADDR ")", addr, laddr);
                    }
                    return kEmuErr;
                }
                uint64_t val;
                if(ldxr->sf)
                {
                    val = *(uint64_t*)ldr_addr;
                    if(idx)
                    {
                        HOST_SET(state, ldxr->Rt, host_idx_get(state, idx-1, laddr));
                    }
                    else
                    {
                        if(macho_is_ptr(macho, ldr_addr))
                        {
                            bool bind = false;
                            val = macho_fixup(macho, val, &bind, NULL, NULL, NULL);
                            if(bind) val = 0;
                        }
                        HOST_SET(state, ldxr->Rt, 0);
                    }
                }
                else
                {
                    val = *(uint32_t*)ldr_addr;
                    HOST_SET(state, ldxr->Rt, 0);
                }
                state->x[ldxr->Rt] = val;
                state->valid |= 1 << ldxr->Rt;
                state->wide = (state->wide & ~(1 << ldxr->Rt)) | (ldxr->sf << ldxr->Rt);
            }
        }
        else if(is_ldadd(ptr))
        {
            const ldadd_t *ldadd = ptr;
            if(!(state->valid & (1 << ldadd->Rn))) // Unset validity
            {
                if(ldadd->Rt != 31)
                {
                    state->valid &= ~(1 << ldadd->Rt);
                }
            }
            else
            {
                kptr_t daddr = state->x[ldadd->Rn];
                uint8_t idx = HOST_GET(state, ldadd->Rn);
                size_t size = ldadd->sf ? 8 : 4;
                void *ld_addr = idx ? (HOST_IN_RANGE(state, idx-1, daddr, size) ? (void*)daddr : NULL) : macho_vtop(macho, daddr, size);
                if(!ld_addr)
                {
                    if(idx)
                    {
                        WRN("Load address outside of host mem at " ADDR, addr);
                    }
                    else
                    {
                        WRN("Load address outside of all segments at " ADDR " (" ADDR ")", addr, daddr);
                    }
                    return kEmuErr;
                }
                uint64_t val = ldadd->sf ? *(uint64_t*)ld_addr : *(uint32_t*)ld_addr;
                if(ldadd->Rt != 31)
                {
                    state->x[ldadd->Rt] = val;
                    state->valid |= 1 << ldadd->Rt;
                    state->wide = (state->wide & ~(1 << ldadd->Rt)) | (ldadd->sf << ldadd->Rt);
                    HOST_SET(state, ldadd->Rt, 0);
                }
                if(idx)
                {
                    if(ldadd->Rs != 31 && !(state->valid & (1 << ldadd->Rs)))
                    {
                        if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                        else         DBG(1, "Cannot store invalid value to host mem at " ADDR, addr);
                        return kEmuUnknown;
                    }
                    val += ldadd->Rs == 31 ? 0 : state->x[ldadd->Rs];
                    if(ldadd->sf)
                    {
                        *(uint64_t*)ld_addr = val;
                        host_idx_set(state, idx-1, daddr, 8, 0);
                    }
                    else
                    {
                        *(uint32_t*)ld_addr = (uint32_t)val;
                        host_idx_set(state, idx-1, daddr, 4, 0);
                    }
                }
            }
        }
        else if(is_ldr_fp_uoff(ptr) || is_ldur_fp(ptr))
        {
            uint32_t Rt, Rn, size;
            int64_t off;
            if(is_ldr_fp_uoff(ptr))
            {
                const ldr_fp_uoff_t *ldr = ptr;
                Rt = ldr->Rt;
                Rn = ldr->Rn;
                size = get_fp_uoff_size(ldr);
                off = get_fp_uoff(ldr);
            }
            else if(is_ldur_fp(ptr))
            {
                const ldur_fp_t *ldur = ptr;
                Rt = ldur->Rt;
                Rn = ldur->Rn;
                size = get_ldur_stur_fp_size(ldur);
                off = get_ldur_stur_fp_off(ldur);
            }
            else
            {
                ERR("Bug in a64_emulate (case ldr_fp_uoff) at " ADDR, addr);
                __builtin_trap();
            }
            if(!(state->valid & (1 << Rn))) // Unset validity
            {
                state->qvalid &= ~(1 << Rt);
            }
            else
            {
                kptr_t laddr = state->x[Rn] + off;
                uint8_t idx = HOST_GET(state, Rn);
                const void *ldr_addr = idx ? (HOST_IN_RANGE(state, idx-1, laddr, 1 << size) ? (void*)laddr : NULL) : macho_vtop(macho, laddr, 1 << size);
                if(!ldr_addr)
                {
                    if(idx)
                    {
                        WRN("Load address outside of host mem at " ADDR, addr);
                    }
                    else
                    {
                        WRN("Load address outside of all segments at " ADDR " (" ADDR ")", addr, laddr);
                    }
                    return kEmuErr;
                }
                switch(size)
                {
                    case 0: state->q[Rt] = *(const uint8_t *)ldr_addr; break;
                    case 1: state->q[Rt] = *(const uint16_t*)ldr_addr; break;
                    case 2: state->q[Rt] = *(const uint32_t*)ldr_addr; break;
                    case 3: state->q[Rt] = *(const uint64_t*)ldr_addr; break;
                    case 4:
                    {
                        __uint128_t val = 0;
                        val |= (__uint128_t)((const uint64_t*)ldr_addr)[0];
                        val |= (__uint128_t)((const uint64_t*)ldr_addr)[1] << 64;
                        state->q[Rt] = val;
                        break;
                    }
                    default:
                        WRN("SIMD ldr with invalid size at " ADDR, addr);
                        return kEmuErr;
                }
                state->qvalid |= 1 << Rt;
            }
        }
        else if(is_str_fp_uoff(ptr) || is_stur_fp(ptr))
        {
            uint32_t Rt, Rn, size;
            int64_t off;
            if(is_str_fp_uoff(ptr))
            {
                const str_fp_uoff_t *str = ptr;
                Rt = str->Rt;
                Rn = str->Rn;
                size = get_fp_uoff_size(str);
                off = get_fp_uoff(str);
            }
            else if(is_stur_fp(ptr))
            {
                const stur_fp_t *stur = ptr;
                Rt = stur->Rt;
                Rn = stur->Rn;
                size = get_ldur_stur_fp_size(stur);
                off = get_ldur_stur_fp_off(stur);
            }
            else
            {
                ERR("Bug in a64_emulate (case str_fp_uoff) at " ADDR, addr);
                __builtin_trap();
            }
            uint8_t idx;
            if((state->valid & (1 << Rn)) && (idx = HOST_GET(state, Rn)))
            {
                if(!(state->qvalid & (1 << Rt)))
                {
                    if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                    else         DBG(1, "Cannot store invalid value to host mem at " ADDR, addr);
                    return kEmuUnknown;
                }
                --idx;
                kptr_t staddr = state->x[Rn] + off;
                if(HOST_IN_RANGE(state, idx, staddr, 1 << size))
                {
                    switch(size)
                    {
                        case 0: *(uint8_t *)staddr = (uint8_t )state->q[Rt]; break;
                        case 1: *(uint16_t*)staddr = (uint16_t)state->q[Rt]; break;
                        case 2: *(uint32_t*)staddr = (uint32_t)state->q[Rt]; break;
                        case 3: *(uint64_t*)staddr = (uint64_t)state->q[Rt]; break;
                        case 4:
                        {
                            ((uint64_t*)staddr)[0] = (uint64_t) state->q[Rt];
                            ((uint64_t*)staddr)[1] = (uint64_t)(state->q[Rt] >> 64);
                            break;
                        }
                        default:
                            WRN("SIMD str with invalid size at " ADDR, addr);
                            return kEmuErr;
                    }
                    if(size == 4)
                    {
                        host_idx_set(state, idx, staddr,     8, 0);
                        host_idx_set(state, idx, staddr + 8, 8, 0);
                    }
                    else
                    {
                        host_idx_set(state, idx, staddr, 1 << size, 0);
                    }
                }
            }
        }
        else if(is_ldp_fp_pre(ptr) || is_ldp_fp_post(ptr) || is_ldp_fp_uoff(ptr))
        {
            const ldp_fp_t *ldp = ptr;
            if(!(state->valid & (1 << ldp->Rn))) // Unset validity
            {
                state->qvalid &= ~((1 << ldp->Rt) | (1 << ldp->Rt2));
            }
            else
            {
                kptr_t laddr = state->x[ldp->Rn] + get_ldp_stp_fp_off(ldp);
                if(is_ldp_fp_pre(ldp))
                {
                    state->x[ldp->Rn] = laddr;
                }
                else if(is_ldp_fp_post(ldp))
                {
                    kptr_t tmp = state->x[ldp->Rn];
                    state->x[ldp->Rn] = laddr;
                    laddr = tmp;
                }
                uint8_t idx = HOST_GET(state, ldp->Rn);
                size_t size = 8 << ldp->opc;
                const void *ldr_addr = idx ? (HOST_IN_RANGE(state, idx-1, laddr, size) ? (void*)laddr : NULL) : macho_vtop(macho, laddr, size);
                if(!ldr_addr)
                {
                    if(idx)
                    {
                        WRN("Load address outside of host mem at " ADDR, addr);
                    }
                    else
                    {
                        WRN("Load address outside of all segments at " ADDR " (" ADDR ")", addr, laddr);
                    }
                    return kEmuErr;
                }
                switch(ldp->opc)
                {
                    case 0:
                    {
                        uint32_t *p = (uint32_t*)ldr_addr;
                        state->q[ldp->Rt]  = p[0];
                        state->q[ldp->Rt2] = p[1];
                        break;
                    }
                    case 1:
                    {
                        uint64_t *p = (uint64_t*)ldr_addr;
                        state->q[ldp->Rt]  = p[0];
                        state->q[ldp->Rt2] = p[1];
                        break;
                    }
                    case 2:
                    {
                        uint64_t *p = (uint64_t*)ldr_addr;
                        __uint128_t v1 = 0,
                                    v2 = 0;
                        v1 |= (__uint128_t)p[0];
                        v1 |= (__uint128_t)p[1] << 64;
                        v2 |= (__uint128_t)p[2];
                        v2 |= (__uint128_t)p[3] << 64;
                        state->q[ldp->Rt]  = v1;
                        state->q[ldp->Rt2] = v2;
                        break;
                    }
                    default:
                        WRN("SIMD ldp with invalid size at " ADDR, addr);
                        return kEmuErr;
                }
                state->qvalid |= (1 << ldp->Rt) | (1 << ldp->Rt2);
            }
        }
        else if(is_stp_fp_pre(ptr) || is_stp_fp_post(ptr) || is_stp_fp_uoff(ptr))
        {
            const stp_fp_t *stp = ptr;
            if(state->valid & (1 << stp->Rn)) // Only if valid
            {
                kptr_t staddr = state->x[stp->Rn] + get_ldp_stp_fp_off(stp);
                if(is_stp_fp_pre(stp))
                {
                    state->x[stp->Rn] = staddr;
                }
                else if(is_stp_fp_post(stp))
                {
                    kptr_t tmp = state->x[stp->Rn];
                    state->x[stp->Rn] = staddr;
                    staddr = tmp;
                }
                uint8_t idx = HOST_GET(state, stp->Rn);
                if(idx)
                {
                    if(!(state->qvalid & (1 << stp->Rt)) || !(state->qvalid & (1 << stp->Rt2)))
                    {
                        if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                        else         DBG(1, "Cannot store invalid value to host mem at " ADDR, addr);
                        return kEmuUnknown;
                    }
                    --idx;
                    switch(stp->opc)
                    {
                        case 0:
                        {
                            uint32_t *p = (uint32_t*)staddr;
                            p[0] = (uint32_t)state->q[stp->Rt];
                            p[1] = (uint32_t)state->q[stp->Rt2];
                            host_idx_set(state, idx, staddr, 8, 0);
                            break;
                        }
                        case 1:
                        {
                            uint64_t *p = (uint64_t*)staddr;
                            p[0] = (uint64_t)state->q[stp->Rt];
                            p[1] = (uint64_t)state->q[stp->Rt2];
                            host_idx_set(state, idx, staddr,     8, 0);
                            host_idx_set(state, idx, staddr + 8, 8, 0);
                            break;
                        }
                        case 2:
                        {
                            uint64_t *p = (uint64_t*)staddr;
                            p[0] = (uint64_t) state->q[stp->Rt];
                            p[1] = (uint64_t)(state->q[stp->Rt] >> 64);
                            p[2] = (uint64_t) state->q[stp->Rt2];
                            p[3] = (uint64_t)(state->q[stp->Rt2] >> 64);
                            host_idx_set(state, idx, staddr,      8, 0);
                            host_idx_set(state, idx, staddr +  8, 8, 0);
                            host_idx_set(state, idx, staddr + 16, 8, 0);
                            host_idx_set(state, idx, staddr + 24, 8, 0);
                            break;
                        }
                        default:
                            WRN("SIMD stp with invalid size at " ADDR, addr);
                            return kEmuErr;
                    }
                }
            }
        }
        else if(is_movz(ptr))
        {
            const movz_t *movz = ptr;
            if(movz->Rd != 31)
            {
                state->x[movz->Rd] = get_movzk_imm(movz);
                state->valid |= 1 << movz->Rd;
                state->wide = (state->wide & ~(1 << movz->Rd)) | (movz->sf << movz->Rd);
                HOST_SET(state, movz->Rd, 0);
            }
        }
        else if(is_movk(ptr))
        {
            const movk_t *movk = ptr;
            if(movk->Rd != 31)
            {
                if(state->valid & (1 << movk->Rd)) // Only if valid
                {
                    state->x[movk->Rd] = (state->x[movk->Rd] & ~(0xffff << (movk->hw << 4))) | get_movzk_imm(movk);
                    state->valid |= 1 << movk->Rd;
                    state->wide = (state->wide & ~(1 << movk->Rd)) | (movk->sf << movk->Rd);
                    HOST_SET(state, movk->Rd, 0);
                }
            }
        }
        else if(is_movn(ptr))
        {
            const movn_t *movn = ptr;
            if(movn->Rd != 31)
            {
                state->x[movn->Rd] = get_movn_imm(movn);
                state->valid |= 1 << movn->Rd;
                state->wide = (state->wide & ~(1 << movn->Rd)) | (movn->sf << movn->Rd);
                HOST_SET(state, movn->Rd, 0);
            }
        }
        else if(is_movi(ptr))
        {
            const movi_t *movi = ptr;
            state->q[movi->Rd] = get_movi_imm(movi);
            state->qvalid |= 1 << movi->Rd;
        }
        else if(is_and(ptr) || is_ands(ptr) || is_orr(ptr) || is_eor(ptr))
        {
            bool want_nzcv = is_ands(ptr);
            const orr_t *orr = ptr;
            if(orr->Rn == 31 || (state->valid & (1 << orr->Rn)))
            {
                uint64_t Rd,
                         Rn = (orr->Rn == 31 ? 0 : state->x[orr->Rn]),
                         Rm = get_orr_imm(orr);
                uint8_t idx = 0;
                if(is_and(orr) || is_ands(orr))
                {
                    Rd = Rn & Rm;
                    if(orr->sf && orr->Rn != 31 && __builtin_clzll(Rm) == 0)
                    {
                        idx = HOST_GET(state, orr->Rn);
                    }
                }
                else if(is_orr(orr))
                {
                    Rd = Rn | Rm;
                }
                else if(is_eor(orr))
                {
                    Rd = Rn ^ Rm;
                }
                else
                {
                    ERR("Bug in a64_emulate (case and/orr/eor) at " ADDR, addr);
                    __builtin_trap();
                }
                if(want_nzcv)
                {
                    update_nzcv(state, Rd, Rn, Rm, !!orr->sf);
                }
                if(!want_nzcv || orr->Rd != 31)
                {
                    state->x[orr->Rd] = Rd;
                    state->valid |= 1 << orr->Rd;
                    state->wide = (state->wide & ~(1 << orr->Rd)) | (orr->sf << orr->Rd);
                    HOST_SET(state, orr->Rd, idx);
                }
            }
            else
            {
                if(!want_nzcv || orr->Rd != 31)
                {
                    state->valid &= ~(1 << orr->Rd);
                }
                if(want_nzcv)
                {
                    state->nzcv_valid = 0;
                }
            }
        }
        else if(is_and_reg(ptr) || is_ands_reg(ptr) || is_orr_reg(ptr) || is_eor_reg(ptr))
        {
            bool want_nzcv = is_ands_reg(ptr);
            const orr_reg_t *orr = ptr;
            if((orr->Rn == 31 || (state->valid & (1 << orr->Rn))) && (orr->Rm == 31 || (state->valid & (1 << orr->Rm))))
            {
                uint64_t Rn = (orr->Rn == 31 ? 0 : state->x[orr->Rn]),
                         Rm = (orr->Rm == 31 ? 0 : state->x[orr->Rm]);
                switch(orr->shift)
                {
                    case 0b00: Rm =          Rm << orr->imm; break; // LSL
                    case 0b01: Rm =          Rm >> orr->imm; break; // LSR
                    case 0b10: Rm = (int64_t)Rm >> orr->imm; break; // ASR
                    default:
                        WRN("Bad and/orr/eor shift at " ADDR, addr);
                        return kEmuErr;
                }
                uint64_t Rd;
                if(is_and_reg(orr) || is_ands_reg(orr))
                {
                    Rd = Rn & Rm;
                }
                else if(is_orr_reg(orr))
                {
                    Rd = Rn | Rm;
                }
                else if(is_eor_reg(orr))
                {
                    Rd = Rn ^ Rm;
                }
                else
                {
                    ERR("Bug in a64_emulate (case and_reg/orr_reg/eor_reg) at " ADDR, addr);
                    __builtin_trap();
                }
                if(want_nzcv)
                {
                    update_nzcv(state, Rd, Rn, Rm, !!orr->sf);
                }
                if(orr->Rd != 31)
                {
                    state->x[orr->Rd] = Rd;
                    state->valid |= 1 << orr->Rd;
                    // Because mov is an alias of orr
                    if(orr->sf)
                    {
                        if(orr->Rn == 31 && orr->imm == 0)
                        {
                            state->wide = (state->wide & ~(1 << orr->Rd)) | (((state->wide >> orr->Rm) & 0x1) << orr->Rd);
                            HOST_SET(state, orr->Rd, HOST_GET(state, orr->Rm));
                        }
                        else if(orr->Rm == 31)
                        {
                            state->wide = (state->wide & ~(1 << orr->Rd)) | (((state->wide >> orr->Rn) & 0x1) << orr->Rd);
                            HOST_SET(state, orr->Rd, HOST_GET(state, orr->Rn));
                        }
                        else
                        {
                            state->wide |= 1 << orr->Rd;
                            HOST_SET(state, orr->Rd, 0);
                        }
                    }
                    else
                    {
                        state->wide &= ~(1 << orr->Rd);
                        HOST_SET(state, orr->Rd, 0);
                    }
                }
            }
            else
            {
                if(orr->Rd != 31)
                {
                    state->valid &= ~(1 << orr->Rd);
                }
                if(want_nzcv)
                {
                    state->nzcv_valid = 0;
                }
            }
        }
        else if(is_blr(ptr) || is_br(ptr) || is_blra(ptr) || is_bra(ptr))
        {
            bool link = is_blr(ptr) || is_blra(ptr);
            if(link && !(fn_behaviour & kEmuFnEnter))
            {
                state->valid &= 0xbff80001;
                if(!(fn_behaviour & kEmuFnAssumeX0) || !((state->valid & 0x1) && HOST_GET(state, 0)))
                {
                    state->valid &= ~0x1;
                }
                state->qvalid &= 0xff00; // blindly assuming 128bit shit is handled as needed
            }
            else
            {
                uint32_t Rn = is_br(ptr) ? ((const br_t*)ptr)->Rn : ((const bra_t*)ptr)->Rn;
                if(Rn == 31 || !(state->valid & (1 << Rn)) || !(state->wide & (1 << Rn)))
                {
                    if(warnUnknown) WRN("Cannot branch to invalid value at " ADDR, addr);
                    else         DBG(1, "Cannot branch to invalid value at " ADDR, addr);
                    return kEmuUnknown;
                }
                if(HOST_GET(state, Rn))
                {
                    WRN("Cannot branch to host address at " ADDR, addr);
                    return kEmuErr;
                }
                from = macho_vtop(macho, state->x[Rn], 0);
                if(!from)
                {
                    WRN("Branch address outside of all segments at " ADDR " (" ADDR ")", addr, state->x[Rn]);
                    return kEmuErr;
                }
                if(link)
                {
                    DBG(3, "Entering indirect function call at " ADDR " to " ADDR, addr, state->x[Rn]);
                    state->x[30] = addr + 4;
                    state->valid |= 1 << 30;
                    state->wide  |= 1 << 30;
                    HOST_SET(state, 30, 0);
                }
                else
                {
                    DBG(3, "Following indirect branch at " ADDR " to " ADDR, addr, state->x[Rn]);
                }
                --from;
            }
        }
        else if(is_bl(ptr) || is_b(ptr))
        {
            bool link = is_bl(ptr);
            if(link && !(fn_behaviour & kEmuFnEnter))
            {
                state->valid &= 0xbff80001;
                if(!(fn_behaviour & kEmuFnAssumeX0) || !((state->valid & 0x1) && HOST_GET(state, 0)))
                {
                    state->valid &= ~0x1;
                }
                state->qvalid &= 0xff00; // blindly assuming 128bit shit is handled as needed
            }
            else
            {
                if(link)
                {
                    DBG(3, "Entering function call at " ADDR " to " ADDR, addr, addr + get_bl_off(ptr));
                    state->x[30] = addr + 4;
                    state->valid |= 1 << 30;
                    state->wide  |= 1 << 30;
                    HOST_SET(state, 30, 0);
                }
                from = (uint32_t*)((uintptr_t)from + get_bl_off(ptr));
                --from;
            }
        }
        else if(is_b_cond(ptr))
        {
            const b_cond_t *b = ptr;
            if(!state->nzcv_valid)
            {
                if(warnUnknown) WRN("Cannot do conditional branch with invalid flags at " ADDR, addr);
                else         DBG(1, "Cannot do conditional branch with invalid flags at " ADDR, addr);
                return kEmuUnknown;
            }
            bool match;
            switch(b->cond)
            {
                case 0x0: // eq
                    match = state->z == 1;
                    break;
                case 0x1: // ne
                    match = state->z == 0;
                    break;
                case 0x2: // hs
                    match = state->c == 1;
                    break;
                case 0x3: // lo
                    match = state->c == 0;
                    break;
                case 0x4: // mi
                    match = state->n == 1;
                    break;
                case 0x5: // pl
                    match = state->n == 0;
                    break;
                case 0x6: // vs
                    match = state->v == 1;
                    break;
                case 0x7: // vc
                    match = state->v == 0;
                    break;
                case 0x8: // hi
                    match = state->c == 1 && state->z == 0;
                    break;
                case 0x9: // ls
                    match = !(state->c == 1 && state->z == 0);
                    break;
                case 0xa: // ge
                    match = state->n == state->v;
                    break;
                case 0xb: // lt
                    match = state->n != state->v;
                    break;
                case 0xc: // gt
                    match = state->z == 0 && state->n == state->v;
                    break;
                case 0xd: // le
                    match = !(state->z == 0 && state->n == state->v);
                    break;
                case 0xe: // al
                case 0xf: // nv
                    match = true;
                    break;
            }
            if(match)
            {
                from = (uint32_t*)((uintptr_t)from + get_b_cond_off(b));
                --from;
            }
        }
        else if(is_cbz(ptr) || is_cbnz(ptr))
        {
            const cbz_t *cbz = ptr;
            if(!(state->valid & (1 << cbz->Rt)))
            {
                if(warnUnknown) WRN("Cannot decide cbz/cbnz at " ADDR, addr);
                else         DBG(1, "Cannot decide cbz/cbnz at " ADDR, addr);
                return kEmuUnknown;
            }
            if((state->x[cbz->Rt] == 0) == is_cbz(cbz))
            {
                from = (uint32_t*)((uintptr_t)from + get_cbz_off(cbz));
                --from;
            }
        }
        else if(is_tbz(ptr) || is_tbnz(ptr))
        {
            const tbz_t *tbz = ptr;
            uint32_t bit = get_tbz_bit(tbz);
            if(tbz->Rt != 31 && (!(state->valid & (1 << tbz->Rt)) || (bit >= 32 && !(state->wide & (1 << tbz->Rt)))))
            {
                if(warnUnknown) WRN("Cannot decide tbz/tbnz at " ADDR, addr);
                else         DBG(1, "Cannot decide tbz/tbnz at " ADDR, addr);
                return kEmuUnknown;
            }
            if((((tbz->Rt == 31 ? 0 : state->x[tbz->Rt]) & (1 << bit)) == 0) == is_tbz(tbz))
            {
                from = (uint32_t*)((uintptr_t)from + get_tbz_off(tbz));
                --from;
            }
        }
        else if(is_ret(ptr))
        {
            if(fn_behaviour & kEmuFnEnter)
            {
                if(!(state->valid & (1 << 30)) || !(state->wide & (1 << 30)))
                {
                    if(warnUnknown) WRN("Cannot return at " ADDR, addr);
                    else         DBG(1, "Cannot return at " ADDR, addr);
                    return kEmuUnknown;
                }
                if(HOST_GET(state, 30))
                {
                    WRN("Cannot return to host address at " ADDR, addr);
                    return kEmuErr;
                }
                DBG(3, "Returning from function at " ADDR, state->x[30]);
                // TODO: This is really dirty, but... whatcha gonna do?
                if(state->x[30] != 0)
                {
                    from = macho_vtop(macho, state->x[30], 0);
                    if(!from)
                    {
                        WRN("Return address outside of all segments at " ADDR " (" ADDR ")", addr, state->x[30]);
                        return kEmuErr;
                    }
                    --from;
                    continue;
                }
            }
            return kEmuRet;
        }
        else
        {
            WRN("Unexpected instruction at " ADDR, addr);
            return kEmuErr;
        }
    }
    return kEmuEnd;
}

// This is a very annoying thing that we only need as a fallback.
// Certain calls to OSMetaClass::OSMetaClass() do not have x0 generated as an immediate,
// but passed in from the caller. If these are the only constructor calls for a given class,
// then we have no choice but to follow those calls back until we get an x0.
bool multi_call_emulate(macho_t *macho, const uint32_t *fncall, const uint32_t *end, a64_state_t *state, void *sp, uint8_t *bitstr, uint32_t wantvalid, const char *name)
{
    const void *segptr = NULL;
    kptr_t segaddr = 0;
    size_t segsize = 0;
    if(!macho_segment_for_ptr(macho, fncall, &segptr, &segaddr, &segsize, NULL))
    {
        ERR("Bug in multi_call_emulate: fncall ptr is not in any segment.");
        __builtin_trap();
    }

    kptr_t fncalladdr = (uintptr_t)fncall - (uintptr_t)segptr + segaddr;

    bool have_stack_frame;
    const bl_t *bl = (const bl_t*)fncall;
    if(is_bl(bl))
    {
        have_stack_frame = true;
    }
    else if(is_b(bl))
    {
        have_stack_frame = false;
    }
    else
    {
        ERR("Bug in multi_call_emulate: fncall at " ADDR " is neither b nor bl.", fncalladdr);
        __builtin_trap();
    }
    const uint32_t *fnstart = find_function_start(macho, name, fncall, segptr, have_stack_frame);
    if(!fnstart)
    {
        return false;
    }
    kptr_t fnaddr = (uintptr_t)fnstart - (uintptr_t)segptr + segaddr;
    DBG(1, "Function with call " ADDR " starts at " ADDR, fncalladdr, fnaddr);

    bool deep = false;
    while(1)
    {
        bzero(sp, A64_EMU_SPSIZE);
        bzero(bitstr, (A64_EMU_SPSIZE + 31) / 32);
        for(size_t i = 0; i < 31; ++i)
        {
            state->x[i] = 0;
            state->q[i] = 0;
        }
        state->q[31]  = 0;
        state->x[31]  = (uintptr_t)sp + A64_EMU_SPSIZE;
        state->flags  = 0;
        state->valid  = 0xfff80000;
        state->qvalid = 0x0000ff00;
        state->wide   = 0xfff80000;
        state->host   = 0;
        HOST_SET(state, 31, 1);
        state->hostmem[0].min = (uintptr_t)sp;
        state->hostmem[0].max = (uintptr_t)sp + A64_EMU_SPSIZE;
        state->hostmem[0].bitstring = bitstr;
        emu_ret_t ret;
        if(deep)
        {
            // Second iteration: we only get here if the first iteration didn't work, so now we descend into functions
            ret = a64_emulate(macho, state, fnstart, &a64cb_check_equal, (void*)end, false, false, kEmuFnEnter);
        }
        else
        {
            // First iteration: skip all function calls except the target one, hope that the missing values are function-local immediates
            ret = a64_emulate(macho, state, fnstart, &a64cb_check_equal, (void*)fncall, false, false, kEmuFnIgnore);
            if(ret == kEmuEnd)
            {
                ret = a64_emulate(macho, state, fncall, &a64cb_check_equal, (void*)end, false, false, kEmuFnEnter);
            }
        }
        switch(ret)
        {
            default:
            case kEmuRet:
                // This should be impossible
                ERR("Bug in a64_emulate: got %u for kEmuFnEnter.", ret);
                __builtin_trap();

            case kEmuErr:
                // This is a fatal error, so no point in trying further.
                return false;

            case kEmuEnd:
                // This is the only possibly successful case. Just need to make sure we got everything we need.
                if((state->valid & wantvalid) == wantvalid)
                {
                    DBG(1, "Got a satisfying function call stack at " ADDR, fnaddr);
                    return true;
                }
                // Otherwise fall through

            case kEmuUnknown:
                // This means we don't have enough info yet, so break into the code below and do another call level.
                break;
        }
        if(deep)
        {
            break;
        }
        deep = true;
    }

    DBG(1, "Searching for function calls to " ADDR, fnaddr);
    STEP_MEM(uint32_t, mem, segptr, segsize, 1)
    {
        bl_t *bl = (bl_t*)mem;
        if(is_bl(bl) || is_b(bl))
        {
            kptr_t bladdr = (uintptr_t)bl - (uintptr_t)segptr + segaddr;
            kptr_t bltarg = bladdr + get_bl_off(bl);
            if(bltarg == fnaddr && multi_call_emulate(macho, mem, end, state, sp, bitstr, wantvalid, name))
            {
                return true;
            }
        }
    }
    return false;
}
