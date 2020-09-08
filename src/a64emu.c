#include <stdbool.h>
#include <stddef.h>             // size_t
#include <stdint.h>
#include <stdlib.h>             // exit

#include "a64.h"
#include "a64emu.h"
#include "macho.h"
#include "util.h"

bool is_linear_inst(void *ptr)
{
    return is_adr(ptr) ||
           is_adrp(ptr) ||
           is_add_imm(ptr) ||
           is_sub_imm(ptr) ||
           is_add_reg(ptr) ||
           is_sub_reg(ptr) ||
           is_ldr_imm_uoff(ptr) ||
           is_ldr_lit(ptr) ||
           is_ldp_pre(ptr) ||
           is_ldp_post(ptr) ||
           is_ldp_uoff(ptr) ||
           is_ldxr(ptr) ||
           is_ldadd(ptr) ||
           is_ldur(ptr) ||
           is_ldr_fp_uoff(ptr) ||
           is_ldur_fp(ptr) ||
           is_ldp_fp_pre(ptr) ||
           is_ldp_fp_post(ptr) ||
           is_ldp_fp_uoff(ptr) ||
           is_bl(ptr) ||
           is_mov(ptr) ||
           is_movz(ptr) ||
           is_movk(ptr) ||
           is_movn(ptr) ||
           is_movi(ptr) ||
           is_orr(ptr) ||
           is_str_pre(ptr) ||
           is_str_post(ptr) ||
           is_str_uoff(ptr) ||
           is_stp_pre(ptr) ||
           is_stp_post(ptr) ||
           is_stp_uoff(ptr) ||
           is_stxr(ptr) ||
           is_stur(ptr) ||
           is_str_fp_uoff(ptr) ||
           is_stur_fp(ptr) ||
           is_stp_fp_pre(ptr) ||
           is_stp_fp_post(ptr) ||
           is_stp_fp_uoff(ptr) ||
           is_ldrb_imm_uoff(ptr) ||
           is_ldrh_imm_uoff(ptr) ||
           is_ldrsb_imm_uoff(ptr) ||
           is_ldrsh_imm_uoff(ptr) ||
           is_ldrsw_imm_uoff(ptr) ||
           is_strb_imm_uoff(ptr) ||
           is_strh_imm_uoff(ptr) ||
           is_pac(ptr) ||
           is_pacsys(ptr) ||
           is_pacga(ptr) ||
           is_aut(ptr) ||
           is_autsys(ptr) ||
           is_nop(ptr);
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
uint32_t* find_function_start(void *kernel, mach_seg_t *seg, const char *name, uint32_t *fnstart, bool have_stack_frame)
{
    while(1)
    {
        --fnstart;
        if(fnstart < (uint32_t*)((uintptr_t)kernel + seg->fileoff))
        {
            // If we expect a stack frame, this is fatal.
            if(have_stack_frame)
            {
                WRN("Hit start of segment at " ADDR " for %s", seg->vmaddr + ((uintptr_t)fnstart - ((uintptr_t)kernel + seg->fileoff)), name);
                return NULL;
            }
            // Otherwise ehh whatever.
            DBG("Hit start of segment at " ADDR " for %s", seg->vmaddr + ((uintptr_t)fnstart - ((uintptr_t)kernel + seg->fileoff)), name);
            ++fnstart;
            break;
        }
        if(!is_linear_inst(fnstart) || (is_bl((bl_t*)fnstart) && !have_stack_frame))
        {
            ++fnstart;
            break;
        }
        stp_t *stp = (stp_t*)fnstart;
        ldp_t *ldp = (ldp_t*)fnstart;
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

bool a64cb_check_equal(uint32_t *pos, void *arg)
{
    return pos != (uint32_t*)arg;
}

bool a64cb_check_bl(uint32_t *pos, void *arg)
{
    if(is_bl((bl_t*)pos))
    {
        *(uint32_t**)arg = pos;
        return false;
    }
    return true;
}

// Best-effort emulation: halt on unknown instructions, keep track of which registers
// hold known values and only operate on those. Ignore non-static memory unless
// it is specifically marked as "host memory".
emu_ret_t a64_emulate(void *kernel, kptr_t kbase, fixup_kind_t fixupKind, a64_state_t *state, uint32_t *from, a64cb_t check, void *arg, bool init, bool warnUnknown, emu_fn_behaviour_t fn_behaviour)
{
    if(init)
    {
        for(size_t i = 0; i < 32; ++i)
        {
            state->x[i] = 0;
            state->q[i] = 0;
        }
        state->valid = 0;
        state->wide = 0;
        state->host = 0;
    }
    for(; check(from, arg); ++from)
    {
        void *ptr = from;
        kptr_t addr = off2addr(kernel, (uintptr_t)from - (uintptr_t)kernel);
        if(is_nop(ptr) /*|| is_stp_fp_uoff(ptr)*/ || is_pac(ptr) || is_pacsys(ptr) || is_pacga(ptr) || is_aut(ptr) || is_autsys(ptr))
        {
            // Ignore/no change
        }
        else if(is_str_pre(ptr) || is_str_post(ptr))
        {
            str_imm_t *str = ptr;
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
                if(state->host & (1 << str->Rn))
                {
                    if(!(state->valid & (1 << str->Rt)))
                    {
                        if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                        else            DBG("Cannot store invalid value to host mem at " ADDR, addr);
                        return kEmuUnknown;
                    }
                    if(str->sf)
                    {
                        *(uint64_t*)staddr = state->x[str->Rt];
                    }
                    else
                    {
                        *(uint32_t*)staddr = (uint32_t)state->x[str->Rt];
                    }
                }
            }
        }
        else if(is_str_uoff(ptr) || is_stur(ptr) || is_strb_imm_uoff(ptr) || is_strh_imm_uoff(ptr))
        {
            uint32_t Rt, Rn, size;
            int64_t off;
            if(is_str_uoff(ptr))
            {
                str_uoff_t *str = ptr;
                Rt = str->Rt;
                Rn = str->Rn;
                size = 4 << str->sf;
                off = get_str_uoff(str);
            }
            else if(is_stur(ptr))
            {
                stur_t *stur = ptr;
                Rt = stur->Rt;
                Rn = stur->Rn;
                size = 4 << stur->sf;
                off = get_stur_off(stur);
            }
            else if(is_strb_imm_uoff(ptr))
            {
                strb_imm_uoff_t *strb = ptr;
                Rt = strb->Rt;
                Rn = strb->Rn;
                size = 1;
                off = get_strb_imm_uoff(strb);
            }
            else if(is_strh_imm_uoff(ptr))
            {
                strh_imm_uoff_t *strh = ptr;
                Rt = strh->Rt;
                Rn = strh->Rn;
                size = 2;
                off = get_strh_imm_uoff(strh);
            }
            else
            {
                return kEmuErr;
            }
            if((state->valid & (1 << Rn)) && (state->host & (1 << Rn)))
            {
                if(!(state->valid & (1 << Rt)))
                {
                    if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                    else            DBG("Cannot store invalid value to host mem at " ADDR, addr);
                    return kEmuUnknown;
                }
                kptr_t staddr = state->x[Rn] + off;
                switch(size)
                {
                    case 1: *(uint8_t *)staddr = (uint8_t )state->x[Rt]; break;
                    case 2: *(uint16_t*)staddr = (uint16_t)state->x[Rt]; break;
                    case 4: *(uint32_t*)staddr = (uint32_t)state->x[Rt]; break;
                    case 8: *(uint64_t*)staddr = (uint64_t)state->x[Rt]; break;
                    default:
                        ERR("Bug in a64_emulate: str_uoff with invalid size at " ADDR, addr);
                        exit(-1);
                }
            }
        }
        else if(is_stp_pre(ptr) || is_stp_post(ptr) || is_stp_uoff(ptr))
        {
            stp_t *stp = ptr;
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
                if(state->host & (1 << stp->Rn))
                {
                    if(!(state->valid & (1 << stp->Rt)) || !(state->valid & (1 << stp->Rt2)))
                    {
                        if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                        else            DBG("Cannot store invalid value to host mem at " ADDR, addr);
                        return kEmuUnknown;
                    }
                    if(stp->sf)
                    {
                        uint64_t *p = (uint64_t*)staddr;
                        p[0] = state->x[stp->Rt];
                        p[1] = state->x[stp->Rt2];
                    }
                    else
                    {
                        uint32_t *p = (uint32_t*)staddr;
                        p[0] = (uint32_t)state->x[stp->Rt];
                        p[1] = (uint32_t)state->x[stp->Rt2];
                    }
                }
            }
        }
        else if(is_stxr(ptr))
        {
            stxr_t *stxr = ptr;
            // Always set success
            state->x[stxr->Rs] = 0;
            state->valid  |= 1 << stxr->Rs;
            state->wide &= ~(1 << stxr->Rs);
            state->host &= ~(1 << stxr->Rs);
            if((state->valid & (1 << stxr->Rn)) && (state->host & (1 << stxr->Rn))) // Only if valid & host
            {
                if(!(state->valid & (1 << stxr->Rt)))
                {
                    if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                    else            DBG("Cannot store invalid value to host mem at " ADDR, addr);
                    return kEmuUnknown;
                }
                kptr_t staddr = state->x[stxr->Rn];
                if(stxr->sf)
                {
                    *(uint64_t*)staddr = state->x[stxr->Rt];
                }
                else
                {
                    *(uint32_t*)staddr = (uint32_t)state->x[stxr->Rt];
                }
            }
        }
        else if(is_adr(ptr) || is_adrp(ptr))
        {
            adr_t *adr = ptr;
            state->x[adr->Rd] = (adr->op1 ? (addr & ~0xfff) : addr) + get_adr_off(adr);
            state->valid |=   1 << adr->Rd;
            state->wide  |=   1 << adr->Rd;
            state->host  &= ~(1 << adr->Rd);
        }
        else if(is_add_imm(ptr) || is_sub_imm(ptr))
        {
            add_imm_t *add = ptr;
            if(!(state->valid & (1 << add->Rn))) // Unset validity
            {
                state->valid &= ~(1 << add->Rd);
            }
            else
            {
                state->x[add->Rd] = state->x[add->Rn] + (is_add_imm(add) ? 1LL : -1LL) * get_add_sub_imm(add);
                state->valid |= 1 << add->Rd;
                state->wide = (state->wide & ~(1 << add->Rd)) | (add->sf << add->Rd);
                state->host = (state->host & ~(1 << add->Rd)) | (((state->host >> add->Rn) & 0x1) << add->Rd);
            }
        }
        else if(is_add_reg(ptr) || is_sub_reg(ptr))
        {
            add_reg_t *add = ptr;
            if(!(state->valid & (1 << add->Rn)) || !(state->valid & (1 << add->Rm))) // Unset validity
            {
                state->valid &= ~(1 << add->Rd);
            }
            else
            {
                uint64_t Rm = state->x[add->Rm];
                switch(add->shift)
                {
                    case 0b00: Rm =          Rm << add->imm; break; // LSL
                    case 0b01: Rm =          Rm >> add->imm; break; // LSR
                    case 0b10: Rm = (int64_t)Rm >> add->imm; break; // ASR
                    default:
                        WRN("Bad add/sub shift at " ADDR, addr);
                        return kEmuErr;
                }
                uint64_t Rd;
                if(is_add_reg(add))
                {
                    Rd = state->x[add->Rn] + Rm;
                }
                else
                {
                    Rd = state->x[add->Rn] - Rm;
                }
                state->x[add->Rd] = add->sf ? Rd : (Rd & 0xffffffffULL);
                state->valid |= 1 << add->Rd;
                state->wide = (state->wide & ~(1 << add->Rd)) | (add->sf << add->Rd);
                // Weird case: we only wanna keep the host flag if exactly one of the source registers has it.
                // If both have it, something's gone wrong, but we wanna be able to add immediates that are loaded into a register.
                state->host = (state->host & ~(1 << add->Rd)) | ((((state->host >> add->Rn) & 0x1) ^ ((state->host >> add->Rm) & 0x1)) << add->Rd);
            }
        }
        else if(is_ldr_imm_uoff(ptr) || is_ldur(ptr) || is_ldrb_imm_uoff(ptr) || is_ldrh_imm_uoff(ptr) || is_ldrsb_imm_uoff(ptr) || is_ldrsh_imm_uoff(ptr) || is_ldrsw_imm_uoff(ptr))
        {
            bool sign = false;
            uint32_t Rt, Rn, sf, size;
            int64_t off;
            if(is_ldr_imm_uoff(ptr))
            {
                ldr_imm_uoff_t *ldr = ptr;
                Rt = ldr->Rt;
                Rn = ldr->Rn;
                sf = ldr->sf;
                size = 4 << ldr->sf;
                off = get_ldr_imm_uoff(ldr);
            }
            else if(is_ldur(ptr))
            {
                ldur_t *ldur = ptr;
                Rt = ldur->Rt;
                Rn = ldur->Rn;
                sf = ldur->sf;
                size = 4 << ldur->sf;
                off = get_ldur_off(ldur);
            }
            else if(is_ldrb_imm_uoff(ptr))
            {
                ldrb_imm_uoff_t *ldrb = ptr;
                Rt = ldrb->Rt;
                Rn = ldrb->Rn;
                sf = 0;
                size = 1;
                off = get_ldrb_imm_uoff(ldrb);
            }
            else if(is_ldrh_imm_uoff(ptr))
            {
                ldrh_imm_uoff_t *ldrh = ptr;
                Rt = ldrh->Rt;
                Rn = ldrh->Rn;
                sf = 0;
                size = 2;
                off = get_ldrh_imm_uoff(ldrh);
            }
            else if(is_ldrsb_imm_uoff(ptr))
            {
                ldrsb_imm_uoff_t *ldrsb = ptr;
                Rt = ldrsb->Rt;
                Rn = ldrsb->Rn;
                sf = ldrsb->sf;
                size = 1;
                off = get_ldrsb_imm_uoff(ldrsb);
                sign = true;
            }
            else if(is_ldrsh_imm_uoff(ptr))
            {
                ldrsh_imm_uoff_t *ldrsh = ptr;
                Rt = ldrsh->Rt;
                Rn = ldrsh->Rn;
                sf = ldrsh->sf;
                size = 2;
                off = get_ldrsh_imm_uoff(ldrsh);
                sign = true;
            }
            else if(is_ldrsw_imm_uoff(ptr))
            {
                ldrsw_imm_uoff_t *ldrsw = ptr;
                Rt = ldrsw->Rt;
                Rn = ldrsw->Rn;
                sf = 1;
                size = 4;
                off = get_ldrsw_imm_uoff(ldrsw);
                sign = true;
            }
            else
            {
                return kEmuErr;
            }
            if(!(state->valid & (1 << Rn))) // Unset validity
            {
                state->valid &= ~(1 << Rt);
            }
            else
            {
                kptr_t laddr = state->x[Rn] + off;
                void *ldr_addr = (state->host & (1 << Rn)) ? (void*)laddr : addr2ptr(kernel, laddr);
                if(!ldr_addr)
                {
                    return kEmuErr;
                }
                uint64_t val;
                switch(size)
                {
                    case 1: val = *(uint8_t *)ldr_addr; break;
                    case 2: val = *(uint16_t*)ldr_addr; break;
                    case 4: val = *(uint32_t*)ldr_addr; break;
                    case 8: val = *(uint64_t*)ldr_addr; break;
                    default:
                        ERR("Bug in a64_emulate: ldr_uoff with invalid size at " ADDR, addr);
                        exit(-1);
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
                            exit(-1);
                    }
                    if(!sf)
                    {
                        val &= 0xffffffff;
                    }
                }
                if(!(state->host & (1 << Rn)) && size == 8)
                {
                    if(is_in_fixup_chain(kernel, kbase, ldr_addr))
                    {
                        val = kuntag(kbase, fixupKind, val, NULL, NULL);
                    }
                }
                state->x[Rt] = val;
                state->valid |= 1 << Rt;
                state->wide = (state->wide & ~(1 << Rt)) | (sf << Rt);
                state->host &= ~(1 << Rt);
            }
        }
        else if(is_ldr_lit(ptr))
        {
            ldr_lit_t *ldr = ptr;
            void *ldr_addr = addr2ptr(kernel, addr + get_ldr_lit_off(ldr));
            if(!ldr_addr)
            {
                return kEmuErr;
            }
            kptr_t val = *(kptr_t*)ldr_addr;
            if(ldr->sf && is_in_fixup_chain(kernel, kbase, ldr_addr))
            {
                val = kuntag(kbase, fixupKind, val, NULL, NULL);
            }
            state->x[ldr->Rt] = val;
            state->valid |= 1 << ldr->Rt;
            state->wide = (state->wide & ~(1 << ldr->Rt)) | (ldr->sf << ldr->Rt);
            state->host &= ~(1 << ldr->Rt);
        }
        else if(is_ldp_pre(ptr) || is_ldp_post(ptr) || is_ldp_uoff(ptr))
        {
            ldp_t *ldp = ptr;
            if(!(state->valid & (1 << ldp->Rn))) // Unset validity
            {
                state->valid &= ~((1 << ldp->Rt) | (1 << ldp->Rt2));
            }
            else
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
                void *ldr_addr = (state->host & (1 << ldp->Rn)) ? (void*)laddr : addr2ptr(kernel, laddr);
                if(!ldr_addr)
                {
                    return kEmuErr;
                }
                if(ldp->sf)
                {
                    uint64_t *p = ldr_addr;
                    uint64_t v1 = p[0];
                    uint64_t v2 = p[1];
                    if(!(state->host & (1 << ldp->Rn)))
                    {
                        if(is_in_fixup_chain(kernel, kbase, ldr_addr))
                        {
                            v1 = kuntag(kbase, fixupKind, v1, NULL, NULL);
                        }
                        if(is_in_fixup_chain(kernel, kbase, ldr_addr + 1))
                        {
                            v2 = kuntag(kbase, fixupKind, v2, NULL, NULL);
                        }
                    }
                    state->x[ldp->Rt]  = v1;
                    state->x[ldp->Rt2] = v2;
                }
                else
                {
                    uint32_t *p = ldr_addr;
                    state->x[ldp->Rt]  = p[0];
                    state->x[ldp->Rt2] = p[1];
                }
                state->valid |= (1 << ldp->Rt) | (1 << ldp->Rt2);
                state->wide = (state->wide & ~((1 << ldp->Rt) | (1 << ldp->Rt2))) | (ldp->sf << ldp->Rt) | (ldp->sf << ldp->Rt2);
                state->host &= ~((1 << ldp->Rt) | (1 << ldp->Rt2));
            }
        }
        else if(is_ldxr(ptr))
        {
            ldxr_t *ldxr = ptr;
            if(!(state->valid & (1 << ldxr->Rn))) // Unset validity
            {
                state->valid &= ~(1 << ldxr->Rt);
            }
            else
            {
                kptr_t laddr = state->x[ldxr->Rn];
                void *ldr_addr = (state->host & (1 << ldxr->Rn)) ? (void*)laddr : addr2ptr(kernel, laddr);
                if(!ldr_addr)
                {
                    return kEmuErr;
                }
                kptr_t val = *(kptr_t*)ldr_addr;
                if(ldxr->sf && is_in_fixup_chain(kernel, kbase, ldr_addr))
                {
                    val = kuntag(kbase, fixupKind, val, NULL, NULL);
                }
                state->x[ldxr->Rt] = val;
                state->valid |= 1 << ldxr->Rt;
                state->wide = (state->wide & ~(1 << ldxr->Rt)) | (ldxr->sf << ldxr->Rt);
                state->host &= ~(1 << ldxr->Rt);
            }
        }
        else if(is_ldadd(ptr))
        {
            ldadd_t *ldadd = ptr;
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
                void *ld_addr = (state->host & (1 << ldadd->Rn)) ? (void*)daddr : addr2ptr(kernel, daddr);
                if(!ld_addr)
                {
                    return kEmuErr;
                }
                kptr_t val = *(kptr_t*)ld_addr;
                if(ldadd->Rt != 31)
                {
                    state->x[ldadd->Rt] = val;
                    state->valid |= 1 << ldadd->Rt;
                    state->wide = (state->wide & ~(1 << ldadd->Rt)) | (ldadd->sf << ldadd->Rt);
                    state->host &= ~(1 << ldadd->Rt);
                }
                if((state->host & (1 << ldadd->Rn)))
                {
                    if(!(state->valid & (1 << ldadd->Rs)))
                    {
                        if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                        else            DBG("Cannot store invalid value to host mem at " ADDR, addr);
                        return kEmuUnknown;
                    }
                    val += state->x[ldadd->Rs];
                    if(ldadd->sf)
                    {
                        *(uint64_t*)ld_addr = val;
                    }
                    else
                    {
                        *(uint32_t*)ld_addr = (uint32_t)val;
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
                str_fp_uoff_t *ldr = ptr;
                Rt = ldr->Rt;
                Rn = ldr->Rn;
                size = get_fp_uoff_size(ldr);
                off = get_fp_uoff(ldr);
            }
            else if(is_ldur_fp(ptr))
            {
                ldur_fp_t *ldur = ptr;
                Rt = ldur->Rt;
                Rn = ldur->Rn;
                size = get_ldur_stur_fp_size(ldur);
                off = get_ldur_stur_fp_off(ldur);
            }
            else
            {
                return kEmuErr;
            }
            if(!(state->valid & (1 << Rn))) // Unset validity
            {
                state->qvalid &= ~(1 << Rt);
            }
            else
            {
                kptr_t laddr = state->x[Rn] + off;
                void *ldr_addr = (state->host & (1 << Rn)) ? (void*)laddr : addr2ptr(kernel, laddr);
                if(!ldr_addr)
                {
                    return kEmuErr;
                }
                switch(size)
                {
                    case 0: state->q[Rt] = *(uint8_t *)ldr_addr; break;
                    case 1: state->q[Rt] = *(uint16_t*)ldr_addr; break;
                    case 2: state->q[Rt] = *(uint32_t*)ldr_addr; break;
                    case 3: state->q[Rt] = *(uint64_t*)ldr_addr; break;
                    case 4:
                    {
                        __uint128_t val = 0;
                        val |= (__uint128_t)((uint64_t*)ldr_addr)[0];
                        val |= (__uint128_t)((uint64_t*)ldr_addr)[1] << 64;
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
                str_fp_uoff_t *str = ptr;
                Rt = str->Rt;
                Rn = str->Rn;
                size = get_fp_uoff_size(str);
                off = get_fp_uoff(str);
            }
            else if(is_stur_fp(ptr))
            {
                stur_fp_t *stur = ptr;
                Rt = stur->Rt;
                Rn = stur->Rn;
                size = get_ldur_stur_fp_size(stur);
                off = get_ldur_stur_fp_off(stur);
            }
            else
            {
                return kEmuErr;
            }
            if((state->valid & (1 << Rn)) && (state->host & (1 << Rn)))
            {
                if(!(state->qvalid & (1 << Rt)))
                {
                    if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                    else            DBG("Cannot store invalid value to host mem at " ADDR, addr);
                    return kEmuUnknown;
                }
                kptr_t staddr = state->x[Rn] + off;
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
            }
        }
        else if(is_ldp_fp_pre(ptr) || is_ldp_fp_post(ptr) || is_ldp_fp_uoff(ptr))
        {
            ldp_fp_t *ldp = ptr;
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
                void *ldr_addr = (state->host & (1 << ldp->Rn)) ? (void*)laddr : addr2ptr(kernel, laddr);
                if(!ldr_addr)
                {
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
            stp_fp_t *stp = ptr;
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
                if(state->host & (1 << stp->Rn))
                {
                    if(!(state->qvalid & (1 << stp->Rt)) || !(state->qvalid & (1 << stp->Rt2)))
                    {
                        if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                        else            DBG("Cannot store invalid value to host mem at " ADDR, addr);
                        return kEmuUnknown;
                    }
                    switch(stp->opc)
                    {
                        case 0:
                        {
                            uint32_t *p = (uint32_t*)staddr;
                            p[0] = (uint32_t)state->q[stp->Rt];
                            p[1] = (uint32_t)state->q[stp->Rt2];
                            break;
                        }
                        case 1:
                        {
                            uint64_t *p = (uint64_t*)staddr;
                            p[0] = (uint64_t)state->q[stp->Rt];
                            p[1] = (uint64_t)state->q[stp->Rt2];
                            break;
                        }
                        case 2:
                        {
                            uint64_t *p = (uint64_t*)staddr;
                            p[0] = (uint64_t) state->q[stp->Rt];
                            p[1] = (uint64_t)(state->q[stp->Rt] >> 64);
                            p[2] = (uint64_t) state->q[stp->Rt2];
                            p[3] = (uint64_t)(state->q[stp->Rt2] >> 64);
                            break;
                        }
                        default:
                            WRN("SIMD stp with invalid size at " ADDR, addr);
                            return kEmuErr;
                    }
                }
            }
        }
        else if(is_bl(ptr))
        {
            if(fn_behaviour == kEmuFnEnter)
            {
                state->x[30] = addr + 4;
                state->valid |=   1 << 30;
                state->wide  |=   1 << 30;
                state->host  &= ~(1 << 30);
                from = (uint32_t*)((uintptr_t)from + get_bl_off(ptr));
                --from;
            }
            else
            {
                state->valid &= ~0x4003fffe;
                if(fn_behaviour != kEmuFnAssumeX0 || !((state->valid & 0x1) && (state->host & 0x1)))
                {
                    state->valid &= ~0x1;
                }
                state->qvalid &= 0xff00; // blindly assuming 128bit shit is handled as needed
            }
        }
        else if(is_mov(ptr))
        {
            mov_t *mov = ptr;
            if(!(state->valid & (1 << mov->Rm))) // Unset validity
            {
                state->valid &= ~(1 << mov->Rd);
            }
            else
            {
                state->x[mov->Rd] = state->x[mov->Rm];
                state->valid |= 1 << mov->Rd;
                state->wide = (state->wide & ~(1 << mov->Rd)) | (((state->wide >> mov->Rm) & 0x1 & mov->sf) << mov->Rd);
                state->host = (state->host & ~(1 << mov->Rd)) | (((state->host >> mov->Rm) & 0x1) << mov->Rd);
            }
        }
        else if(is_movz(ptr))
        {
            movz_t *movz = ptr;
            state->x[movz->Rd] = get_movzk_imm(movz);
            state->valid |= 1 << movz->Rd;
            state->wide = (state->wide & ~(1 << movz->Rd)) | (movz->sf << movz->Rd);
            state->host &= ~(1 << movz->Rd);
        }
        else if(is_movk(ptr))
        {
            movk_t *movk = ptr;
            if(state->valid & (1 << movk->Rd)) // Only if valid
            {
                state->x[movk->Rd] = (state->x[movk->Rd] & ~(0xffff << (movk->hw << 4))) | get_movzk_imm(movk);
                state->valid |= 1 << movk->Rd;
                state->wide = (state->wide & ~(1 << movk->Rd)) | (movk->sf << movk->Rd);
                state->host &= ~(1 << movk->Rd);
            }
        }
        else if(is_movn(ptr))
        {
            movn_t *movn = ptr;
            state->x[movn->Rd] = get_movn_imm(movn);
            state->valid |= 1 << movn->Rd;
            state->wide = (state->wide & ~(1 << movn->Rd)) | (movn->sf << movn->Rd);
            state->host &= ~(1 << movn->Rd);
        }
        else if(is_movi(ptr))
        {
            movi_t *movi = ptr;
            state->q[movi->Rd] = get_movi_imm(movi);
            state->qvalid |= 1 << movi->Rd;
        }
        else if(is_orr(ptr))
        {
            orr_t *orr = ptr;
            if(orr->Rn == 31 || (state->valid & (1 << orr->Rn)))
            {
                state->x[orr->Rd] = (orr->Rn == 31 ? 0 : state->x[orr->Rn]) | get_orr_imm(orr);
                state->valid |= 1 << orr->Rd;
                state->wide = (state->wide & ~(1 << orr->Rd)) | (orr->sf << orr->Rd);
                state->host &= ~(1 << orr->Rd);
            }
            else
            {
                state->valid &= ~(1 << orr->Rd);
            }
        }
        else if(is_b(ptr))
        {
            from = (uint32_t*)((uintptr_t)from + get_bl_off(ptr));
            --from;
        }
        else if(is_cbz(ptr) || is_cbnz(ptr))
        {
            cbz_t *cbz = ptr;
            if(!(state->valid & (1 << cbz->Rt)))
            {
                if(warnUnknown) WRN("Cannot decide cbz/cbnz at " ADDR, addr);
                else            DBG("Cannot decide cbz/cbnz at " ADDR, addr);
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
            tbz_t *tbz = ptr;
            uint32_t bit = get_tbz_bit(tbz);
            if(!(state->valid & (1 << tbz->Rt)) || (bit >= 32 && !(state->wide & (1 << tbz->Rt))))
            {
                if(warnUnknown) WRN("Cannot decide tbz/tbnz at " ADDR, addr);
                else            DBG("Cannot decide tbz/tbnz at " ADDR, addr);
                return kEmuUnknown;
            }
            if(((state->x[tbz->Rt] & (1 << bit)) == 0) == is_tbz(tbz))
            {
                from = (uint32_t*)((uintptr_t)from + get_tbz_off(tbz));
                --from;
            }
        }
        else if(is_ret(ptr))
        {
            if(fn_behaviour == kEmuFnEnter)
            {
                if(!(state->valid & (1 << 30)) || !(state->wide & (1 << 30)))
                {
                    if(warnUnknown) WRN("Cannot return at " ADDR, addr);
                    else            DBG("Cannot return at " ADDR, addr);
                    return kEmuUnknown;
                }
                if(state->host & (1 << 30))
                {
                    WRN("Cannot return to host address at " ADDR, addr);
                    return kEmuErr;
                }
                // This is really dirty, but... whatcha gonna do?
                if(state->x[30] != 0)
                {
                    from = addr2ptr(kernel, state->x[30]);
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
bool multi_call_emulate(void *kernel, kptr_t kbase, fixup_kind_t fixupKind, uint32_t *fncall, uint32_t *end, a64_state_t *state, void *sp, uint32_t wantvalid, const char *name)
{
    mach_seg_t *seg = seg4ptr(kernel, fncall);
    kptr_t fncalladdr = seg->vmaddr + ((uintptr_t)fncall - ((uintptr_t)kernel + seg->fileoff));

    bool have_stack_frame;
    bl_t *bl = (bl_t*)fncall;
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
        ERR("Bug in multi_call_emulate: fncall at " ADDR " is neither b nor bl", fncalladdr);
        exit(-1);
    }
    uint32_t *fnstart = find_function_start(kernel, seg, name, fncall, have_stack_frame);
    if(!fnstart)
    {
        return false;
    }
    kptr_t fnaddr = seg->vmaddr + ((uintptr_t)fnstart - ((uintptr_t)kernel + seg->fileoff));
    DBG("Function with call " ADDR " starts at " ADDR, fncalladdr, fnaddr);

    bzero(sp, A64_EMU_SPSIZE);
    for(size_t i = 0; i < 31; ++i)
    {
        state->x[i] = 0;
        state->q[i] = 0;
    }
    state->q[31]  = 0;
    state->x[31]  = (uintptr_t)sp + A64_EMU_SPSIZE;
    state->valid  = 0xfff80000;
    state->qvalid = 0x0000ff00;
    state->wide   = 0xfff80000;
    state->host   = 0x80000000;
    emu_ret_t ret = a64_emulate(kernel, kbase, fixupKind, state, fnstart, &a64cb_check_equal, end, false, false, kEmuFnEnter);
    switch(ret)
    {
        default:
        case kEmuRet:
            // This should be impossible
            ERR("Bug in a64_emulate: got %u for kEmuFnEnter", ret);
            exit(-1);

        case kEmuErr:
            // This is a fatal error, so no point in trying further.
            return false;

        case kEmuEnd:
            // This is the only possibly successful case. Just need to make sure we got everything we need.
            if((state->valid & wantvalid) == wantvalid)
            {
                DBG("Got a satisfying function call stack at " ADDR, fnaddr);
                return true;
            }
            // Otherwise fall through

        case kEmuUnknown:
            // This means we don't have enough info yet, so break into the code below and do another call level.
            break;
    }

    DBG("Searching for function calls to " ADDR, fnaddr);
    STEP_MEM(uint32_t, mem, (uintptr_t)kernel + seg->fileoff, seg->filesize, 1)
    {
        bl_t *bl = (bl_t*)mem;
        if(is_bl(bl) || is_b(bl))
        {
            kptr_t bladdr = seg->vmaddr + ((uintptr_t)bl - ((uintptr_t)kernel + seg->fileoff));
            kptr_t bltarg = bladdr + get_bl_off(bl);
            if(bltarg == fnaddr && multi_call_emulate(kernel, kbase, fixupKind, mem, end, state, sp, wantvalid, name))
            {
                return true;
            }
        }
    }
    return false;
}
