/* Copyright (c) 2018-2019 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#ifndef A64_H
#define A64_H

#include <stddef.h>             // size_t
#include <stdbool.h>
#include <stdint.h>

#pragma pack(4)
typedef struct
{
    uint32_t Rd     :  5,
             immhi  : 19,
             op2    :  5,
             immlo  :  2,
             op1    :  1;
} adr_t;

typedef struct
{
    uint32_t Rd     :  5,
             Rn     :  5,
             imm    : 12,
             shift  :  1,
             op     :  8,
             sf     :  1;
} add_imm_t, sub_imm_t;

typedef struct
{
    uint32_t Rd     : 5,
             Rn     : 5,
             imm    : 6,
             Rm     : 5,
             op2    : 1,
             shift  : 2,
             op1    : 7,
             sf     : 1;
} add_reg_t, sub_reg_t;

typedef struct
{
    uint32_t Rt     :  5,
             Rn     :  5,
             imm    : 12,
             op2    :  8,
             sf     :  1,
             op1    :  1;
} ldr_imm_uoff_t;

typedef struct
{
    uint32_t Rt     :  5,
             imm    : 19,
             op2    :  6,
             sf     :  1,
             op1    :  1;
} ldr_lit_t;

typedef struct
{
    uint32_t Rt     : 5,
             Rn     : 5,
             Rt2    : 5,
             imm    : 7,
             op     : 9,
             sf     : 1;
} ldp_t, stp_t;

typedef struct
{
    uint32_t Rt     : 5,
             Rn     : 5,
             Rt2    : 5,
             op3    : 1,
             Rs     : 5,
             op2    : 9,
             sf     : 1,
             op1    : 1;
} ldxr_t, stxr_t;

typedef struct
{
    uint32_t Rt     : 5,
             Rn     : 5,
             op4    : 6,
             Rs     : 5,
             op3    : 1,
             R      : 1,
             A      : 1,
             op2    : 6,
             sf     : 1,
             op1    : 1;
} ldadd_t;

/*typedef struct
{
    uint32_t Rt     : 5,
             Rn     : 5,
             op3    : 2,
             S      : 1,
             opt    : 3,
             Rm     : 5,
             op2    : 9,
             sf     : 1,
             op1    : 1;
} str_reg_t;*/

typedef struct
{
    uint32_t Rt     : 5,
             Rn     : 5,
             op3    : 2,
             imm    : 9,
             op2    : 9,
             sf     : 1,
             op1    : 1;
} str_imm_t;

typedef struct
{
    uint32_t Rt     :  5,
             Rn     :  5,
             imm    : 12,
             op2    :  8,
             sf     :  1,
             op1    :  1;
} str_uoff_t;

typedef struct
{
    uint32_t Rt     : 5,
             Rn     : 5,
             op3    : 2,
             imm    : 9,
             op2    : 9,
             sf     : 1,
             op1    : 1;
} ldur_t, stur_t;

typedef struct
{
    uint32_t Rt     :  5,
             Rn     :  5,
             imm    : 12,
             op     : 10;
} ldrb_imm_uoff_t, ldrh_imm_uoff_t, ldrsw_imm_uoff_t, strb_imm_uoff_t, strh_imm_uoff_t;

typedef struct
{
    uint32_t Rt     :  5,
             Rn     :  5,
             imm    : 12,
             sf     :  1,
             op     :  9;
} ldrsb_imm_uoff_t, ldrsh_imm_uoff_t;

typedef struct
{
    uint32_t Rt     :  5,
             Rn     :  5,
             imm    : 12,
             op2    :  1,
             opc    :  1,
             op1    :  6,
             size   :  2;
} ldr_fp_uoff_t, str_fp_uoff_t;

typedef struct
{
    uint32_t Rt     : 5,
             Rn     : 5,
             op3    : 2,
             imm    : 9,
             op2    : 2,
             opc    : 1,
             op1    : 6,
             size   : 2;
} ldur_fp_t, stur_fp_t;

typedef struct
{
    uint32_t Rt     : 5,
             Rn     : 5,
             Rt2    : 5,
             imm    : 7,
             op     : 8,
             opc    : 2;
} ldp_fp_t, stp_fp_t;

typedef struct
{
    uint32_t op2    :  5,
             Rn     :  5,
             op1    : 22;
} br_t;

typedef struct
{
    uint32_t imm    : 26,
             op     :  5,
             mode   :  1;
} bl_t, b_t;

typedef struct
{
    uint32_t cond :  4,
             op2  :  1,
             imm  : 19,
             op1  :  8;
} b_cond_t;

typedef struct
{
    uint32_t Rt     :  5,
             imm    : 19,
             op     :  7,
             sf     :  1;
} cbz_t;

typedef struct
{
    uint32_t Rt     :  5,
             imm    : 14,
             bit    :  5,
             op     :  7,
             sf     :  1;
} tbz_t;

/*typedef struct
{
    uint32_t Rd     :  5,
             op2    : 11,
             Rm     :  5,
             op1    : 10,
             sf     :  1;
} mov_t;*/

typedef struct
{
    uint32_t Rd     :  5,
             imm    : 16,
             hw     :  2,
             op     :  8,
             sf     :  1;
} movz_t, movk_t, movn_t;

typedef struct
{
    uint32_t Rd     :  5,
             defgh  :  5,
             op3    :  2,
             cmode  :  4,
             abc    :  3,
             op2    : 10,
             op     :  1,
             Q      :  1,
             op1    :  1;
} movi_t;

typedef struct
{
    uint32_t Rd     : 5,
             Rn     : 5,
             imms   : 6,
             immr   : 6,
             N      : 1,
             op     : 8,
             sf     : 1;
} and_t, orr_t, eor_t;

typedef struct
{
    uint32_t Rd    : 5,
             Rn    : 5,
             imm   : 6,
             Rm    : 5,
             N     : 1,
             shift : 2,
             op    : 7,
             sf    : 1;
} and_reg_t, orr_reg_t, eor_reg_t;

typedef struct
{
    uint32_t Rd     :  5,
             Rn     :  5,
             key    :  1,
             data   :  1,
             op2    :  1,
             Z      :  1,
             op1    : 18;
} pac_t;

typedef struct
{
    uint32_t op3    :  5,
             x      :  1,
             key    :  1,
             op2    :  2,
             C      :  1,
             op1    : 22;
} pacsys_t;

typedef struct
{
    uint32_t Rd     :  5,
             Rn     :  5,
             op2    :  6,
             Rm     :  5,
             op1    : 11;
} pacga_t;

typedef struct
{
    uint32_t Rm  :  5,
             Rn  :  5,
             key :  1,
             op  : 21;
} bra_t;

typedef struct
{
    uint32_t op2    :  8,
             CRm    :  4,
             op     : 20;
} bti_t;

typedef uint32_t nop_t;
typedef uint32_t ret_t;
#pragma pack()

static inline bool is_adr(adr_t *adr)
{
    return adr->op1 == 0 && adr->op2 == 0x10;
}

static inline bool is_adrp(adr_t *adrp)
{
    return adrp->op1 == 1 && adrp->op2 == 0x10;
}

static inline int64_t get_adr_off(adr_t *adr)
{
    size_t scale = adr->op1 ? 12 : 0;
    return (((int64_t)(adr->immlo | (adr->immhi << 2))) << (64 - 21)) >> (64 - 21 - scale);
}

static inline bool is_add_imm(add_imm_t *add)
{
    return add->op == 0b00100010;
}

static inline bool is_sub_imm(sub_imm_t *sub)
{
    return sub->op == 0b10100010;
}

static inline bool is_adds_imm(add_imm_t *add)
{
    return add->op == 0b01100010;
}

static inline bool is_subs_imm(sub_imm_t *sub)
{
    return sub->op == 0b11100010;
}

static inline uint32_t get_add_sub_imm(add_imm_t *add)
{
    return add->imm << (add->shift ? 12 : 0);
}

static inline bool is_add_reg(add_reg_t *add)
{
    return add->op1 == 0b0001011 && add->op2 == 0;
}

static inline bool is_sub_reg(sub_reg_t *sub)
{
    return sub->op1 == 0b1001011 && sub->op2 == 0;
}

static inline bool is_adds_reg(add_reg_t *add)
{
    return add->op1 == 0b0101011 && add->op2 == 0;
}

static inline bool is_subs_reg(sub_reg_t *sub)
{
    return sub->op1 == 0b1101011 && sub->op2 == 0;
}

static inline bool is_ldr_imm_uoff(ldr_imm_uoff_t *ldr)
{
    return ldr->op1 == 1 && ldr->op2 == 0xe5;
}

static inline uint32_t get_ldr_imm_uoff(ldr_imm_uoff_t *ldr)
{
    return ldr->imm << (2 + ldr->sf);
}

static inline bool is_ldr_lit(ldr_lit_t *ldr)
{
    return ldr->op1 == 0 && ldr->op2 == 0x18;
}

static inline int64_t get_ldr_lit_off(ldr_lit_t *ldr)
{
    return (((int64_t)ldr->imm) << (64 - 19)) >> (64 - 19 - 2);
}

static inline bool is_ldxr(ldxr_t *ldxr)
{
    return ldxr->op1 == 1 && ldxr->op2 == 0x42 && ldxr->op3 == 0 && ldxr->Rs == 0x1f && ldxr->Rt2 == 0x1f;
}

static inline bool is_stxr(stxr_t *stxr)
{
    return stxr->op1 == 1 && stxr->op2 == 0x40 && stxr->op3 == 0 && stxr->Rt2 == 0x1f;
}

static inline bool is_ldadd(ldadd_t *ldadd)
{
    return ldadd->op4 == 0 && ldadd->op3 == 1 && ldadd->op2 == 0x38 && ldadd->op1 == 1;
}

static inline bool is_ldp_pre(ldp_t *ldp)
{
    return ldp->op == 0xa7;
}

static inline bool is_ldp_post(ldp_t *ldp)
{
    return ldp->op == 0xa3;
}

static inline bool is_ldp_uoff(ldp_t *ldp)
{
    return ldp->op == 0xa5;
}

static inline bool is_stp_pre(stp_t *stp)
{
    return stp->op == 0xa6;
}

static inline bool is_stp_post(stp_t *stp)
{
    return stp->op == 0xa2;
}

static inline bool is_stp_uoff(stp_t *stp)
{
    return stp->op == 0xa4;
}

static inline int64_t get_ldp_stp_off(ldp_t *ldp)
{
    return ((int64_t)ldp->imm << (64 - 7)) >> (64 - 7 - (2 + ldp->sf));
}

/*static inline bool is_str_reg(str_reg_t *str)
{
    return str->op1 == 1 && str->op2 == 0x1c1 && str->op3 == 2;
}*/

static inline bool is_str_pre(str_imm_t *str)
{
    return str->op1 == 1 && str->op2 == 0x1c0 && str->op3 == 0x3;
}

static inline bool is_str_post(str_imm_t *str)
{
    return str->op1 == 1 && str->op2 == 0x1c0 && str->op3 == 0x1;
}

static inline int64_t get_str_imm(str_imm_t *str)
{
    return ((int64_t)str->imm << (64 - 9)) >> (64 - 9 - (2 + str->sf));
}

static inline bool is_str_uoff(str_uoff_t *str)
{
    return str->op1 == 1 && str->op2 == 0xe4;
}

static inline uint32_t get_str_uoff(str_uoff_t *str)
{
    return str->imm << (2 + str->sf);
}

static inline bool is_ldur(ldur_t *ldur)
{
    return ldur->op1 == 0b1 && ldur->op2 == 0b111000010 && ldur->op3 == 0b0;
}

static inline int64_t get_ldur_off(ldur_t *ldur)
{
    return ((int64_t)ldur->imm << (64 - 9)) >> (64 - 9);
}

static inline bool is_stur(stur_t *stur)
{
    return stur->op1 == 0b1 && stur->op2 == 0b111000000 && stur->op3 == 0b0;
}

static inline int64_t get_stur_off(stur_t *stur)
{
    return ((int64_t)stur->imm << (64 - 9)) >> (64 - 9);
}

static inline bool is_ldrb_imm_uoff(ldrb_imm_uoff_t *ldrb)
{
    return ldrb->op == 0b0011100101;
}

static inline uint32_t get_ldrb_imm_uoff(ldrb_imm_uoff_t *ldrb)
{
    return ldrb->imm;
}

static inline bool is_ldrh_imm_uoff(ldrh_imm_uoff_t *ldrh)
{
    return ldrh->op == 0b0111100101;
}

static inline uint32_t get_ldrh_imm_uoff(ldrh_imm_uoff_t *ldrh)
{
    return ldrh->imm << 1;
}

static inline bool is_ldrsb_imm_uoff(ldrsb_imm_uoff_t *ldrsb)
{
    return ldrsb->op == 0b001110011;
}

static inline uint32_t get_ldrsb_imm_uoff(ldrsb_imm_uoff_t *ldrsb)
{
    return ldrsb->imm;
}

static inline bool is_ldrsh_imm_uoff(ldrsh_imm_uoff_t *ldrsh)
{
    return ldrsh->op == 0b011110011;
}

static inline uint32_t get_ldrsh_imm_uoff(ldrsh_imm_uoff_t *ldrsh)
{
    return ldrsh->imm << 1;
}

static inline bool is_ldrsw_imm_uoff(ldrsw_imm_uoff_t *ldrsw)
{
    return ldrsw->op == 0b101110011;
}

static inline uint32_t get_ldrsw_imm_uoff(ldrsw_imm_uoff_t *ldrsw)
{
    return ldrsw->imm << 2;
}

static inline bool is_strb_imm_uoff(strb_imm_uoff_t *strb)
{
    return strb->op == 0b0011100100;
}

static inline uint32_t get_strb_imm_uoff(strb_imm_uoff_t *strb)
{
    return strb->imm;
}

static inline bool is_strh_imm_uoff(strh_imm_uoff_t *strh)
{
    return strh->op == 0b0111100100;
}

static inline uint32_t get_strh_imm_uoff(strh_imm_uoff_t *strh)
{
    return strh->imm << 1;
}

static inline bool is_ldr_fp_uoff(ldr_fp_uoff_t *ldr)
{
    return ldr->op1 == 0b111101 && ldr->op2 == 0b1;
}

static inline bool is_str_fp_uoff(str_fp_uoff_t *str)
{
    return str->op1 == 0b111101 && str->op2 == 0b0;
}

static inline uint32_t get_fp_uoff_size(ldr_fp_uoff_t *ldr)
{
    return (ldr->opc << 2) | ldr->size;
}

static inline uint32_t get_fp_uoff(ldr_fp_uoff_t *ldr)
{
    return ldr->imm << get_fp_uoff_size(ldr);
}

static inline bool is_ldur_fp(ldur_fp_t *stur)
{
    return stur->op1 == 0b111100 && stur->op2 == 0b10 && stur->op3 == 0b00;
}

static inline bool is_stur_fp(stur_fp_t *stur)
{
    return stur->op1 == 0b111100 && stur->op2 == 0b00 && stur->op3 == 0b00;
}

static inline uint32_t get_ldur_stur_fp_size(stur_fp_t *ldur)
{
    return (ldur->opc << 2) | ldur->size;
}

static inline int64_t get_ldur_stur_fp_off(stur_fp_t *ldur)
{
    return (((int64_t)ldur->imm) << (64 - 9)) >> (64 - 9);
}

static inline bool is_ldp_fp_pre(ldp_fp_t *ldp)
{
    return ldp->op == 0b10110111;
}

static inline bool is_ldp_fp_post(ldp_fp_t *ldp)
{
    return ldp->op == 0b10110011;
}

static inline bool is_ldp_fp_uoff(ldp_fp_t *ldp)
{
    return ldp->op == 0b10110101;
}

static inline bool is_stp_fp_pre(stp_fp_t *stp)
{
    return stp->op == 0b10110110;
}

static inline bool is_stp_fp_post(stp_fp_t *stp)
{
    return stp->op == 0b10110010;
}

static inline bool is_stp_fp_uoff(stp_fp_t *stp)
{
    return stp->op == 0b10110100;
}

static inline int64_t get_ldp_stp_fp_off(ldp_fp_t *ldp)
{
    return (((int64_t)ldp->imm) << (64 - 7)) >> (64 - 9 - ldp->opc);
}

static inline bool is_br(br_t *br)
{
    return br->op1 == 0x3587c0 && br->op2 == 0;
}

static inline bool is_bl(bl_t *bl)
{
    return bl->op == 0x5 && bl->mode == 1;
}

static inline bool is_b(b_t *b)
{
    return b->op == 0x5 && b->mode == 0;
}

static inline int64_t get_bl_off(bl_t *bl)
{
    return (((int64_t)bl->imm) << (64 - 26)) >> (64 - 26 - 2);
}

static inline bool is_b_cond(b_cond_t *b)
{
    return b->op1 == 0b01010100 && b->op2 == 0;
}

static inline int64_t get_b_cond_off(b_cond_t *b)
{
    return (((int64_t)b->imm) << (64 - 19)) >> (64 - 19 - 2);
}

static inline bool is_cbz(cbz_t *cbz)
{
    return cbz->op == 0x34;
}

static inline bool is_cbnz(cbz_t *cbz)
{
    return cbz->op == 0x35;
}

static inline int64_t get_cbz_off(cbz_t *cbz)
{
    return (((int64_t)cbz->imm) << (64 - 19)) >> (64 - 19 - 2);
}

static inline bool is_tbz(tbz_t *tbz)
{
    return tbz->op == 0x36;
}

static inline bool is_tbnz(tbz_t *tbz)
{
    return tbz->op == 0x37;
}

static inline uint32_t get_tbz_bit(tbz_t *tbz)
{
    return (tbz->sf << 5) | tbz->bit;
}

static inline int64_t get_tbz_off(tbz_t *tbz)
{
    return (((int64_t)tbz->imm) << (64 - 14)) >> (64 - 14 - 2);
}

/*static inline bool is_mov(mov_t *mov)
{
    return mov->op1 == 0x150 && mov->op2 == 0x1f;
}*/

static inline bool is_movz(movz_t *movz)
{
    return movz->op == 0xa5;
}

static inline bool is_movk(movk_t *movk)
{
    return movk->op == 0xe5;
}

static inline uint64_t get_movzk_imm(movz_t *movz)
{
    return movz->imm << (movz->hw << 4);
}

static inline bool is_movn(movn_t *movn)
{
    return movn->op == 0x25;
}

static inline int64_t get_movn_imm(movn_t *movn)
{
    return ~get_movzk_imm(movn);
}

static inline bool is_movi(movi_t *movi)
{
    if(movi->op1 == 0b0 && movi->op2 == 0b0111100000 && movi->op3 == 0b01)
    {
        uint8_t x = (movi->cmode << 1) | movi->op;
        return ((x & 0b10011) == 0b00000) || ((x & 0b11011) == 0b10000) || ((x & 0b11101) == 0b11000) || ((x & 0b11110) == 0b11100) || (x == 0b11110) || (x == 0b11111 && movi->Q == 0b1);
    }
    return false;
}

static inline bool is_pac(pac_t *pac)
{
    return pac->op1 == 0x36b04 && pac->op2 == 0;
}

static inline bool is_pacsys(pacsys_t *pacsys)
{
    return pacsys->op1 == 0x3540c8 && pacsys->op2 == 0x2 && pacsys->op3 == 0x1f && (pacsys->x == 0 || pacsys->C == 1);
}

static inline bool is_pacga(pacga_t *pacga)
{
    return pacga->op1 == 0x4d6 && pacga->op2 == 0xc;
}

static inline bool is_aut(pac_t *pac)
{
    return pac->op1 == 0x36b04 && pac->op2 == 1;
}

static inline bool is_autsys(pacsys_t *pacsys)
{
    return pacsys->op1 == 0x3540c8 && pacsys->op2 == 0x3 && pacsys->op3 == 0x1f && (pacsys->x == 0 || pacsys->C == 1);
}

static inline bool is_bra(bra_t *bra)
{
    return bra->op == 0b110101110001111100001;
}

static inline bool is_nop(nop_t *nop)
{
    return *nop == 0xd503201f;
}

static inline bool is_ret(ret_t *ret)
{
    ret_t r = *ret;
    return r == 0xd65f03c0 || // ret
           r == 0xd65f0bff || // retaa
           r == 0xd65f0fff;   // retab
}

static inline bool is_and_reg(and_reg_t *and)
{
    return and->op == 0b0001010 && and->N == 0;
}

static inline bool is_orr_reg(orr_reg_t *orr)
{
    return orr->op == 0b0101010 && orr->N == 0;
}

static inline bool is_eor_reg(eor_reg_t *eor)
{
    return eor->op == 0b1001010 && eor->N == 0;
}

static inline bool is_and(and_t *and)
{
    return and->op == 0b00100100;
}

static inline bool is_orr(orr_t *orr)
{
    return orr->op == 0b01100100;
}

static inline bool is_eor(eor_t *eor)
{
    return eor->op == 0b10100100;
}

static inline bool is_bti(bti_t *bti)
{
    return bti->op == 0b11010101000000110010 &&
           bti->CRm == 0b0100 &&
           (bti->op2 & 0b00111111) == 0b011111;
}

static inline bool is_ands_reg(and_reg_t *and)
{
    return and->op == 0b1101010 && and->N == 0;
}

static inline bool is_ands(and_t *and)
{
    return and->op == 0b11100100;
}

// and/orr/eor - holy clusterfuck

extern uint64_t DecodeBitMasks(uint8_t N, uint8_t imms, uint8_t immr, uint8_t bits);

static inline uint32_t get_orr_imm(orr_t *orr)
{
    return DecodeBitMasks(orr->N, orr->imms, orr->immr, 32 << orr->sf);
}

// movi - well fml this is even worse

extern uint64_t AdvSIMDExpandImm(uint8_t op, uint8_t cmode, uint64_t imm8);

static inline __uint128_t get_movi_imm(movi_t *movi)
{
    __uint128_t val = AdvSIMDExpandImm(movi->op, movi->cmode, (movi->abc << 5) | movi->defgh);
    if(movi->Q == 0b1)
    {
        val |= val << 64;
    }
    return val;
}

#endif
