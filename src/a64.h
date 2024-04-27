/* Copyright (c) 2018-2024 Siguza
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

#define CACHELINE_SIZE 0x40ULL

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
    uint32_t Rd  :  5,
             Rn  :  5,
             Ra  :  5,
             op0 :  1,
             Rm  :  5,
             op  : 10,
             sf  :  1;
} madd_t;

typedef struct
{
    uint32_t Rt     : 5,
             Rn     : 5,
             op3    : 2,
             imm    : 9,
             op2    : 9,
             sf     : 1,
             op1    : 1;
} ldr_imm_t, str_imm_t;

typedef struct
{
    uint32_t Rt     :  5,
             Rn     :  5,
             imm    : 12,
             op2    :  8,
             sf     :  1,
             op1    :  1;
} ldr_uoff_t, str_uoff_t;

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
             op     : 8,
             opc    : 2;
} ldp_t, ldp_fp_t, ldnp_t, stp_t, stp_fp_t, stnp_t;

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
             op2    : 2,
             imm    : 9,
             op1    : 9,
             size   : 2;
} ldurb_t, ldurh_t, ldur_t, sturb_t, sturh_t, stur_t;

typedef struct
{
    uint32_t Rt     :  5,
             Rn     :  5,
             imm    : 12,
             op     : 10;
} ldrb_uoff_t, ldrh_uoff_t, ldrsw_uoff_t, strb_uoff_t, strh_uoff_t;

typedef struct
{
    uint32_t Rt     :  5,
             Rn     :  5,
             imm    : 12,
             sf     :  1,
             op     :  9;
} ldrsb_uoff_t, ldrsh_uoff_t;

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

typedef struct
{
    uint32_t Rd   :  5,
             Rn   :  5,
             op2  :  2,
             cond :  4,
             Rm   :  5,
             op1  : 10,
             sf   :  1;
} csel_t, csinc_t;

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
} and_t, ands_t, orr_t, eor_t, bfm_t, sbfm_t, ubfm_t;

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
} and_reg_t, ands_reg_t, orr_reg_t, eor_reg_t;

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
    uint32_t Rt  :  5,
             op2 :  3,
             CRm :  4,
             CRn :  4,
             op1 :  3,
             op0 :  2,
             L   :  1,
             op  : 10;
} sys_t;

typedef struct
{
    uint32_t Rm  :  5,
             Rn  :  5,
             key :  1,
             op  : 21;
} bra_t;

typedef struct
{
    uint32_t op3 :  6,
             op2 :  2,
             op1 : 24;
} bti_t;

typedef uint32_t nop_t;
typedef uint32_t ret_t;
#pragma pack()

static inline bool is_adr(const adr_t *adr)
{
    return adr->op1 == 0 && adr->op2 == 0x10;
}

static inline bool is_adrp(const adr_t *adrp)
{
    return adrp->op1 == 1 && adrp->op2 == 0x10;
}

static inline int64_t get_adr_off(const adr_t *adr)
{
    size_t scale = adr->op1 ? 12 : 0;
    return (int64_t)(((uint64_t)(adr->immlo | (adr->immhi << 2))) << (64 - 21)) >> (64 - 21 - scale);
}

static inline bool is_add_imm(const add_imm_t *add)
{
    return add->op == 0b00100010;
}

static inline bool is_sub_imm(const sub_imm_t *sub)
{
    return sub->op == 0b10100010;
}

static inline bool is_adds_imm(const add_imm_t *add)
{
    return add->op == 0b01100010;
}

static inline bool is_subs_imm(const sub_imm_t *sub)
{
    return sub->op == 0b11100010;
}

static inline uint32_t get_add_sub_imm(const add_imm_t *add)
{
    return add->imm << (add->shift ? 12 : 0);
}

static inline bool is_add_reg(const add_reg_t *add)
{
    return add->op1 == 0b0001011 && add->op2 == 0;
}

static inline bool is_sub_reg(const sub_reg_t *sub)
{
    return sub->op1 == 0b1001011 && sub->op2 == 0;
}

static inline bool is_adds_reg(const add_reg_t *add)
{
    return add->op1 == 0b0101011 && add->op2 == 0;
}

static inline bool is_subs_reg(const sub_reg_t *sub)
{
    return sub->op1 == 0b1101011 && sub->op2 == 0;
}

static inline bool is_madd(const madd_t *madd)
{
    return madd->op == 0b0011011000 && madd->op0 == 0;
}

static inline bool is_ldr_pre(const ldr_imm_t *ldr)
{
    return ldr->op1 == 1 && ldr->op2 == 0b111000010 && ldr->op3 == 0b11;
}

static inline bool is_ldr_post(const ldr_imm_t *ldr)
{
    return ldr->op1 == 1 && ldr->op2 == 0b111000010 && ldr->op3 == 0b01;
}

static inline int64_t get_ldr_imm(const ldr_imm_t *ldr)
{
    return (int64_t)((uint64_t)ldr->imm << (64 - 9)) >> (64 - 9);
}

static inline bool is_ldr_uoff(const ldr_uoff_t *ldr)
{
    return ldr->op1 == 1 && ldr->op2 == 0xe5;
}

static inline uint32_t get_ldr_uoff(const ldr_uoff_t *ldr)
{
    return ldr->imm << (2 + ldr->sf);
}

static inline bool is_ldr_lit(const ldr_lit_t *ldr)
{
    return ldr->op1 == 0 && ldr->op2 == 0x18;
}

static inline int64_t get_ldr_lit_off(const ldr_lit_t *ldr)
{
    return (int64_t)(((uint64_t)ldr->imm) << (64 - 19)) >> (64 - 19 - 2);
}

static inline bool is_ldxr(const ldxr_t *ldxr)
{
    return ldxr->op1 == 1 && ldxr->op2 == 0x42 && ldxr->op3 == 0 && ldxr->Rs == 0x1f && ldxr->Rt2 == 0x1f;
}

static inline bool is_stxr(const stxr_t *stxr)
{
    return stxr->op1 == 1 && stxr->op2 == 0x40 && stxr->op3 == 0 && stxr->Rt2 == 0x1f;
}

static inline bool is_ldadd(const ldadd_t *ldadd)
{
    return ldadd->op4 == 0 && ldadd->op3 == 1 && ldadd->op2 == 0x38 && ldadd->op1 == 1;
}

static inline bool is_ldp_pre(const ldp_t *ldp)
{
    return ldp->op == 0b10100111 && (ldp->opc & 0b01) == 0b00;
}

static inline bool is_ldp_post(const ldp_t *ldp)
{
    return ldp->op == 0b10100011 && (ldp->opc & 0b01) == 0b00;
}

static inline bool is_ldp_uoff(const ldp_t *ldp)
{
    return ldp->op == 0b10100101 && (ldp->opc & 0b01) == 0b00;
}

static inline bool is_ldp_fp_pre(const ldp_fp_t *ldp)
{
    return ldp->op == 0b10110111;
}

static inline bool is_ldp_fp_post(const ldp_fp_t *ldp)
{
    return ldp->op == 0b10110011;
}

static inline bool is_ldp_fp_uoff(const ldp_fp_t *ldp)
{
    return ldp->op == 0b10110101;
}

static inline bool is_ldnp(const ldnp_t *ldnp)
{
    return ldnp->op == 0b10100001 && (ldnp->opc & 0b01) == 0b00;
}

static inline bool is_stp_pre(const stp_t *stp)
{
    return stp->op == 0b10100110 && (stp->opc & 0b01) == 0b00;
}

static inline bool is_stp_post(const stp_t *stp)
{
    return stp->op == 0b10100010 && (stp->opc & 0b01) == 0b00;
}

static inline bool is_stp_uoff(const stp_t *stp)
{
    return stp->op == 0b10100100 && (stp->opc & 0b01) == 0b00;
}

static inline bool is_stp_fp_pre(const stp_fp_t *stp)
{
    return stp->op == 0b10110110;
}

static inline bool is_stp_fp_post(const stp_fp_t *stp)
{
    return stp->op == 0b10110010;
}

static inline bool is_stp_fp_uoff(const stp_fp_t *stp)
{
    return stp->op == 0b10110100;
}

static inline bool is_stnp(const stnp_t *stnp)
{
    return stnp->op == 0b10100000 && (stnp->opc & 0b01) == 0b00;
}

static inline int64_t get_ldp_stp_off(const ldp_t *ldp)
{
    return (int64_t)((uint64_t)ldp->imm << (64 - 7)) >> (64 - 7 - (2 + (ldp->opc >> 1)));
}

static inline int64_t get_ldp_stp_fp_off(const ldp_fp_t *ldp)
{
    return (int64_t)((uint64_t)ldp->imm << (64 - 7)) >> (64 - 7 - (2 + ldp->opc));
}

/*static inline bool is_str_reg(const str_reg_t *str)
{
    return str->op1 == 1 && str->op2 == 0x1c1 && str->op3 == 2;
}*/

static inline bool is_str_pre(const str_imm_t *str)
{
    return str->op1 == 1 && str->op2 == 0x1c0 && str->op3 == 0x3;
}

static inline bool is_str_post(const str_imm_t *str)
{
    return str->op1 == 1 && str->op2 == 0x1c0 && str->op3 == 0x1;
}

static inline int64_t get_str_imm(const str_imm_t *str)
{
    return (int64_t)((uint64_t)str->imm << (64 - 9)) >> (64 - 9);
}

static inline bool is_str_uoff(const str_uoff_t *str)
{
    return str->op1 == 1 && str->op2 == 0xe4;
}

static inline uint32_t get_str_uoff(const str_uoff_t *str)
{
    return str->imm << (2 + str->sf);
}

static inline bool is_ldurb(const ldurb_t *ldurb)
{
    return ldurb->size == 0b00 && ldurb->op1 == 0b111000010 && ldurb->op2 == 0b00;
}

static inline bool is_ldurh(const ldurh_t *ldurh)
{
    return ldurh->size == 0b01 && ldurh->op1 == 0b111000010 && ldurh->op2 == 0b00;
}

static inline bool is_ldur(const ldur_t *ldur)
{
    return (ldur->size & 0b10) == 0b10 && ldur->op1 == 0b111000010 && ldur->op2 == 0b00;
}

static inline int64_t get_ldur_off(const ldur_t *ldur)
{
    return (int64_t)((uint64_t)ldur->imm << (64 - 9)) >> (64 - 9);
}

static inline bool is_sturb(const sturb_t *sturb)
{
    return sturb->size == 0b00 && sturb->op1 == 0b111000000 && sturb->op2 == 0b00;
}

static inline bool is_sturh(const sturh_t *sturh)
{
    return sturh->size == 0b01 && sturh->op1 == 0b111000000 && sturh->op2 == 0b00;
}

static inline bool is_stur(const stur_t *stur)
{
    return (stur->size & 0b10) == 0b10 && stur->op1 == 0b111000000 && stur->op2 == 0b00;
}

static inline int64_t get_stur_off(const stur_t *stur)
{
    return (int64_t)((uint64_t)stur->imm << (64 - 9)) >> (64 - 9);
}

static inline bool is_ldrb_uoff(const ldrb_uoff_t *ldrb)
{
    return ldrb->op == 0b0011100101;
}

static inline uint32_t get_ldrb_uoff(const ldrb_uoff_t *ldrb)
{
    return ldrb->imm;
}

static inline bool is_ldrh_uoff(const ldrh_uoff_t *ldrh)
{
    return ldrh->op == 0b0111100101;
}

static inline uint32_t get_ldrh_uoff(const ldrh_uoff_t *ldrh)
{
    return ldrh->imm << 1;
}

static inline bool is_ldrsb_uoff(const ldrsb_uoff_t *ldrsb)
{
    return ldrsb->op == 0b001110011;
}

static inline uint32_t get_ldrsb_uoff(const ldrsb_uoff_t *ldrsb)
{
    return ldrsb->imm;
}

static inline bool is_ldrsh_uoff(const ldrsh_uoff_t *ldrsh)
{
    return ldrsh->op == 0b011110011;
}

static inline uint32_t get_ldrsh_uoff(const ldrsh_uoff_t *ldrsh)
{
    return ldrsh->imm << 1;
}

static inline bool is_ldrsw_uoff(const ldrsw_uoff_t *ldrsw)
{
    return ldrsw->op == 0b101110011;
}

static inline uint32_t get_ldrsw_uoff(const ldrsw_uoff_t *ldrsw)
{
    return ldrsw->imm << 2;
}

static inline bool is_strb_uoff(const strb_uoff_t *strb)
{
    return strb->op == 0b0011100100;
}

static inline uint32_t get_strb_uoff(const strb_uoff_t *strb)
{
    return strb->imm;
}

static inline bool is_strh_uoff(const strh_uoff_t *strh)
{
    return strh->op == 0b0111100100;
}

static inline uint32_t get_strh_uoff(const strh_uoff_t *strh)
{
    return strh->imm << 1;
}

static inline bool is_ldr_fp_uoff(const ldr_fp_uoff_t *ldr)
{
    return ldr->op1 == 0b111101 && ldr->op2 == 0b1;
}

static inline bool is_str_fp_uoff(const str_fp_uoff_t *str)
{
    return str->op1 == 0b111101 && str->op2 == 0b0;
}

static inline uint32_t get_fp_uoff_size(const ldr_fp_uoff_t *ldr)
{
    return (ldr->opc << 2) | ldr->size;
}

static inline uint32_t get_fp_uoff(const ldr_fp_uoff_t *ldr)
{
    return ldr->imm << get_fp_uoff_size(ldr);
}

static inline bool is_ldur_fp(const ldur_fp_t *stur)
{
    return stur->op1 == 0b111100 && stur->op2 == 0b10 && stur->op3 == 0b00;
}

static inline bool is_stur_fp(const stur_fp_t *stur)
{
    return stur->op1 == 0b111100 && stur->op2 == 0b00 && stur->op3 == 0b00;
}

static inline uint32_t get_ldur_stur_fp_size(const stur_fp_t *ldur)
{
    return (ldur->opc << 2) | ldur->size;
}

static inline int64_t get_ldur_stur_fp_off(const stur_fp_t *ldur)
{
    return (int64_t)(((uint64_t)ldur->imm) << (64 - 9)) >> (64 - 9);
}

static inline bool is_blr(const br_t *br)
{
    return br->op1 == 0b1101011000111111000000 && br->op2 == 0;
}

static inline bool is_br(const br_t *br)
{
    return br->op1 == 0b1101011000011111000000 && br->op2 == 0;
}

static inline bool is_bl(const bl_t *bl)
{
    return bl->op == 0x5 && bl->mode == 1;
}

static inline bool is_b(const b_t *b)
{
    return b->op == 0x5 && b->mode == 0;
}

static inline int64_t get_bl_off(const bl_t *bl)
{
    return (int64_t)(((uint64_t)bl->imm) << (64 - 26)) >> (64 - 26 - 2);
}

static inline bool is_b_cond(const b_cond_t *b)
{
    return b->op1 == 0b01010100 && b->op2 == 0;
}

static inline int64_t get_b_cond_off(const b_cond_t *b)
{
    return (int64_t)(((uint64_t)b->imm) << (64 - 19)) >> (64 - 19 - 2);
}

static inline bool is_cbz(const cbz_t *cbz)
{
    return cbz->op == 0x34;
}

static inline bool is_cbnz(const cbz_t *cbz)
{
    return cbz->op == 0x35;
}

static inline int64_t get_cbz_off(const cbz_t *cbz)
{
    return (int64_t)(((uint64_t)cbz->imm) << (64 - 19)) >> (64 - 19 - 2);
}

static inline bool is_tbz(const tbz_t *tbz)
{
    return tbz->op == 0x36;
}

static inline bool is_tbnz(const tbz_t *tbz)
{
    return tbz->op == 0x37;
}

static inline uint32_t get_tbz_bit(const tbz_t *tbz)
{
    return (tbz->sf << 5) | tbz->bit;
}

static inline int64_t get_tbz_off(const tbz_t *tbz)
{
    return (int64_t)(((uint64_t)tbz->imm) << (64 - 14)) >> (64 - 14 - 2);
}

/*static inline bool is_mov(const mov_t *mov)
{
    return mov->op1 == 0x150 && mov->op2 == 0x1f;
}*/

static inline bool is_csel(const csel_t *csel)
{
    return csel->op1 == 0b0011010100 && csel->op2 == 0b00;
}

static inline bool is_csinc(const csinc_t *csinc)
{
    return csinc->op1 == 0b0011010100 && csinc->op2 == 0b01;
}

static inline bool is_movz(const movz_t *movz)
{
    return movz->op == 0xa5;
}

static inline bool is_movk(const movk_t *movk)
{
    return movk->op == 0xe5;
}

static inline uint64_t get_movzk_imm(const movz_t *movz)
{
    return movz->imm << (movz->hw << 4);
}

static inline bool is_movn(const movn_t *movn)
{
    return movn->op == 0x25;
}

static inline int64_t get_movn_imm(const movn_t *movn)
{
    return ~get_movzk_imm(movn);
}

static inline bool is_movi(const movi_t *movi)
{
    if(movi->op1 == 0b0 && movi->op2 == 0b0111100000 && movi->op3 == 0b01)
    {
        uint8_t x = (movi->cmode << 1) | movi->op;
        return ((x & 0b10011) == 0b00000) || ((x & 0b11011) == 0b10000) || ((x & 0b11101) == 0b11000) || ((x & 0b11110) == 0b11100) || (x == 0b11110) || (x == 0b11111 && movi->Q == 0b1);
    }
    return false;
}

static inline bool is_pac(const pac_t *pac)
{
    return pac->op1 == 0x36b04 && pac->op2 == 0;
}

static inline bool is_pacsys(const pacsys_t *pacsys)
{
    return pacsys->op1 == 0x3540c8 && pacsys->op2 == 0x2 && pacsys->op3 == 0x1f && (pacsys->x == 0 || pacsys->C == 1);
}

static inline bool is_pacga(const pacga_t *pacga)
{
    return pacga->op1 == 0x4d6 && pacga->op2 == 0xc;
}

static inline bool is_aut(const pac_t *pac)
{
    return pac->op1 == 0x36b04 && pac->op2 == 1;
}

static inline bool is_autsys(const pacsys_t *pacsys)
{
    return pacsys->op1 == 0x3540c8 && pacsys->op2 == 0x3 && pacsys->op3 == 0x1f && (pacsys->x == 0 || pacsys->C == 1);
}

static inline bool is_mrs(const sys_t *sys)
{
    return sys->op == 0b1101010100 && sys->L == 1 && (sys->op0 & 0b10) == 0b10;
}

static inline bool is_dc_zva(const sys_t *sys)
{
    return sys->op == 0b1101010100 && sys->L == 0 && sys->op0 == 0b01 && sys->op1 == 0b011 && sys->CRn == 0b0111 && sys->CRm == 0b0100 && sys->op2 == 0b001;
}

static inline bool is_blra(const bra_t *bra)
{
    return bra->op == 0b110101110011111100001;
}

static inline bool is_bra(const bra_t *bra)
{
    return bra->op == 0b110101110001111100001;
}

static inline bool is_bti(const bti_t *bti)
{
    return bti->op1 == 0b110101010000001100100100 && bti->op3 == 0b011111;
}

static inline bool is_nop(const nop_t *nop)
{
    return *nop == 0xd503201f;
}

static inline bool is_ret(const ret_t *ret)
{
    ret_t r = *ret;
    return r == 0xd65f03c0 || // ret
           r == 0xd65f0bff || // retaa
           r == 0xd65f0fff;   // retab
}

static inline bool is_and_reg(const and_reg_t *and)
{
    return and->op == 0b0001010 && and->N == 0;
}

static inline bool is_ands_reg(const ands_reg_t *ands)
{
    return ands->op == 0b1101010 && ands->N == 0;
}

static inline bool is_orr_reg(const orr_reg_t *orr)
{
    return orr->op == 0b0101010 && orr->N == 0;
}

static inline bool is_eor_reg(const eor_reg_t *eor)
{
    return eor->op == 0b1001010 && eor->N == 0;
}

static inline bool is_and(const and_t *and)
{
    return and->op == 0b00100100;
}

static inline bool is_ands(const ands_t *ands)
{
    return ands->op == 0b11100100;
}

static inline bool is_orr(const orr_t *orr)
{
    return orr->op == 0b01100100;
}

static inline bool is_eor(const eor_t *eor)
{
    return eor->op == 0b10100100;
}

static inline bool is_bfm(const bfm_t *bfm)
{
    return bfm->op == 0b01100110;
}

static inline bool is_sbfm(const sbfm_t *sbfm)
{
    return sbfm->op == 0b00100110;
}

static inline bool is_ubfm(const ubfm_t *ubfm)
{
    return ubfm->op == 0b10100110;
}

// and/orr/eor - holy clusterfuck

typedef struct
{
    uint64_t wmask;
    uint64_t tmask;
} a64_bitmasks_t;

extern a64_bitmasks_t DecodeBitMasks(uint8_t N, uint8_t imms, uint8_t immr, uint8_t bits);

static inline a64_bitmasks_t get_bitmasks(const orr_t *orr)
{
    return DecodeBitMasks(orr->N, orr->imms, orr->immr, 32 << orr->sf);
}

// movi - well fml this is even worse

extern uint64_t AdvSIMDExpandImm(uint8_t op, uint8_t cmode, uint64_t imm8);

static inline __uint128_t get_movi_imm(const movi_t *movi)
{
    __uint128_t val = AdvSIMDExpandImm(movi->op, movi->cmode, (movi->abc << 5) | movi->defgh);
    if(movi->Q == 0b1)
    {
        val |= val << 64;
    }
    return val;
}

#endif
