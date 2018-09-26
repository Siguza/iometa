#ifndef A64_H
#define A64_H

#include <stddef.h>             // size_t
#include <stdbool.h>
#include <stdint.h>

#pragma pack(4)
typedef struct
{
    uint32_t Rd     : 5,
             immhi  : 19,
             op2    : 5,
             immlo  : 2,
             op1    : 1;
} adr_t;

typedef struct
{
    uint32_t Rd     : 5,
             Rn     : 5,
             imm    : 12,
             shift  : 2,
             op     : 7,
             sf     : 1;
} add_imm_t, sub_imm_t;

typedef struct
{
    uint32_t Rt     : 5,
             Rn     : 5,
             imm    : 12,
             op2    : 8,
             sf     : 1,
             op1    : 1;
} ldr_imm_uoff_t;

typedef struct
{
    uint32_t Rt     : 5,
             imm    : 19,
             op2    : 6,
             sf     : 1,
             op1    : 1;
} ldr_lit_t;

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
             imm    : 12,
             op2    : 8,
             sf     : 1,
             op1    : 1;
} str_uoff_t;

typedef struct
{
    uint32_t Rt     : 5,
             Rn     : 5,
             Rt2    : 5,
             imm    : 7,
             op     : 9,
             sf     : 1;
} stp_t;

/*typedef struct
{
    uint32_t Rt     : 5,
             Rn     : 5,
             Rt2    : 5,
             imm    : 7,
             op     : 8,
             opc    : 2;
} stp_fp_t;*/

typedef struct
{
    uint32_t op2    : 5,
             Rn     : 5,
             op1    : 22;
} br_t;

typedef struct
{
    uint32_t imm    : 26,
             op     : 5,
             mode   : 1;
} bl_t;

typedef struct
{
    uint32_t Rd     : 5,
             op2    : 11,
             Rm     : 5,
             op1    : 10,
             sf     : 1;
} mov_t;

typedef struct
{
    uint32_t Rd     : 5,
             imm    : 16,
             hw     : 2,
             op     : 8,
             sf     : 1;
} movz_t, movk_t, movn_t;

typedef struct
{
    uint32_t Rd     : 5,
             Rn     : 5,
             imms   : 6,
             immr   : 6,
             N      : 1,
             op     : 8,
             sf     : 1;
} orr_t;

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
    return add->op == 0x11 && !(add->shift & 2);
}

static inline bool is_sub_imm(sub_imm_t *sub)
{
    return sub->op == 0x51 && !(sub->shift & 2);
}

static inline uint32_t get_add_sub_imm(add_imm_t *add)
{
    return add->imm << ((add->shift & 1) ? 12 : 0);
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
    return (((int64_t)ldr->imm) << (64 - 19)) >> (64 - 21);
}

/*static inline bool is_str_reg(str_reg_t *str)
{
    return str->op1 == 1 && str->op2 == 0x1c1 && str->op3 == 2;
}*/

static inline bool is_str_uoff(str_uoff_t *str)
{
    return str->op1 == 1 && str->op2 == 0xe4;
}

static inline uint32_t get_str_uoff(str_uoff_t *str)
{
    return str->imm << (2 + str->sf);
}

static inline bool is_stp_pre(stp_t *stp)
{
    return stp->op == 0xa6;
}

static inline int64_t get_stp_pre_off(stp_t *stp)
{
    return ((int64_t)stp->imm << (64 - 7)) >> (64 - 7 - (2 + stp->sf));
}

static inline bool is_stp_uoff(stp_t *stp)
{
    return stp->op == 0xa4;
}

/*static inline bool is_stp_fp_uoff(stp_fp_t *stp)
{
    return stp->op == 0xb4;
}*/

static inline bool is_br(br_t *br)
{
    return br->op1 == 0x3587c0 && br->op2 == 0;
}

static inline bool is_bl(bl_t *bl)
{
    return bl->op == 0x5;
}

static inline int64_t get_bl_off(bl_t *bl)
{
    return (((int64_t)bl->imm) << (64 - 26)) >> (64 - 26 - 2);
}

static inline bool is_mov(mov_t *mov)
{
    return mov->op1 == 0x150 && mov->op2 == 0x1f;
}

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

static inline bool is_nop(nop_t *nop)
{
    return *nop == 0xd503201f;
}

static inline bool is_ret(ret_t *ret)
{
    return *ret == 0xd65f03c0;
}

static inline bool is_orr(orr_t *orr)
{
    return orr->op == 0x64;
}

// orr - holy clusterfuck

extern uint64_t DecodeBitMasks(uint8_t N, uint8_t imms, uint8_t immr, uint8_t bits);

static inline uint32_t get_orr_imm(orr_t *orr)
{
    return DecodeBitMasks(orr->N, orr->imms, orr->immr, 32 << orr->sf);
}

#endif
