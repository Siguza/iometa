/* Copyright (c) 2018-2024 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#ifndef A64EMU_H
#define A64EMU_H

#include <stdbool.h>
#include <stdint.h>

#include "macho.h"

#define A64_EMU_SPSIZE 0x1000

typedef enum
{
    kEmuErr,
    kEmuUnknown,
    kEmuEnd,
    kEmuRet,
} emu_ret_t;

typedef enum
{
    kEmuFnIgnore   = 0,
    kEmuFnAssumeX0 = 1 << 0,
    kEmuFnEnter    = 1 << 1,
} emu_fn_behaviour_t;

typedef struct
{
    uint64_t x[32];
    __uint128_t q[32];
    union
    {
        uint32_t flags;
        struct
        {
            uint32_t v          :  1,
                     c          :  1,
                     z          :  1,
                     n          :  1,
                     res        : 27,
                     nzcv_valid :  1;
        };
    };
    uint32_t valid;
    uint32_t qvalid;
    uint32_t wide;
    // TODO: qwide
    uint64_t host; // 32x 2 bits, index into hostmem
    struct
    {
        uint64_t min;
        uint64_t max;
        uint8_t *bitstring;
    } hostmem[3];
} a64_state_t;

#define HOST_GET(state, reg) ((uint8_t)(((state)->host >> ((reg) << 1)) & 3ULL))
#define HOST_SET(state, reg, idx) do { ((state)->host = ((state)->host & ~(3ULL << ((reg) << 1))) | ((((uint64_t)idx) & 3ULL) << ((reg) << 1))); } while(0)

typedef bool (*a64cb_t)(const uint32_t *pos, void *arg);

bool is_linear_inst(const void *ptr);

const uint32_t* find_function_start(macho_t *macho, const char *name, const uint32_t *fnstart, const uint32_t *bound, bool have_stack_frame);

bool a64cb_check_equal(const uint32_t *pos, void *arg);
bool a64cb_check_bl(const uint32_t *pos, void *arg);

emu_ret_t a64_emulate(macho_t *macho, a64_state_t *state, const uint32_t *from, a64cb_t check, void *arg, bool init, bool warnUnknown, emu_fn_behaviour_t fn_behaviour);
bool multi_call_emulate(macho_t *macho, const uint32_t *fncall, const uint32_t *end, a64_state_t *state, void *sp, uint8_t *bitstr, uint32_t wantvalid, const char *name);

#endif
