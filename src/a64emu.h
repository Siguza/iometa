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
    kEmuFnIgnore,
    kEmuFnAssumeX0,
    kEmuFnEnter,
} emu_fn_behaviour_t;

typedef struct
{
    uint64_t x[32];
    __uint128_t q[32];
    uint32_t valid;
    uint32_t qvalid;
    uint32_t wide;
    uint32_t host;
} a64_state_t;

typedef bool (*a64cb_t)(uint32_t *pos, void *arg);

bool is_linear_inst(void *ptr);

uint32_t* find_function_start(void *kernel, mach_seg_t *seg, const char *name, uint32_t *fnstart, bool have_stack_frame);

bool a64cb_check_equal(uint32_t *pos, void *arg);
bool a64cb_check_bl(uint32_t *pos, void *arg);

emu_ret_t a64_emulate(void *kernel, kptr_t kbase, fixup_kind_t fixupKind, a64_state_t *state, uint32_t *from, a64cb_t check, void *arg, bool init, bool warnUnknown, emu_fn_behaviour_t fn_behaviour);
bool multi_call_emulate(void *kernel, kptr_t kbase, fixup_kind_t fixupKind, uint32_t *fncall, uint32_t *end, a64_state_t *state, void *sp, uint32_t wantvalid, const char *name);

#endif
