/* Copyright (c) 2018-2024 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#ifndef META_H
#define META_H

#include <stdint.h>

#include "a64emu.h"
#include "macho.h"
#include "util.h"

#define NUM_METACLASSES_EXPECT 0x1000

struct symmap_class;

typedef struct vtab_entry
{
    struct vtab_entry *chain; // only used for back-propagating name
    const char *mangled;
    const char *class;
    const char *method;
    kptr_t addr;
    uint16_t pac;
    uint16_t structor      :  1,
             authoritative :  1,
             overrides     :  1,
             auth          :  1,
             reserved      : 12;
} vtab_entry_t;

typedef struct metaclass
{
    kptr_t addr;
    kptr_t parent;
    kptr_t vtab;
    kptr_t metavtab;
    kptr_t callsite;
    struct metaclass *parentP;
    struct symmap_class *symclass;
    const char *name;
    const char *bundle;
    vtab_entry_t *methods;
    vtab_entry_t *metamethods;
    size_t nmethods;
    size_t nmetamethods;
    uint32_t objsize;
    uint32_t methods_done   :  1,
             methods_err    :  1,
             visited        :  1,
             duplicate      :  1,
             has_dependents :  1,
             reserved       : 27;
} metaclass_t;

typedef struct
{
    const char *name;
    const uint32_t *fncall;
} metaclass_candidate_t;

typedef bool (*meta_constructor_cb_t)(macho_t *macho, bool want_vtabs, void *metas, void *names, a64_state_t *state, const uint32_t *fnstart, const uint32_t *bl, kptr_t bladdr, void *arg);

int compare_meta_candidates(const void *a, const void *b);
int compare_meta_names(const void *a, const void *b);
int compare_meta_bundles(const void *a, const void *b);

#if 0
void add_metaclass(void *kernel, kptr_t kbase, fixup_kind_t fixupKind, void *arg, a64_state_t *state, uint32_t *callsite, bool want_vtabs, sym_t *bsyms, size_t nsyms);

void meta_constructor_cb(void *kernel, kptr_t kbase, mach_seg_t *seg, fixup_kind_t fixupKind, bool want_vtabs, void *metas, void *names, sym_t *bsyms, size_t nsyms, a64_state_t *state, uint32_t *fnstart, uint32_t *bl, kptr_t bladdr, void *arg);
void meta_alt_constructor_cb(void *kernel, kptr_t kbase, mach_seg_t *seg, fixup_kind_t fixupKind, bool want_vtabs, void *metas, void *names, sym_t *bsyms, size_t nsyms, a64_state_t *state, uint32_t *fnstart, uint32_t *bl, kptr_t bladdr, void *arg);
void find_meta_constructor_calls(void *kernel, mach_hdr_t *hdr, kptr_t kbase, fixup_kind_t fixupKind, bool have_plk_text_exec, bool want_vtabs, void *arr, void *metas, void *names, sym_t *bsyms, size_t nsyms, meta_constructor_cb_t cb, void *arg);
#else
void add_metaclass(macho_t *macho, void *arg, a64_state_t *state, const uint32_t *callsite, bool want_vtabs);

bool meta_constructor_cb(macho_t *macho, bool want_vtabs, void *metas, void *names, a64_state_t *state, const uint32_t *fnstart, const uint32_t *bl, kptr_t bladdr, void *arg);
bool meta_alt_constructor_cb(macho_t *macho, bool want_vtabs, void *metas, void *names, a64_state_t *state, const uint32_t *fnstart, const uint32_t *bl, kptr_t bladdr, void *arg);
bool find_meta_constructor_calls(macho_t *macho, bool want_vtabs, void *arr, void *metas, void *names, meta_constructor_cb_t cb, void *arg);
#endif

#endif
