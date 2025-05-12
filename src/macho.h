/* Copyright (c) 2018-2025 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#ifndef MACHO_H
#define MACHO_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>             // size_t
#include <stdint.h>
//#include <CoreFoundation/CoreFoundation.h>

// Apple notation
#define VM_PROT_READ    0x1
#define VM_PROT_WRITE   0x2
#define VM_PROT_EXECUTE 0x4
#define VM_PROT_ALL     0x7

// My stuff
#define ADDR     "0x%016"PRIx64
typedef uint64_t kptr_t;

typedef struct
{
    kptr_t addr;
    const char *name;
} sym_t;

typedef struct _macho macho_t;

macho_t* macho_open(const char *file);
void macho_close(macho_t *macho);

bool macho_is_kext(macho_t *macho);
bool macho_has_pac(macho_t *macho);

bool macho_is_ptr(macho_t *macho, const void *loc);
kptr_t macho_fixup(macho_t *macho, kptr_t ptr, bool *bind, bool *auth, uint16_t *pac, size_t *skip);

kptr_t macho_base(macho_t *macho);
kptr_t macho_ptov(macho_t *macho, const void *ptr);
const void* macho_vtop(macho_t *macho, kptr_t addr, size_t size);
void* macho_vtop_rw(macho_t *macho, kptr_t addr, size_t size);

// NOTE: Zerofill ranges excluded here
bool macho_segment(macho_t *macho, const char *segment, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot);
bool macho_section(macho_t *macho, const char *segment, const char *section, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot);
bool macho_segment_for_addr(macho_t *macho, kptr_t target, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot);
bool macho_section_for_addr(macho_t *macho, kptr_t target, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot);
bool macho_segment_for_ptr(macho_t *macho, const void *target, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot);
bool macho_section_for_ptr(macho_t *macho, const void *target, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot);

bool macho_foreach_map(macho_t *macho, bool (*cb)(const void *ptr, kptr_t addr, size_t size, uint32_t prot, void *arg), void *arg);
bool macho_foreach_segment(macho_t *macho, bool (*cb)(const void *ptr, kptr_t addr, size_t size, uint32_t prot, const char *segment, void *arg), void *arg);
bool macho_foreach_section(macho_t *macho, bool (*cb)(const void *ptr, kptr_t addr, size_t size, uint32_t prot, const char *segment, const char *section, void *arg), void *arg);

bool macho_foreach_ptr(macho_t *macho, bool (*cb)(const kptr_t *ptr, void *arg), void *arg);
bool macho_find_bytes(macho_t *macho, const void *bytes, size_t size, size_t alignment, bool (*cb)(kptr_t addr, void *arg), void *arg);

bool macho_have_symbols(macho_t *macho);
kptr_t macho_symbol(macho_t *macho, const char *sym);
const sym_t* macho_symbols_for_prefix(macho_t *macho, const char *prefix, size_t *n);
const sym_t* macho_symbols_for_addr(macho_t *macho, kptr_t addr, size_t *n);
kptr_t macho_reloc(macho_t *macho, const char *sym);
const char* macho_reloc_for_addr(macho_t *macho, kptr_t loc);

//CFTypeRef macho_prelink_info(macho_t *macho);

kptr_t macho_fnstart(macho_t *macho, kptr_t addr);

const char* const* macho_bundles(macho_t *macho, size_t *n);
const char* macho_bundle_for_addr(macho_t *macho, kptr_t addr);

#endif
