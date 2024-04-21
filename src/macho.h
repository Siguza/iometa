/* Copyright (c) 2018-2024 Siguza
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
#include <CoreFoundation/CoreFoundation.h>

#ifdef CPU_TYPE_ARM64
#   undef CPU_TYPE_ARM64
#endif
#ifdef CPU_SUBTYPE_MASK
#   undef CPU_SUBTYPE_MASK
#endif
#ifdef CPU_SUBTYPE_ARM64_ALL
#   undef CPU_SUBTYPE_ARM64_ALL
#endif
#ifdef CPU_SUBTYPE_ARM64E
#   undef CPU_SUBTYPE_ARM64E
#endif

// Apple notation
#define VM_PROT_READ                       0x1
#define VM_PROT_WRITE                      0x2
#define VM_PROT_EXECUTE                    0x4
#define VM_PROT_ALL                        0x7
#define CPU_TYPE_ARM64              0x0100000c
#define CPU_SUBTYPE_MASK            0x00ffffff
#define CPU_SUBTYPE_ARM64_ALL              0x0
#define CPU_SUBTYPE_ARM64E                 0x2
#define FAT_CIGAM                   0xbebafeca
#define MH_MAGIC_64                 0xfeedfacf
#define MH_EXECUTE                  0x00000002
#define MH_KEXT_BUNDLE              0x0000000b
#define MH_FILESET                  0x0000000c
#define MH_DYLIB_IN_CACHE           0x80000000
#define LC_REQ_DYLD                 0x80000000
#define LC_SYMTAB                   0x00000002
#define LC_DYSYMTAB                 0x0000000b
#define LC_SEGMENT_64               0x00000019
#define LC_UUID                     0x0000001b
#define LC_DYLD_CHAINED_FIXUPS      0x80000034
#define LC_FILESET_ENTRY            0x80000035
#define SECTION_TYPE                0x000000ff
#define S_ZEROFILL                         0x1
#define N_STAB                            0xe0
#define N_TYPE                            0x0e
#define N_EXT                             0x01
#define N_SECT                            0x0e
struct fat_header
{
    uint32_t magic;
    uint32_t nfat_arch;
};
struct fat_arch
{
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
};
struct mach_header_64
{
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};
struct load_command
{
    uint32_t cmd;
    uint32_t cmdsize;
};
struct segment_command_64
{
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};
struct section_64
{
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};
struct symtab_command
{
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
};
struct dysymtab_command
{
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t iundefsym;
    uint32_t nundefsym;
    uint32_t tocoff;
    uint32_t ntoc;
    uint32_t modtaboff;
    uint32_t nmodtab;
    uint32_t extrefsymoff;
    uint32_t nextrefsyms;
    uint32_t indirectsymoff;
    uint32_t nindirectsyms;
    uint32_t extreloff;
    uint32_t nextrel;
    uint32_t locreloff;
    uint32_t nlocrel;
};
struct linkedit_data_command
{
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};
struct uuid_command
{
    uint32_t cmd;
    uint32_t cmdsize;
    uint8_t  uuid[16];
};
struct fileset_entry_command
{
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t vmaddr;
    uint64_t fileoff;
    uint32_t nameoff;
};
struct nlist_64
{
    uint32_t n_strx;
    uint8_t  n_type;
    uint8_t  n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};
struct relocation_info
{
   int32_t  r_address;
   uint32_t r_symbolnum : 24,
            r_pcrel     :  1,
            r_length    :  2,
            r_extern    :  1,
            r_type      :  4;
};
struct dyld_chained_fixups_header
{
    uint32_t fixups_version;
    uint32_t starts_offset;
    uint32_t imports_offset;
    uint32_t symbols_offset;
    uint32_t imports_count;
    uint32_t imports_format;
    uint32_t symbols_format;
};
struct dyld_chained_starts_in_image
{
    uint32_t seg_count;
    uint32_t seg_info_offset[];
};
struct dyld_chained_starts_in_segment
{
    uint32_t size;
    uint16_t page_size;
    uint16_t pointer_format;
    uint64_t segment_offset;
    uint32_t max_valid_pointer;
    uint16_t page_count;
    uint16_t page_start[];
};
struct dyld_chained_import
{
    uint32_t lib_ordinal :  8,
             weak_import :  1,
             name_offset : 23;
};

// My aliases
#define ADDR                                    "0x%016" PRIx64
//#define MACH_MAGIC                              MH_MAGIC_64
//#define MACH_SEGMENT                            LC_SEGMENT_64
typedef struct fat_header                       fat_hdr_t;
typedef struct fat_arch                         fat_arch_t;
typedef struct mach_header_64                   mach_hdr_t;
typedef struct load_command                     mach_lc_t;
typedef struct segment_command_64               mach_seg_t;
typedef struct section_64                       mach_sec_t;
typedef struct symtab_command                   mach_stab_t;
typedef struct dysymtab_command                 mach_dstab_t;
typedef struct fileset_entry_command            mach_fileent_t;
typedef struct nlist_64                         mach_nlist_t;
typedef struct relocation_info                  mach_reloc_t;
typedef struct dyld_chained_fixups_header       fixup_hdr_t;
typedef struct dyld_chained_starts_in_image     fixup_seg_t;
typedef struct dyld_chained_starts_in_segment   fixup_starts_t;
typedef struct dyld_chained_import              fixup_import_t;
typedef uint64_t                                kptr_t;

typedef struct
{
    kptr_t addr;
    const char *name;
} sym_t;

#if 0
#define FOREACH_CMD(_hdr, _cmd) \
for( \
    mach_lc_t *_cmd = (mach_lc_t*)(_hdr + 1), *_end = (mach_lc_t*)((uintptr_t)_cmd + _hdr->sizeofcmds - sizeof(mach_lc_t)); \
    _cmd <= _end; \
    _cmd = (mach_lc_t*)((uintptr_t)_cmd + _cmd->cmdsize) \
)

#define SEG_IS_EXEC(seg, fixupKind, have_plk_text_exec) (((seg)->initprot & VM_PROT_EXECUTE) || ((fixupKind) == DYLD_CHAINED_PTR_NONE && !(have_plk_text_exec) && strcmp("__PRELINK_TEXT", (seg)->segname) == 0))

kptr_t off2addr(void *macho, size_t off);
void* addr2ptr(void *macho, kptr_t addr);
mach_seg_t* seg4ptr(void *macho, void *ptr);

kptr_t kuntag(kptr_t base, fixup_kind_t fixupKind, kptr_t ptr, bool *bind, bool *auth, uint16_t *pac, size_t *skip);

bool is_in_fixup_chain(void *macho, kptr_t base, void *ptr);

int validate_macho(void **machop, size_t *machosizep, mach_hdr_t **hdrp, const char *name);

int compare_sym_addrs(const void *a, const void *b);
int compare_sym_names(const void *a, const void *b);
int compare_sym_addr(const void *a, const void *b);
int compare_sym_name(const void *a, const void *b);
const char* find_sym_by_addr(kptr_t addr, sym_t *asyms, size_t nsyms);
kptr_t find_sym_by_name(const char *name, sym_t *bsyms, size_t nsyms);

bool macho_extract_symbols(void *macho, mach_stab_t *stab, sym_t **symp, size_t *nsymp);
bool macho_extract_reloc(void *macho, kptr_t base, mach_dstab_t *dstab, mach_nlist_t *symtab, char *strtab, sym_t **exrelocp, size_t *nexrelocp);
bool macho_extract_chained_imports(void *macho, kptr_t base, struct linkedit_data_command *cmd, sym_t **exrelocp, size_t *nexrelocp);
#else
// Actual custom impl
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

CFTypeRef macho_prelink_info(macho_t *macho);
#endif

#endif
