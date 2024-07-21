/* Copyright (c) 2018-2024 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#if 0
#include <stdlib.h>             // realloc
#endif

#include <fcntl.h>              // open
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>             // malloc, free, qsort, bsearch, exit
#include <unistd.h>             // close
#include <sys/mman.h>           // mmap, munmap, MAP_FAILED
#include <sys/stat.h>           // fstat
#include <CoreFoundation/CoreFoundation.h>

extern CFTypeRef IOCFUnserialize(const char *buffer, CFAllocatorRef allocator, CFOptionFlags options, CFStringRef *errorString);

#include "macho.h"
#include "util.h"

typedef enum
{
    DYLD_CHAINED_PTR_NONE               = 0,  // pacptr.ptr
    DYLD_CHAINED_PTR_ARM64E_KERNEL      = 7,  // pacptr.pac, virt offset
    DYLD_CHAINED_PTR_64_KERNEL_CACHE    = 8,  // pacptr.cache, virt offset
    DYLD_CHAINED_PTR_ARM64E_FIRMWARE    = 10, // pacptr.pac, virt addr (unauth) or virt offset (auth)
} fixup_kind_t;

typedef struct
{
    uint32_t stride;
    uint32_t starts[];
} thread_starts_t;

typedef struct
{
    uint32_t count;
    uint32_t offsetsArray[];
} kaslrPackedOffsets_t;

typedef union
{
    kptr_t ptr;
    struct
    {
        int64_t lo  : 51,
                hi  : 13;
    } raw;
    struct
    {
        kptr_t off  : 32,
               div  : 16,
               tag  :  1,
               dkey :  1,
               bkey :  1,
               next : 11,
               bind :  1,
               auth :  1;
    } pac;
    struct
    {
        kptr_t target : 30,
               cache  :  2,
               div    : 16,
               tag    :  1,
               dkey   :  1,
               bkey   :  1,
               next   : 12,
               auth   :  1;
    } cache;
} pacptr_t;

typedef struct
{
    kptr_t addr;
    size_t size;
    uintptr_t mem;
    uint32_t prot;
} macho_map_t;

typedef struct
{
    kptr_t addr;
    size_t size;
    uintptr_t mem;
    uint32_t prot;
    char segname[17]; // null terminator
} macho_segment_t;

typedef struct
{
    kptr_t addr;
    size_t size;
    uintptr_t mem;
    uint32_t prot;
    char segname[17]; // null terminator
    char secname[17]; // null terminator
} macho_section_t;

struct _macho
{
    int fd;
    uint32_t filetype;
    uint32_t subtype;
    fixup_kind_t fixupKind;
    union fixup_data
    {
        const fixup_seg_t *chain;
        const mach_sec_t *thread;
        kaslrPackedOffsets_t *kxld;
    } fixup;
    const void *mem;
    size_t memsize;
    const mach_hdr_t *hdr;
    size_t size;
    kptr_t base;
    macho_map_t *mapV;
    size_t nmapV;
    macho_map_t *mapP;
    size_t nmapP;
    macho_segment_t *segmentsByName;
    macho_segment_t *segmentsByAddr;
    size_t nsegs;
    macho_section_t *sectionsByName;
    macho_section_t *sectionsByAddr;
    size_t nsecs;
    sym_t *symsByName;
    sym_t *symsByAddr;
    size_t nsyms;
    sym_t *relocByName;
    sym_t *relocByAddr;
    size_t nreloc;
    CFTypeRef prelinkInfo;
    uint8_t **ptrBitmap;
};

// High-level funcs needed during initialisation
static kptr_t macho_fixup_internal(fixup_kind_t fixupKind, kptr_t base, kptr_t ptr, bool *bind, bool *auth, uint16_t *pac, size_t *skip);
static kptr_t macho_ptov_internal(const macho_map_t *mapP, size_t nmapP, const void *ptr);
static const void* macho_vtop_internal(const macho_map_t *mapV, size_t nmapV, kptr_t addr, size_t size);
static bool macho_section_for_addr_internal(const macho_section_t *sectionsByAddr, size_t nsecs, kptr_t target, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot);
static bool macho_foreach_ptr_internal(uintptr_t hdr, fixup_kind_t fixupKind, union fixup_data fixup, kptr_t base, macho_map_t *mapV, size_t nmapV, bool (*cb)(const kptr_t *ptr, void *arg), void *arg);
static CFTypeRef macho_prelink_info_internal(const macho_section_t *sectionsByName, size_t nsecs);

#define MACHO_BITMAP_PAGESIZE 0x4000
#define MACHO_BITMAP_PAGE(off) ((off) / MACHO_BITMAP_PAGESIZE)
#define MACHO_BITMAP_IDX(off) (((off) & (MACHO_BITMAP_PAGESIZE - 1)) >> 5)
#define MACHO_BITMAP_BIT(off) (((off) >> 2) & 0x7)

// Because simple subtraction doesn't fit into the return value
static inline int macho_cmp_u64(uint64_t a, uint64_t b)
{
    if(a == b)
    {
        return 0;
    }
    return a < b ? -1 : 1;
}

static int macho_cmp_map_addr(const void *a, const void *b)
{
    return macho_cmp_u64(((const macho_map_t*)a)->addr, ((const macho_map_t*)b)->addr);
}

static int macho_cmp_map_ptr(const void *a, const void *b)
{
    return macho_cmp_u64(((const macho_map_t*)a)->mem, ((const macho_map_t*)b)->mem);
}

static int macho_cmp_seg_name(const void *a, const void *b)
{
    return strcmp(((const macho_segment_t*)a)->segname, ((const macho_segment_t*)b)->segname);
}

static int macho_cmp_seg_addr(const void *a, const void *b)
{
    return macho_cmp_u64(((const macho_segment_t*)a)->addr, ((const macho_segment_t*)b)->addr);
}

static int macho_cmp_seg_addr_key(const void *key, const void *value)
{
    return macho_cmp_u64((uint64_t)key, ((const macho_segment_t*)value)->addr);
}

static int macho_cmp_sec_name(const void *a, const void *b)
{
    int r = strcmp(((const macho_section_t*)a)->segname, ((const macho_section_t*)b)->segname);
    if(r != 0)
    {
        return r;
    }
    return strcmp(((const macho_section_t*)a)->secname, ((const macho_section_t*)b)->secname);
}

static int macho_cmp_sec_addr(const void *a, const void *b)
{
    return macho_cmp_u64(((const macho_section_t*)a)->addr, ((const macho_section_t*)b)->addr);
}

static int macho_cmp_sym_name(const void *a, const void *b)
{
    return strcmp(((const sym_t*)a)->name, ((const sym_t*)b)->name);
}

static int macho_cmp_sym_addr(const void *a, const void *b)
{
    return macho_cmp_u64(((const sym_t*)a)->addr, ((const sym_t*)b)->addr);
}

static inline bool macho_skip_symbol(const mach_nlist_t *sym)
{
    uint8_t type = sym->n_type;
    return (type & N_TYPE) != N_SECT || ((type & N_STAB) && !(type & N_EXT));
}

static bool macho_bitmap_set(uint8_t **ptrBitmap, size_t off)
{
    if(off & 0x3)
    {
        __builtin_trap();
    }
    uint8_t *bitmap = ptrBitmap[MACHO_BITMAP_PAGE(off)];
    if(!bitmap)
    {
        bitmap = malloc(MACHO_BITMAP_PAGESIZE >> 5); // 2 for alignment, 3 for uint8
        if(!bitmap)
        {
            ERRNO("malloc(bitmap)");
            return false;
        }
        ptrBitmap[MACHO_BITMAP_PAGE(off)] = bitmap;
    }
    bitmap[MACHO_BITMAP_IDX(off)] |= 0x1 << MACHO_BITMAP_BIT(off);
    return true;
}

static bool macho_validate_fixup_chain(const mach_hdr_t *hdr, kptr_t base, fixup_kind_t fixupKind, const kptr_t *ptr, uintptr_t end, uint8_t **ptrBitmap, size_t *nreloc, uint32_t imports_count)
{
    size_t skip = 0;
    while(1)
    {
        size_t off = (uintptr_t)ptr - (uintptr_t)hdr;
        kptr_t addr = base + off;
        DBG(3, "Fixup " ADDR, addr);
        if(!macho_bitmap_set(ptrBitmap, off))
        {
            return false;
        }
        bool bind = false;
        kptr_t val = macho_fixup_internal(fixupKind, base, *ptr, &bind, NULL, NULL, &skip);
        if(bind)
        {
            if(val >= imports_count)
            {
                ERR("Mach-O chained import number out of bounds: 0x%x", (uint32_t)val);
                return false;
            }
            ++*nreloc;
        }
        if(skip == 0)
        {
            break;
        }
        if(skip < sizeof(kptr_t))
        {
            ERR("Mach-O chained fixup at " ADDR " skips less than 8 bytes.", addr);
            return false;
        }
        ptr = (const kptr_t*)((uintptr_t)ptr + skip);
        if((uintptr_t)ptr > end - sizeof(kptr_t))
        {
            ERR("Mach-O chained fixup at " ADDR " skips past the end of its segment/page.", addr);
            return false;
        }
    }
    return true;
}

typedef struct
{
    const fixup_kind_t fixupKind;
    const kptr_t base;
    const macho_map_t * const mapP;
    const size_t nmapP;
    const fixup_import_t * const import;
    const char * const syms;
    sym_t * const relocByName;
    size_t relocidx;
} chained_imports_cb_t;

static bool macho_chained_imports_cb(const kptr_t *ptr, void *arg)
{
    chained_imports_cb_t *args = arg;
    bool bind = false;
    kptr_t idx = macho_fixup_internal(args->fixupKind, args->base, *ptr, &bind, NULL, NULL, NULL);
    if(bind)
    {
        // At this point, chained fixups were traversed before already, so we don't
        // need to do any validation, and ptrBitmap has been populated too already.
        kptr_t addr = macho_ptov_internal(args->mapP, args->nmapP, ptr);
        const char *name = &args->syms[args->import[idx].name_offset];
        DBG(3, "Chained import " ADDR ": %s", addr, name);
        sym_t *sym = &args->relocByName[args->relocidx++];
        sym->addr = addr;
        sym->name = name;
    }
    return true;
}

macho_t* macho_open(const char *file)
{
    macho_t *macho = NULL;
    int fd = -1;
    const void *mem = MAP_FAILED;
    size_t memsize = 0;
    macho_map_t *mapV = NULL;
    macho_map_t *mapP = NULL;
    macho_segment_t *segmentsByName = NULL;
    macho_segment_t *segmentsByAddr = NULL;
    macho_section_t *sectionsByName = NULL;
    macho_section_t *sectionsByAddr = NULL;
    sym_t *symsByName = NULL;
    sym_t *symsByAddr = NULL;
    sym_t *relocByName = NULL;
    sym_t *relocByAddr = NULL;
    kaslrPackedOffsets_t *kxld = NULL;
    CFTypeRef prelinkInfo = NULL;
    uint8_t **ptrBitmap = NULL;

    fd = open(file, O_RDONLY);
    if(fd == -1)
    {
        ERRNO("open(%s)", file);
        goto out;
    }

    struct stat s;
    if(fstat(fd, &s) != 0)
    {
        ERRNO("fstat(%s)", file);
        goto out;
    }

    memsize = s.st_size;
    if(memsize < sizeof(mach_hdr_t))
    {
        ERR("File is too short to be a Mach-O.");
        goto out;
    }

    mem = mmap(NULL, memsize, PROT_READ, MAP_PRIVATE, fd, 0);
    if(mem == MAP_FAILED)
    {
        ERRNO("mmap(%s)", file);
        goto out;
    }

    const mach_hdr_t *hdr = mem;
    size_t size = memsize;
    if(*(const uint32_t*)mem == FAT_CIGAM)
    {
        if(memsize < sizeof(fat_hdr_t))
        {
            ERR("File is too short to be a fat Mach-O.");
            goto out;
        }
        const fat_hdr_t *fat = mem;
        uint32_t narchs = SWAP32(fat->nfat_arch);
        if(memsize - sizeof(fat_hdr_t) < narchs * sizeof(fat_arch_t))
        {
            ERR("Fat arch list out of bounds.");
            goto out;
        }

        const fat_arch_t *arch = (fat_arch_t*)(fat + 1);
        const fat_arch_t *best = NULL;
        for(uint32_t i = 0; i < narchs; ++i)
        {
            uint32_t cputype = SWAP32(arch[i].cputype);
            if(cputype == CPU_TYPE_ARM64)
            {
                uint32_t off = SWAP32(arch[i].offset);
                uint32_t sz = SWAP32(arch[i].size);
                if(off > memsize || sz > memsize - off)
                {
                    ERR("Fat arch out of bounds.");
                    continue;
                }
                if(sz < sizeof(mach_hdr_t))
                {
                    ERR("Fat arch is too short to contain a Mach-O.");
                    continue;
                }
                uint32_t subtype = SWAP32(arch[i].cpusubtype);
                const mach_hdr_t *candidate = (const mach_hdr_t*)((uintptr_t)mem + off);
                if(candidate->cputype != cputype || candidate->cpusubtype != subtype)
                {
                    ERR("Fat arch doesn't match Mach-O arch.");
                    continue;
                }

                best = &arch[i];
                // Prefer arm64e
                if((subtype & CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E)
                {
                    break;
                }
            }
        }

        if(!best)
        {
            ERR("No (valid) arm64(e) slice in fat binary.");
            goto out;
        }

        hdr = (const mach_hdr_t*)((uintptr_t)mem + SWAP32(best->offset));
        size = SWAP32(best->size);
    }

    // TODO: madvise prefault?

    if(hdr->magic != MH_MAGIC_64)
    {
        ERR("Wrong magic: 0x%08x", hdr->magic);
        goto out;
    }
    if(hdr->cputype != CPU_TYPE_ARM64)
    {
        ERR("Wrong architecture, only arm64(e) is supported.");
        goto out;
    }
    uint32_t subtype = hdr->cpusubtype & CPU_SUBTYPE_MASK;
    if(subtype != CPU_SUBTYPE_ARM64_ALL && subtype != CPU_SUBTYPE_ARM64E)
    {
        ERR("Unknown cpusubtype: 0x%x", subtype);
        goto out;
    }
    uint32_t filetype = hdr->filetype;
    if(filetype != MH_EXECUTE && filetype != MH_KEXT_BUNDLE && filetype != MH_FILESET)
    {
        ERR("Wrong Mach-O type: 0x%x", filetype);
        goto out;
    }
    if(hdr->flags & MH_DYLIB_IN_CACHE)
    {
        ERR("Mach-O header has embedded flag set.");
        goto out;
    }
    if(hdr->sizeofcmds > size - sizeof(mach_hdr_t))
    {
        ERR("Mach-O load commands out of bounds.");
        goto out;
    }

    bool have_base = false;
    kptr_t base = 0;
    bool have_plk_base = false;
    kptr_t plk_base = 0;
    fixup_kind_t fixupKind = DYLD_CHAINED_PTR_NONE;
    const mach_sec_t *thread_starts = NULL;
    const fixup_hdr_t *chained_fixups = NULL;
    size_t nmaps = 0;
    size_t nsegs = 0;
    size_t nsecs = 0;
    const mach_stab_t *stab = NULL;
    const mach_dstab_t *dstab = NULL;
    size_t nsyms = 0;
    size_t nreloc = 0;

    const uint32_t ncmds = hdr->ncmds;
    const uint32_t sizeofcmds = hdr->sizeofcmds;
    const mach_lc_t * const firstcmd = (const mach_lc_t*)(hdr + 1);
    // Block for variable scoping
    {
        const mach_lc_t *cmd = firstcmd;
        for(uint32_t i = 0; i < ncmds; ++i)
        {
            size_t max = sizeofcmds - ((uintptr_t)cmd - (uintptr_t)firstcmd);
            uint32_t cmdsize;
            if(sizeof(mach_lc_t) > max || (cmdsize = cmd->cmdsize) > max)
            {
                ERR("Mach-O load command %u out of bounds.", i);
                goto out;
            }
            if(cmdsize < sizeof(mach_lc_t))
            {
                ERR("Mach-O load command %u too short.", i);
                goto out;
            }
            switch(cmd->cmd)
            {
                case LC_SYMTAB:
                    if(cmdsize < sizeof(mach_stab_t))
                    {
                        ERR("LC_SYMTAB command too short.");
                        goto out;
                    }
                    if(filetype == MH_FILESET)
                    {
                        ERR("LC_SYMTAB command in MH_FILESET Mach-O.");
                        goto out;
                    }
                    if(stab)
                    {
                        ERR("Multiple LC_SYMTAB commands.");
                        goto out;
                    }
                    stab = (const mach_stab_t*)cmd;
                    if(stab->symoff > size || stab->nsyms * sizeof(mach_nlist_t) > size - stab->symoff || stab->stroff >= size || stab->strsize > size - stab->stroff)
                    {
                        ERR("Mach-O symtab out of bounds.");
                        goto out;
                    }
                    if(stab->strsize > 0 && ((const char*)hdr)[stab->stroff + stab->strsize - 1] != '\0')
                    {
                        ERR("Mach-O strtab is missing null terminator.");
                        goto out;
                    }
                    const mach_nlist_t *symtab = (const mach_nlist_t*)((uintptr_t)hdr + stab->symoff);
                    for(size_t j = 0; j < stab->nsyms; ++j)
                    {
                        if(symtab[j].n_strx >= stab->strsize)
                        {
                            ERR("Mach-O symbol out of bounds.");
                            goto out;
                        }
                        if(macho_skip_symbol(&symtab[j]))
                        {
                            continue;
                        }
                        ++nsyms;
                    }
                    break;

                case LC_DYSYMTAB:
                    if(cmdsize < sizeof(mach_dstab_t))
                    {
                        ERR("LC_DYSYMTAB command too short.");
                        goto out;
                    }
                    if(filetype == MH_FILESET)
                    {
                        ERR("LC_DYSYMTAB command in MH_FILESET Mach-O.");
                        goto out;
                    }
                    if(dstab)
                    {
                        ERR("Multiple LC_DYSYMTAB commands.");
                        goto out;
                    }
                    dstab = (const mach_dstab_t*)cmd;
                    if(dstab->extreloff > size || dstab->nextrel * sizeof(mach_reloc_t) > size - dstab->extreloff || dstab->locreloff > size || dstab->nlocrel * sizeof(mach_reloc_t) > size - dstab->locreloff)
                    {
                        ERR("Mach-O dsymtab out of bounds.");
                        goto out;
                    }
                    nreloc = dstab->nextrel;
                    break;

                case LC_SEGMENT_64:
                    if(cmdsize < sizeof(mach_seg_t))
                    {
                        ERR("LC_SEGMENT_64 command (%u) too short.", i);
                        goto out;
                    }
                    const mach_seg_t *seg = (const mach_seg_t*)cmd;
                    if(!seg->vmsize) // Skip segments that aren't mapped
                    {
                        break;
                    }
                    if(seg->fileoff > size)
                    {
                        ERR("LC_SEGMENT_64 (%u) starts out of bounds.", i);
                        goto out;
                    }
                    if(seg->filesize > size - seg->fileoff)
                    {
                        ERR("LC_SEGMENT_64 (%u) ends out of bounds.", i);
                        goto out;
                    }
                    if(seg->vmsize < seg->filesize)
                    {
                        ERR("LC_SEGMENT_64 (%u) maps less than filesize.", i);
                        goto out;
                    }
                    if(seg->initprot & ~VM_PROT_ALL)
                    {
                        ERR("LC_SEGMENT_64 (%u) has invalid permissions.", i);
                        goto out;
                    }
                    if(seg->nsects * sizeof(mach_sec_t) < cmdsize - sizeof(mach_seg_t))
                    {
                        ERR("LC_SEGMENT_64 command (%u) too short for its sections.", i);
                        goto out;
                    }
                    const mach_sec_t *sec = (const mach_sec_t*)(seg + 1);
                    for(uint32_t j = 0; j < seg->nsects; ++j)
                    {
                        // Skip zerofill
                        if((sec[j].flags & SECTION_TYPE) == S_ZEROFILL)
                        {
                            continue;
                        }
                        if(sec[j].addr - seg->vmaddr != sec[j].offset - seg->fileoff)
                        {
                            ERR("Section (%u/%u) has mismatching address/offset.", i, j);
                            goto out;
                        }
                        if(sec[j].offset < seg->fileoff || sec[j].size > seg->fileoff + seg->filesize - sec[j].offset)
                        {
                            ERR("Section (%u/%u) overflows its segment.", i, j);
                            goto out;
                        }
                        if(memcmp(seg->segname, sec[j].segname, 16) != 0)
                        {
                            ERR("Section name doesn't match segment name (%.16s vs %.16s).", seg->segname, sec[j].segname);
                            goto out;
                        }
                        ++nsecs;
                        if(sec[j].size > 0 && strcmp(sec[j].segname, "__TEXT") == 0 && strcmp(sec[j].sectname, "__thread_starts") == 0)
                        {
                            if(fixupKind != DYLD_CHAINED_PTR_NONE)
                            {
                                ERR("Mach-O has multiple fixup types.");
                                goto out;
                            }
                            fixupKind = DYLD_CHAINED_PTR_ARM64E_FIRMWARE;
                            if(sec[j].size % sizeof(uint32_t) != 0)
                            {
                                ERR("Mach-O chained fixup section has bad size: 0x%llx", sec[j].size);
                                goto out;
                            }
                            uint32_t stride = ((const thread_starts_t*)((uintptr_t)hdr + sec[j].offset))->stride;
                            if(stride != 0)
                            {
                                ERR("Mach-O chained fixup has bad stride: 0x%x", stride);
                                goto out;
                            }
                            thread_starts = &sec[j];
                        }
                    }
                    if(seg->filesize > 0)
                    {
                        if(seg->fileoff == 0)
                        {
                            if(have_base)
                            {
                                ERR("Mach-O has multiple segments mapping offset 0.");
                                goto out;
                            }
                            base = seg->vmaddr;
                            have_base = true;
                        }
                        if(strcmp(seg->segname, "__PRELINK_TEXT") == 0)
                        {
                            if(have_plk_base)
                            {
                                ERR("Mach-O has multiple __PRELINK_TEXT segments.");
                                goto out;
                            }
                            plk_base = seg->vmaddr;
                            have_plk_base = true;
                        }
                        ++nsegs;
                        ++nmaps;
                    }
                    // Account for zerofill portion
                    if(seg->vmsize > seg->filesize)
                    {
                        ++nmaps;
                    }
                    break;

                // TODO: LC_SEGMENT_SPLIT_INFO?

                case LC_DYLD_CHAINED_FIXUPS:
                    if(fixupKind != DYLD_CHAINED_PTR_NONE)
                    {
                        ERR("Mach-O has multiple fixup types.");
                        goto out;
                    }
                    if(cmdsize < sizeof(struct linkedit_data_command))
                    {
                        ERR("LC_DYLD_CHAINED_FIXUPS command too short.");
                        goto out;
                    }
                    const struct linkedit_data_command *data = (const struct linkedit_data_command*)cmd;
                    if(data->datasize < sizeof(fixup_hdr_t))
                    {
                        ERR("Mach-O chained fixup data too small to hold fixup chain header.");
                        goto out;
                    }
                    if(data->dataoff > size || data->datasize > size - data->dataoff)
                    {
                        ERR("Mach-O chained fixup data out of bounds.");
                        goto out;
                    }
                    const fixup_hdr_t *fixup = (const fixup_hdr_t*)((uintptr_t)hdr + data->dataoff);
                    if(fixup->fixups_version != 0)
                    {
                        ERR("Unsupported chained fixup version: %u", fixup->fixups_version);
                        goto out;
                    }
                    if(fixup->imports_count)
                    {
                        if(fixup->imports_count > 0xffff)
                        {
                            ERR("More imports that the pointer format can handle: 0x%x", fixup->imports_count);
                            goto out;
                        }
                        if(fixup->imports_format != 0x1 || fixup->symbols_format != 0x0)
                        {
                            ERR("Unsupported chained imports or symbols format: 0x%x/0x%x", fixup->imports_format, fixup->symbols_format);
                            goto out;
                        }
                        if(fixup->imports_offset > data->datasize || fixup->imports_count * sizeof(fixup_import_t) > data->datasize - fixup->imports_offset)
                        {
                            ERR("Mach-O chained imports out of bounds.");
                            goto out;
                        }
                        if(fixup->symbols_offset >= data->datasize)
                        {
                            ERR("Mach-O import symbols out of bounds.");
                            goto out;
                        }
                        const fixup_import_t *import = (const fixup_import_t*)((uintptr_t)fixup + fixup->imports_offset);
                        uint32_t max_name_offset = data->datasize - fixup->symbols_offset;
                        for(uint32_t j = 0; j < fixup->imports_count; ++j)
                        {
                            const fixup_import_t *imp = import + j;
                            if(imp->lib_ordinal != 0xfe)
                            {
                                ERR("Unsupported chained import ordinal: 0x%x (import %u)", imp->lib_ordinal, j);
                                goto out;
                            }
                            if(imp->name_offset >= max_name_offset)
                            {
                                ERR("Mach-O chained import out of bounds: 0x%x (import %u)", imp->name_offset, j);
                                goto out;
                            }
                        }
                    }
                    uint32_t max_seg_off;
                    if(fixup->starts_offset > data->datasize || (max_seg_off = data->datasize - fixup->starts_offset) < sizeof(fixup_seg_t))
                    {
                        ERR("Mach-O chained fixup segments out of bounds.");
                        goto out;
                    }
                    const fixup_seg_t *segs = (const fixup_seg_t*)((uintptr_t)fixup + fixup->starts_offset);
                    if((uintptr_t)&segs->seg_info_offset[segs->seg_count] - (uintptr_t)segs > max_seg_off)
                    {
                        ERR("Mach-O chained fixup segments out of bounds.");
                        goto out;
                    }
                    uint32_t fixup_page_size = 0;
                    for(uint32_t j = 0; j < segs->seg_count; ++j)
                    {
                        if(segs->seg_info_offset[j] == 0)
                        {
                            continue;
                        }
                        uint32_t max_start_off;
                        if(segs->seg_info_offset[j] > max_seg_off || (max_start_off = max_seg_off - segs->seg_info_offset[j]) < sizeof(fixup_starts_t))
                        {
                            ERR("Mach-O chained fixup starts out of bounds (%u).", j);
                            goto out;
                        }
                        const fixup_starts_t *starts = (const fixup_starts_t*)((uintptr_t)segs + segs->seg_info_offset[j]);
                        if(starts->size > max_start_off || starts->size < __builtin_offsetof(fixup_starts_t, page_start) + starts->page_count * sizeof(uint16_t))
                        {
                            ERR("Mach-O chained fixup starts has bad size (%u).", j);
                            goto out;
                        }
                        if(starts->page_size != 0x1000 && starts->page_size != 0x4000)
                        {
                            ERR("Mach-O chained fixup starts has bad page size: 0x%x (%u)", starts->page_size, j);
                            goto out;
                        }
                        if(fixup_page_size == 0)
                        {
                            fixup_page_size = starts->page_size;
                        }
                        else if(fixup_page_size != starts->page_size)
                        {
                            ERR("Mach-O has multiple fixup page sizes.");
                            goto out;
                        }
                        if(starts->pointer_format != DYLD_CHAINED_PTR_ARM64E_KERNEL && starts->pointer_format != DYLD_CHAINED_PTR_64_KERNEL_CACHE)
                        {
                            ERR("Unsupported chained fixup pointer format: 0x%x (%u)", starts->pointer_format, j);
                            goto out;
                        }
                        if(fixupKind == DYLD_CHAINED_PTR_NONE)
                        {
                            fixupKind = starts->pointer_format;
                        }
                        else if(fixupKind != starts->pointer_format)
                        {
                            ERR("Mach-O has multiple fixup types.");
                            goto out;
                        }
                        if(starts->max_valid_pointer != 0)
                        {
                            ERR("Mach-O chained fixup starts has bad max_valid_pointer: 0x%x (%u)", starts->max_valid_pointer, j);
                            goto out;
                        }
                    }
                    chained_fixups = fixup;
                    break;

                case LC_FILESET_ENTRY:
                    if(cmdsize < sizeof(mach_fileent_t))
                    {
                        ERR("LC_FILESET_ENTRY command (%u) too short.", i);
                        goto out;
                    }
                    if(filetype != MH_FILESET)
                    {
                        ERR("LC_FILESET_ENTRY command (%u) in non-MH_FILESET Mach-O.", i);
                        goto out;
                    }
                    const mach_fileent_t *ent = (const mach_fileent_t*)cmd;
                    if(ent->fileoff > size || size - ent->fileoff < sizeof(mach_hdr_t) || ent->nameoff >= ent->cmdsize)
                    {
                        ERR("LC_FILESET_ENTRY command (%u) out of bounds.", i);
                        goto out;
                    }
                    if(((const char*)ent)[ent->cmdsize - 1] != '\0')
                    {
                        ERR("LC_FILESET_ENTRY (%u) name is missing null terminator.", i);
                        goto out;
                    }
                    size_t sz = size - ent->fileoff;
                    const char *name = (const char*)((uintptr_t)ent + ent->nameoff);
                    mach_hdr_t *mh = (void*)((uintptr_t)hdr + ent->fileoff);
                    DBG(2, "Processing embedded header of %s", name);
                    if(mh->magic != MH_MAGIC_64)
                    {
                        ERR("Embedded Mach-O header has wrong magic: 0x%08x (%s)", mh->magic, name);
                        goto out;
                    }
                    if(mh->cputype != hdr->cputype || (mh->cpusubtype & CPU_SUBTYPE_MASK) != subtype)
                    {
                        ERR("Embedded Mach-O has mismatching cputype or cpusubtype (%s).", name);
                        goto out;
                    }
                    if(!(mh->flags & MH_DYLIB_IN_CACHE))
                    {
                        ERR("Embedded Mach-O is missing embedded flag (%s).", name);
                        goto out;
                    }
                    if(mh->filetype != MH_EXECUTE && mh->filetype != MH_KEXT_BUNDLE)
                    {
                        ERR("Embedded Mach-O has bad type: 0x%x", mh->filetype);
                        goto out;
                    }
                    if(mh->sizeofcmds > sz - sizeof(mach_hdr_t))
                    {
                        ERR("Embedded Mach-O load commands out of bounds (%s).", name);
                        goto out;
                    }
                    const mach_stab_t *st = NULL;
                    const mach_dstab_t *dst = NULL;
                    const mach_lc_t * const firstlc = (const mach_lc_t*)(mh + 1);
                    const mach_lc_t *lc = firstlc;
                    for(uint32_t j = 0, num = mh->ncmds; j < num; ++j)
                    {
                        size_t lcmax = mh->sizeofcmds - ((uintptr_t)lc - (uintptr_t)firstlc);
                        uint32_t lcsize;
                        if(sizeof(mach_lc_t) > lcmax || (lcsize = lc->cmdsize) > lcmax)
                        {
                            ERR("Embedded Mach-O load command %u out of bounds (%s).", j, name);
                            goto out;
                        }
                        if(lcsize < sizeof(mach_lc_t))
                        {
                            ERR("Embedded Mach-O load command %u too short (%s).", j, name);
                            goto out;
                        }
                        switch(lc->cmd)
                        {
                            case LC_SYMTAB:
                                if(lcsize < sizeof(mach_stab_t))
                                {
                                    ERR("Embedded LC_SYMTAB command too short (%s).", name);
                                    goto out;
                                }
                                if(st)
                                {
                                    ERR("Multiple embedded LC_SYMTAB commands (%s).", name);
                                    goto out;
                                }
                                st = (const mach_stab_t*)lc;
                                if(st->symoff > size || st->nsyms * sizeof(mach_nlist_t) > size - st->symoff || st->stroff >= size || st->strsize > size - st->stroff)
                                {
                                    ERR("Embedded Mach-O symtab out of bounds (%s).", name);
                                    goto out;
                                }
                                if(st->strsize > 0 && ((const char*)hdr)[st->stroff + st->strsize - 1] != '\0')
                                {
                                    ERR("Embedded Mach-O strtab is missing null terminator (%s).", name);
                                    goto out;
                                }
                                const mach_nlist_t *symtab = (const mach_nlist_t*)((uintptr_t)hdr + st->symoff);
                                for(size_t k = 0; k < st->nsyms; ++k)
                                {
                                    if(symtab[k].n_strx >= st->strsize)
                                    {
                                        ERR("Embedded Mach-O symbol out of bounds (%s).", name);
                                        goto out;
                                    }
                                    if(macho_skip_symbol(&symtab[k]))
                                    {
                                        continue;
                                    }
                                    ++nsyms;
                                }
                                break;

                            case LC_DYSYMTAB:
                                if(lcsize < sizeof(mach_dstab_t))
                                {
                                    ERR("Embedded LC_DYSYMTAB command too short (%s).", name);
                                    goto out;
                                }
                                if(dst)
                                {
                                    ERR("Multiple embedded LC_DYSYMTAB commands (%s).", name);
                                    goto out;
                                }
                                dst = (const mach_dstab_t*)lc;
                                if(dst->nextrel)
                                {
                                    ERR("Embedded Mach-O has external relocs (%s).", name);
                                    goto out;
                                }
                                if(dst->nlocrel)
                                {
                                    ERR("Embedded Mach-O has local relocs (%s).", name);
                                    goto out;
                                }
                                break;

                            default:
                                if(lc->cmd & LC_REQ_DYLD)
                                {
                                    ERR("Unknown load command %u marked as required in embedded Mach-O (%s).", j, name);
                                    goto out;
                                }
                                break;
                        }
                        lc = (const mach_lc_t*)((uintptr_t)lc + lc->cmdsize);
                    }
                    if(((uintptr_t)lc - (uintptr_t)firstlc) != mh->sizeofcmds)
                    {
                        ERR("Embedded Mach-O load commands don't match sizeofcmds.");
                        goto out;
                    }
                    break;

                default:
                    if(cmd->cmd & LC_REQ_DYLD)
                    {
                        ERR("Unknown load command %u marked as required.", i);
                        goto out;
                    }
                    break;
            }
            cmd = (const mach_lc_t*)((uintptr_t)cmd + cmd->cmdsize);
        }
        if(((uintptr_t)cmd - (uintptr_t)firstcmd) != sizeofcmds)
        {
            ERR("Mach-O load commands don't match sizeofcmds.");
            goto out;
        }
    }
    if(!have_base)
    {
        ERR("Failed to find kernel base.");
        goto out;
    }

    mapV = malloc(sizeof(macho_map_t) * nmaps);
    if(!mapV)
    {
        ERRNO("malloc(mapV)");
        goto out;
    }
    mapP = malloc(sizeof(macho_map_t) * nmaps);
    if(!mapP)
    {
        ERRNO("malloc(mapP)");
        goto out;
    }
    segmentsByName = malloc(sizeof(macho_segment_t) * nsegs);
    if(!segmentsByName)
    {
        ERRNO("malloc(segmentsByName)");
        goto out;
    }
    segmentsByAddr = malloc(sizeof(macho_segment_t) * nsegs);
    if(!segmentsByAddr)
    {
        ERRNO("malloc(segmentsByAddr)");
        goto out;
    }
    sectionsByName = malloc(sizeof(macho_section_t) * nsecs);
    if(!sectionsByName)
    {
        ERRNO("malloc(sectionsByName)");
        goto out;
    }
    sectionsByAddr = malloc(sizeof(macho_section_t) * nsecs);
    if(!sectionsByAddr)
    {
        ERRNO("malloc(sectionsByAddr)");
        goto out;
    }

    // Block for variable scoping
    {
        size_t mapidx = 0;
        size_t segidx = 0;
        size_t secidx = 0;
        const mach_lc_t *cmd = firstcmd;
        for(uint32_t i = 0; i < ncmds; ++i)
        {
            if(cmd->cmd == LC_SEGMENT_64)
            {
                const mach_seg_t *seg = (const mach_seg_t*)cmd;
                if(seg->vmsize) // Only mapped segments
                {
                    const mach_sec_t *sec = (const mach_sec_t*)(seg + 1);
                    for(uint32_t j = 0; j < seg->nsects; ++j)
                    {
                        // Skip zerofill
                        if((sec[j].flags & SECTION_TYPE) == S_ZEROFILL)
                        {
                            continue;
                        }
                        sectionsByName[secidx].addr = sec[j].addr;
                        sectionsByName[secidx].size = sec[j].size;
                        sectionsByName[secidx].mem  = (uintptr_t)hdr + sec[j].offset;
                        sectionsByName[secidx].prot = seg->initprot;
                        memcpy(sectionsByName[secidx].segname, sec[j].segname, 16);
                        memcpy(sectionsByName[secidx].secname, sec[j].sectname, 16);
                        sectionsByName[secidx].segname[16] = '\0';
                        sectionsByName[secidx].secname[16] = '\0';
                        ++secidx;
                    }
                    if(seg->filesize > 0)
                    {
                        segmentsByName[segidx].addr = seg->vmaddr;
                        segmentsByName[segidx].size = seg->filesize;
                        segmentsByName[segidx].mem  = (uintptr_t)hdr + seg->fileoff;
                        segmentsByName[segidx].prot = seg->initprot;
                        memcpy(segmentsByName[segidx].segname, seg->segname, 16);
                        segmentsByName[segidx].segname[16] = '\0';
                        ++segidx;
                        mapV[mapidx].addr = seg->vmaddr;
                        mapV[mapidx].size = seg->filesize;
                        mapV[mapidx].mem  = (uintptr_t)hdr + seg->fileoff;
                        mapV[mapidx].prot = seg->initprot;
                        ++mapidx;
                    }
                    if(seg->vmsize > seg->filesize)
                    {
                        size_t mapsize = seg->vmsize - seg->filesize;
                        void *mapmem = mmap(NULL, mapsize, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0); // TODO: PROT_WRITE ?
                        if(mapmem == MAP_FAILED)
                        {
                            ERRNO("mmap(mapmem)");
                            goto out;
                        }
                        mapV[mapidx].addr = seg->vmaddr + seg->filesize;
                        mapV[mapidx].size = mapsize;
                        mapV[mapidx].mem  = (uintptr_t)mapmem;
                        mapV[mapidx].prot = seg->initprot;
                        ++mapidx;
                    }
                }
            }
            cmd = (const mach_lc_t*)((uintptr_t)cmd + cmd->cmdsize);
        }
    }

    // TODO: override prelink segment perms for old kernels?

    memcpy(mapP, mapV, sizeof(macho_map_t) * nmaps);
    memcpy(segmentsByAddr, segmentsByName, sizeof(macho_segment_t) * nsegs);
    memcpy(sectionsByAddr, sectionsByName, sizeof(macho_section_t) * nsecs);

    qsort(mapV, nmaps, sizeof(macho_map_t), &macho_cmp_map_addr);
    qsort(mapP, nmaps, sizeof(macho_map_t), &macho_cmp_map_ptr);
    qsort(segmentsByName, nsegs, sizeof(macho_segment_t), &macho_cmp_seg_name);
    qsort(segmentsByAddr, nsegs, sizeof(macho_segment_t), &macho_cmp_seg_addr);
    qsort(sectionsByName, nsecs, sizeof(macho_section_t), &macho_cmp_sec_name);
    qsort(sectionsByAddr, nsecs, sizeof(macho_section_t), &macho_cmp_sec_addr);

    bool cursor = false;
    size_t nmapV = 0;
    for(size_t i = 1; i < nmaps; ++i)
    {
        if(mapV[i].addr - mapV[nmapV].addr < mapV[nmapV].size)
        {
            ERR("Overlapping maps: " ADDR " and " ADDR, mapV[nmapV].addr, mapV[i].addr);
            goto out;
        }
        if(mapV[nmapV].addr + mapV[nmapV].size == mapV[i].addr && mapV[nmapV].mem + mapV[nmapV].size == mapV[i].mem && mapV[nmapV].prot == mapV[i].prot)
        {
            mapV[nmapV].size += mapV[i].size;
            cursor = true;
        }
        else if(++nmapV != i)
        {
            memcpy(&mapV[nmapV], &mapV[i], sizeof(macho_map_t));
            cursor = true;
        }
    }
    if(cursor) // Account for "current" map
    {
        ++nmapV;
    }
    cursor = false;
    size_t nmapP = 0;
    for(size_t i = 1; i < nmaps; ++i)
    {
        if(mapP[i].mem - mapP[nmapP].mem < mapP[nmapP].size)
        {
            ERR("Overlapping maps: " ADDR " and " ADDR, mapP[nmapP].addr, mapP[i].addr);
            goto out;
        }
        if(mapP[nmapP].addr + mapP[nmapP].size == mapP[i].addr && mapP[nmapP].mem + mapP[nmapP].size == mapP[i].mem && mapP[nmapP].prot == mapP[i].prot)
        {
            mapP[nmapP].size += mapP[i].size;
            cursor = true;
        }
        else if(++nmapP != i)
        {
            memcpy(&mapP[nmapP], &mapP[i], sizeof(macho_map_t));
            cursor = true;
        }
    }
    if(cursor) // Account for "current" map
    {
        ++nmapP;
    }
    for(size_t i = 0; i < nmapV; ++i)
    {
        DBG(2, "Map " ADDR " 0x%016lx 0x%08zx 0x%x", mapV[i].addr, mapV[i].mem, mapV[i].size, mapV[i].prot);
    }

    if(nsyms)
    {
        symsByName = malloc(sizeof(sym_t) * nsyms);
        if(!symsByName)
        {
            ERRNO("malloc(symsByName)");
            goto out;
        }
        symsByAddr = malloc(sizeof(sym_t) * nsyms);
        if(!symsByAddr)
        {
            ERRNO("malloc(symsByAddr)");
            goto out;
        }

        size_t symidx = 0;
        if(filetype == MH_FILESET)
        {
            const mach_lc_t *cmd = firstcmd;
            for(uint32_t i = 0; i < ncmds; ++i)
            {
                if(cmd->cmd == LC_FILESET_ENTRY)
                {
                    const mach_fileent_t *ent = (const mach_fileent_t*)cmd;
                    mach_hdr_t *mh = (void*)((uintptr_t)hdr + ent->fileoff);
                    const mach_lc_t * const firstlc = (const mach_lc_t*)(mh + 1);
                    const mach_lc_t *lc = firstlc;
                    for(uint32_t j = 0, num = mh->ncmds; j < num; ++j)
                    {
                        if(lc->cmd == LC_SYMTAB)
                        {
                            const mach_stab_t *st = (const mach_stab_t*)lc;
                            const mach_nlist_t *symtab = (const mach_nlist_t*)((uintptr_t)hdr + st->symoff);
                            const char *strtab = (const char*)((uintptr_t)hdr + st->stroff);
                            for(size_t k = 0; k < st->nsyms; ++k)
                            {
                                if(macho_skip_symbol(&symtab[k]))
                                {
                                    continue;
                                }
                                sym_t *sym = &symsByName[symidx++];
                                sym->addr = symtab[k].n_value;
                                sym->name = &strtab[symtab[k].n_strx];
                                DBG(2, "Symbol: " ADDR " %s", sym->addr, sym->name);
                            }
                            break;
                        }
                        lc = (const mach_lc_t*)((uintptr_t)lc + lc->cmdsize);
                    }
                }
                cmd = (const mach_lc_t*)((uintptr_t)cmd + cmd->cmdsize);
            }
        }
        else
        {
            const mach_nlist_t *symtab = (const mach_nlist_t*)((uintptr_t)hdr + stab->symoff);
            const char *strtab = (const char*)((uintptr_t)hdr + stab->stroff);
            for(size_t i = 0; i < stab->nsyms; ++i)
            {
                if(macho_skip_symbol(&symtab[i]))
                {
                    continue;
                }
                sym_t *sym = &symsByName[symidx++];
                sym->addr = symtab[i].n_value;
                sym->name = &strtab[symtab[i].n_strx];
                DBG(2, "Symbol: " ADDR " %s", sym->addr, sym->name);
            }
        }

        memcpy(symsByAddr, symsByName, sizeof(sym_t) * nsyms);
        qsort(symsByName, nsyms, sizeof(sym_t), &macho_cmp_sym_name);
        qsort(symsByAddr, nsyms, sizeof(sym_t), &macho_cmp_sym_addr);
    }

    size_t numbitmap = (size + MACHO_BITMAP_PAGESIZE - 1) / MACHO_BITMAP_PAGESIZE;
    ptrBitmap = malloc(sizeof(uint8_t*) * numbitmap);
    if(!ptrBitmap)
    {
        ERRNO("malloc(ptrBitmap)");
        goto out;
    }
    bzero(ptrBitmap, sizeof(uint8_t*) * numbitmap);

    switch(fixupKind)
    {
        case DYLD_CHAINED_PTR_ARM64E_KERNEL:
        case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
        {
            const fixup_seg_t *segs = (const fixup_seg_t*)((uintptr_t)chained_fixups + chained_fixups->starts_offset);
            for(uint32_t i = 0, max = segs->seg_count; i < max; ++i)
            {
                if(segs->seg_info_offset[i] == 0)
                {
                    continue;
                }
                const fixup_starts_t *starts = (const fixup_starts_t*)((uintptr_t)segs + segs->seg_info_offset[i]);
                kptr_t segbase = base + starts->segment_offset;
                macho_segment_t *seg = bsearch((const void*)segbase, segmentsByAddr, nsegs, sizeof(macho_segment_t), &macho_cmp_seg_addr_key);
                if(!seg)
                {
                    ERR("Mach-O chained fixup segment doesn't map to actual segment (" ADDR ").", segbase);
                    goto out;
                }
                size_t segsize = (size_t)starts->page_count * (size_t)starts->page_size;
                if(segsize > seg->size)
                {
                    ERR("Mach-O chained fixup segment size doesn't match actual segment size (" ADDR ", 0x%zx vs 0x%zx).", segbase, segsize, seg->size);
                    goto out;
                }
                uintptr_t segend = (uintptr_t)seg->mem + seg->size;
                for(uint16_t j = 0, m = starts->page_count; j < m; ++j)
                {
                    uint16_t idx = starts->page_start[j];
                    if(idx == 0xffff)
                    {
                        continue;
                    }
                    size_t off = (size_t)j * (size_t)starts->page_size + (size_t)idx;
                    if(idx > starts->page_size - sizeof(kptr_t))
                    {
                        ERR("Mach-O chained fixup start at 0x%zx overflows pagesize (0x%hx).", off, idx);
                        goto out;
                    }
                    if(idx & 0x3)
                    {
                        ERR("Mach-O chained fixup start at 0x%zx is not aligned to 4 bytes (0x%hx).", off, idx);
                        goto out;
                    }
                    const kptr_t *ptr = (const kptr_t*)(seg->mem + off);
                    uintptr_t end = seg->mem + ((size_t)j + 1) * (size_t)starts->page_size;
                    // macho_validate_fixup_chain() checks that pointers stay fully within the bounds of `end`,
                    // but pointers can start at page offset 0x3ffc and run onto the next page. So as long as
                    // that doesn't happen at the end of a segment, add 4 bytes
                    if(end < segend)
                    {
                        end += sizeof(uint32_t);
                    }
                    if(!macho_validate_fixup_chain(hdr, base, fixupKind, ptr, end, ptrBitmap, &nreloc, chained_fixups->imports_count))
                    {
                        goto out;
                    }
                }
            }
            break;
        }

        case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
        {
            const thread_starts_t *starts = (const thread_starts_t*)((uintptr_t)hdr + thread_starts->offset);
            for(size_t i = 0, max = thread_starts->size / sizeof(uint32_t) - 1; i < max; ++i)
            {
                uint32_t off = starts->starts[i];
                if(off == 0xffffffff)
                {
                    continue;
                }
                if(off & 0x3)
                {
                    ERR("Mach-O chained fixup start at 0x%x is not aligned to 4 bytes.", off);
                    goto out;
                }
                kptr_t addr = base + off;
                const void *secbase = NULL;
                kptr_t secaddr = 0;
                size_t secsize = 0;
                if(!macho_section_for_addr_internal(sectionsByAddr, nsecs, addr, &secbase, &secaddr, &secsize, NULL))
                {
                    ERR("Mach-O chained fixup start doesn't maps to any segment (" ADDR ").", addr);
                    goto out;
                }
                const kptr_t *ptr = (const kptr_t*)(addr - secaddr + (uintptr_t)secbase);
                uintptr_t end = (uintptr_t)secbase + secsize;
                if(!macho_validate_fixup_chain(hdr, base, fixupKind, ptr, end, ptrBitmap, &nreloc, chained_fixups->imports_count))
                {
                    goto out;
                }
            }
            break;
        }

        case DYLD_CHAINED_PTR_NONE:
        {
            size_t count = 0;
            const kaslrPackedOffsets_t *kaslr = NULL;
            if(dstab)
            {
                count += dstab->nlocrel;
            }
            if(filetype == MH_EXECUTE)
            {
                prelinkInfo = macho_prelink_info_internal(sectionsByName, nsecs);
                if(prelinkInfo)
                {
                    if(!have_plk_base)
                    {
                        ERR("Mach-O is missing __PRELINK_TEXT.");
                        goto out;
                    }
                    CFDataRef data = CFDictionaryGetValue(prelinkInfo, CFSTR("_PrelinkLinkKASLROffsets"));
                    if(!data || CFGetTypeID(data) != CFDataGetTypeID())
                    {
                        ERR("PrelinkLinkKASLROffsets missing or wrong type.");
                        goto out;
                    }
                    kaslr = (const kaslrPackedOffsets_t*)CFDataGetBytePtr(data);
                    if(!kaslr)
                    {
                        ERR("Failed to get PrelinkLinkKASLROffsets byte pointer.");
                        goto out;
                    }
                    CFIndex len = CFDataGetLength(data);
                    if(len < sizeof(kaslrPackedOffsets_t) || len != sizeof(kaslrPackedOffsets_t) + kaslr->count * sizeof(uint32_t))
                    {
                        ERR("PrelinkLinkKASLROffsets has bad size.");
                        goto out;
                    }
                    count += kaslr->count;
                }
            }
            DBG(2, "Got %lu local relocations", count);
            if(count > UINT32_MAX)
            {
                ERR("kxld fixup count overflows.");
                goto out;
            }

            kxld = malloc(sizeof(kaslrPackedOffsets_t) + count * sizeof(uint32_t));
            if(!kxld)
            {
                ERRNO("malloc(kxld)");
                goto out;
            }
            kxld->count = (uint32_t)count;

            size_t idx = 0;
            if(dstab)
            {
                mach_reloc_t *reloc = (mach_reloc_t*)((uintptr_t)hdr + dstab->locreloff);
                for(size_t i = 0; i < dstab->nlocrel; ++i)
                {
                    int32_t off = reloc[i].r_address;
                    if(reloc[i].r_extern)
                    {
                        ERR("Local relocation entry %zu at 0x%x has external bit set.", i, off);
                        goto out;
                    }
                    if(reloc[i].r_length != 0x3)
                    {
                        ERR("Local relocation entry %zu at 0x%x is not 8 bytes.", i, off);
                        goto out;
                    }
                    if(off & 0x3)
                    {
                        ERR("Local relocation entry %zu at 0x%x is not aligned to 4 bytes.", i, off);
                        goto out;
                    }
                    kptr_t addr = base + off;
                    DBG(3, "Locreloc %zu: " ADDR, i, addr);
                    const void *ptr = macho_vtop_internal(mapV, nmapV, addr, sizeof(kptr_t));
                    if(!ptr || (uintptr_t)ptr < (uintptr_t)hdr || (uintptr_t)ptr >= (uintptr_t)hdr + size)
                    {
                        ERR("Local relocation entry %zu is outside of all mapped segments: " ADDR, i, addr);
                        goto out;
                    }
                    size_t diff = (uintptr_t)ptr - (uintptr_t)hdr;
                    if(diff > UINT32_MAX)
                    {
                        ERR("Local relocation entry %zu is too far: " ADDR, i, addr);
                        goto out;
                    }
                    if(!macho_bitmap_set(ptrBitmap, diff))
                    {
                        goto out;
                    }
                    kxld->offsetsArray[idx++] = (uint32_t)diff;
                }
            }
            if(kaslr)
            {
                for(size_t i = 0; i < kaslr->count; ++i)
                {
                    uint32_t off = kaslr->offsetsArray[i];
                    if(off & 0x3)
                    {
                        ERR("Prelink relocation entry %zu at 0x%x is not aligned to 4 bytes.", i, off);
                        goto out;
                    }
                    kptr_t addr = plk_base + off;
                    DBG(3, "Prelink reloc %zu: " ADDR, i, addr);
                    const void *ptr = macho_vtop_internal(mapV, nmapV, addr, sizeof(kptr_t));
                    if(!ptr || (uintptr_t)ptr < (uintptr_t)hdr || (uintptr_t)ptr >= (uintptr_t)hdr + size)
                    {
                        ERR("Prelink relocation entry %zu is outside of all mapped segments: " ADDR, i, addr);
                        goto out;
                    }
                    size_t diff = (uintptr_t)ptr - (uintptr_t)hdr;
                    if(diff > UINT32_MAX)
                    {
                        ERR("Prelink relocation entry %zu is too far: " ADDR, i, addr);
                        goto out;
                    }
                    if(!macho_bitmap_set(ptrBitmap, diff))
                    {
                        goto out;
                    }
                    kxld->offsetsArray[idx++] = (uint32_t)diff;
                }
            }
            break;
        }

        default:
            __builtin_trap();
    }

    if(nreloc)
    {
        relocByName = malloc(sizeof(sym_t) * nreloc);
        if(!relocByName)
        {
            ERRNO("malloc(relocByName)");
            goto out;
        }
        relocByAddr = malloc(sizeof(sym_t) * nreloc);
        if(!relocByAddr)
        {
            ERRNO("malloc(relocByAddr)");
            goto out;
        }

        size_t relocidx = 0;
        if(dstab)
        {
            if(!stab)
            {
                ERR("Mach-O has dsymtab but not symtab.");
                goto out;
            }
            mach_reloc_t *reloc = (mach_reloc_t*)((uintptr_t)hdr + dstab->extreloff);
            const mach_nlist_t *symtab = (const mach_nlist_t*)((uintptr_t)hdr + stab->symoff);
            const char *strtab = (const char*)((uintptr_t)hdr + stab->stroff);
            for(size_t i = 0; i < dstab->nextrel; ++i)
            {
                int32_t off = reloc[i].r_address;
                if(!reloc[i].r_extern)
                {
                    ERR("External relocation entry %zu at 0x%x has external bit set.", i, off);
                    goto out;
                }
                if(reloc[i].r_length != 0x3)
                {
                    ERR("External relocation entry %zu at 0x%x is not 8 bytes.", i, off);
                    goto out;
                }
                if(off & 0x3)
                {
                    ERR("External relocation entry %zu at 0x%x is not aligned to 4 bytes.", i, off);
                    goto out;
                }
                uint32_t symnum = reloc[i].r_symbolnum;
                if(symnum >= stab->nsyms)
                {
                    ERR("External relocation entry %zu is out of bounds of symtab.", i);
                    goto out;
                }
                kptr_t addr = base + off;
                const char *name = &strtab[symtab[symnum].n_strx];
                DBG(3, "Exreloc: " ADDR " %s", addr, name);
                const void *ptr = macho_vtop_internal(mapV, nmapV, addr, sizeof(kptr_t));
                if(!ptr || (uintptr_t)ptr < (uintptr_t)hdr || (uintptr_t)ptr >= (uintptr_t)hdr + size)
                {
                    ERR("External relocation entry %zu is outside of all mapped segments: " ADDR, i, addr);
                    goto out;
                }
                size_t diff = (uintptr_t)ptr - (uintptr_t)hdr;
                if(diff > UINT32_MAX)
                {
                    ERR("External relocation entry %zu is too far: " ADDR, i, addr);
                    goto out;
                }
                if(!macho_bitmap_set(ptrBitmap, diff))
                {
                    goto out;
                }
                sym_t *sym = &relocByName[relocidx++];
                sym->addr = addr;
                sym->name = name;
            }
        }
        if(chained_fixups && chained_fixups->imports_count)
        {
            chained_imports_cb_t arg =
            {
                .fixupKind = fixupKind,
                .base = base,
                .mapP = mapP,
                .nmapP = nmapP,
                .import = (const fixup_import_t*)((uintptr_t)chained_fixups + chained_fixups->imports_offset),
                .syms = (const char*)((uintptr_t)chained_fixups + chained_fixups->symbols_offset),
                .relocByName = relocByName,
                .relocidx = relocidx,
            };
            if(!macho_foreach_ptr_internal((uintptr_t)hdr, fixupKind, (union fixup_data){ .chain = (const fixup_seg_t*)((uintptr_t)chained_fixups + chained_fixups->starts_offset) }, base, mapV, nmapV, &macho_chained_imports_cb, &arg))
            {
                goto out;
            }
        }

        memcpy(relocByAddr, relocByName, sizeof(sym_t) * nreloc);
        qsort(relocByName, nreloc, sizeof(sym_t), &macho_cmp_sym_name);
        qsort(relocByAddr, nreloc, sizeof(sym_t), &macho_cmp_sym_addr);
    }

    macho = malloc(sizeof(macho_t));
    if(!macho)
    {
        ERRNO("malloc(macho)");
        goto out;
    }

    macho->fd = fd;
    macho->filetype = filetype;
    macho->subtype = subtype;
    macho->fixupKind = fixupKind;
    switch(fixupKind)
    {
        case DYLD_CHAINED_PTR_ARM64E_KERNEL:
        case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
            macho->fixup.chain = (const fixup_seg_t*)((uintptr_t)chained_fixups + chained_fixups->starts_offset);
            break;

        case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
            macho->fixup.thread = thread_starts;
            break;

        case DYLD_CHAINED_PTR_NONE:
            macho->fixup.kxld = kxld;
            break;

        default:
            __builtin_trap();
    }
    macho->mem = mem;
    macho->memsize = memsize;
    macho->hdr = hdr;
    macho->size = size;
    macho->base = base;
    macho->mapV = mapV;
    macho->nmapV = nmapV;
    macho->mapP = mapP;
    macho->nmapP = nmapP;
    macho->segmentsByName = segmentsByName;
    macho->segmentsByAddr = segmentsByAddr;
    macho->nsegs = nsegs;
    macho->sectionsByName = sectionsByName;
    macho->sectionsByAddr = sectionsByAddr;
    macho->nsecs = nsecs;
    macho->symsByName = symsByName;
    macho->symsByAddr = symsByAddr;
    macho->nsyms = nsyms;
    macho->relocByName = relocByName;
    macho->relocByAddr = relocByAddr;
    macho->nreloc = nreloc;
    macho->prelinkInfo = prelinkInfo;
    macho->ptrBitmap = ptrBitmap;

    // Prevent freeing
    fd = -1;
    mem = MAP_FAILED;
    memsize = 0;
    mapV = NULL;
    mapP = NULL;
    segmentsByName = NULL;
    segmentsByAddr = NULL;
    sectionsByName = NULL;
    sectionsByAddr = NULL;
    symsByName = NULL;
    symsByAddr = NULL;
    relocByName = NULL;
    relocByAddr = NULL;
    kxld = NULL;
    prelinkInfo = NULL;
    ptrBitmap = NULL;

out:;
    if(ptrBitmap) free(ptrBitmap);
    if(prelinkInfo) CFRelease(prelinkInfo);
    if(kxld) free(kxld);
    if(symsByName) free(symsByName);
    if(symsByAddr) free(symsByAddr);
    if(relocByName) free(relocByName);
    if(relocByAddr) free(relocByAddr);
    // TODO: mapmem
    if(mapV) free(mapV);
    if(mapP) free(mapP);
    if(segmentsByName) free(segmentsByName);
    if(segmentsByAddr) free(segmentsByAddr);
    if(sectionsByName) free(sectionsByName);
    if(sectionsByAddr) free(sectionsByAddr);
    if(mem != MAP_FAILED)
    {
        munmap((void*)mem, memsize);
    }
    if(fd != -1)
    {
        close(fd);
    }
    return macho;
}

void macho_close(macho_t *macho)
{
    if(macho->ptrBitmap)
    {
        for(size_t i = 0, max = (macho->size + MACHO_BITMAP_PAGESIZE - 1) / MACHO_BITMAP_PAGESIZE; i < max; ++i)
        {
            if(macho->ptrBitmap[i])
            {
                free(macho->ptrBitmap[i]);
            }
        }
        free(macho->ptrBitmap);
    }
    if(macho->prelinkInfo) CFRelease(macho->prelinkInfo);
    if(macho->fixupKind == DYLD_CHAINED_PTR_NONE && macho->fixup.kxld) free(macho->fixup.kxld);
    if(macho->symsByName) free(macho->symsByName);
    if(macho->symsByAddr) free(macho->symsByAddr);
    if(macho->relocByName) free(macho->relocByName);
    if(macho->relocByAddr) free(macho->relocByAddr);
    // TODO: mapmem
    if(macho->mapV) free(macho->mapV);
    if(macho->mapP) free(macho->mapP);
    if(macho->segmentsByName) free(macho->segmentsByName);
    if(macho->segmentsByAddr) free(macho->segmentsByAddr);
    if(macho->sectionsByName) free(macho->sectionsByName);
    if(macho->sectionsByAddr) free(macho->sectionsByAddr);
    if(macho->mem != MAP_FAILED)
    {
        munmap((void*)macho->mem, macho->memsize);
    }
    if(macho->fd != -1)
    {
        close(macho->fd);
    }
    free(macho);
}

bool macho_is_kext(macho_t *macho)
{
    return macho->filetype == MH_KEXT_BUNDLE;
}

bool macho_has_pac(macho_t *macho)
{
    return macho->subtype == CPU_SUBTYPE_ARM64E;
}

bool macho_is_ptr(macho_t *macho, const void *loc)
{
    if((uintptr_t)loc < (uintptr_t)macho->hdr || (uintptr_t)loc >= (uintptr_t)macho->hdr + macho->size)
    {
        return false;
    }
    size_t off = (uintptr_t)loc - (uintptr_t)macho->hdr;
    if(off & 0x3) // Must at least be 4-byte aligned
    {
        return false;
    }
    uint8_t *bitmap = macho->ptrBitmap[MACHO_BITMAP_PAGE(off)];
    if(!bitmap)
    {
        return false;
    }
    return !!((bitmap[MACHO_BITMAP_IDX(off)] >> MACHO_BITMAP_BIT(off)) & 0x1);
}

static kptr_t macho_fixup_internal(fixup_kind_t fixupKind, kptr_t base, kptr_t ptr, bool *bind, bool *auth, uint16_t *pac, size_t *skip)
{
    pacptr_t pp;
    pp.ptr = ptr;
    switch(fixupKind)
    {
        case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
            if(pp.cache.cache != 0)
            {
                ERR("Cannot resolve pointer in cache %u: " ADDR, pp.cache.cache, ptr);
                exit(-1);
            }
            if(bind) *bind = false;
            if(auth) *auth = !!(pp.cache.auth && pp.cache.tag);
            if(pac)  *pac  = pp.cache.div;
            if(skip) *skip = pp.cache.next * sizeof(uint32_t);
            return base + pp.cache.target;

        case DYLD_CHAINED_PTR_ARM64E_KERNEL:
        case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
            if(pp.pac.bind)
            {
                if(!bind)
                {
                    ERR("Cannot bind pointer " ADDR, ptr);
                    exit(-1);
                }
                *bind = true;
            }
            else if(bind)
            {
                *bind = false;
            }
            if(skip) *skip = pp.pac.next * sizeof(uint32_t);
            if(pp.pac.auth)
            {
                if(auth) *auth = !!pp.pac.tag;
                if(pac)  *pac  = pp.pac.div;
            }
            else
            {
                if(auth) *auth = false;
                if(pac)  *pac  = 0;
            }
            if(pp.pac.bind) return pp.pac.off & 0xffff;
            if(pp.pac.auth) return base + pp.pac.off;
            return (kptr_t)pp.raw.lo + (fixupKind == DYLD_CHAINED_PTR_ARM64E_FIRMWARE ? 0 : base);

        default:
            if(bind) *bind = false;
            if(auth) *auth = false;
            if(pac)  *pac  = 0;
            if(skip) *skip = 0;
            return pp.ptr;
    }
}

kptr_t macho_fixup(macho_t *macho, kptr_t ptr, bool *bind, bool *auth, uint16_t *pac, size_t *skip)
{
    return macho_fixup_internal(macho->fixupKind, macho->base, ptr, bind, auth, pac, skip);
}

kptr_t macho_base(macho_t *macho)
{
    return macho->base;
}

static int macho_ptov_cb(const void *key, const void *value)
{
    const macho_map_t *map = value;
    uintptr_t ptr = (uintptr_t)key;
    if(ptr < map->mem)
    {
        return -1;
    }
    if(ptr >= map->mem + map->size)
    {
        return 1;
    }
    return 0;
}

static kptr_t macho_ptov_internal(const macho_map_t *mapP, size_t nmapP, const void *ptr)
{
    const macho_map_t *map = bsearch(ptr, mapP, nmapP, sizeof(macho_map_t), &macho_ptov_cb);
    return !map ? 0 : (uintptr_t)ptr - map->mem + map->addr;
}

kptr_t macho_ptov(macho_t *macho, const void *ptr)
{
    return macho_ptov_internal(macho->mapP, macho->nmapP, ptr);
}

static int macho_vtop_cb(const void *key, const void *value)
{
    const macho_map_t *map = value;
    kptr_t addr = (kptr_t)key;
    if(addr < map->addr)
    {
        return -1;
    }
    if(addr >= map->addr + map->size)
    {
        return 1;
    }
    return 0;
}

static const void* macho_vtop_internal(const macho_map_t *mapV, size_t nmapV, kptr_t addr, size_t size)
{
    const macho_map_t *map = bsearch((const void*)addr, mapV, nmapV, sizeof(macho_map_t), &macho_vtop_cb);
    if(!map)
    {
        return NULL;
    }
    if(size && size >= (map->addr + map->size - addr))
    {
        return NULL;
    }
    return (const void*)((uintptr_t)addr - map->addr + map->mem);
}

const void* macho_vtop(macho_t *macho, kptr_t addr, size_t size)
{
    return macho_vtop_internal(macho->mapV, macho->nmapV, addr, size);
}

void* macho_vtop_rw(macho_t *macho, kptr_t addr, size_t size)
{
    // TODO
    WRN("macho_vtop_rw() not implemented yet!");
    return NULL;
}

static int macho_segment_cb(const void *key, const void *value)
{
    return strcmp(key, ((macho_segment_t*)value)->segname);
}

bool macho_segment(macho_t *macho, const char *segment, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot)
{
    macho_segment_t *seg = bsearch(segment, macho->segmentsByName, macho->nsegs, sizeof(macho_segment_t), &macho_segment_cb);
    if(!seg)
    {
        return false;
    }
    if(ptr)  *ptr  = (const void*)seg->mem;
    if(addr) *addr = seg->addr;
    if(size) *size = seg->size;
    if(prot) *prot = seg->prot;
    return true;
}

typedef struct
{
    const char *segment;
    const char *section;
} macho_section_cb_t;

static int macho_section_cb(const void *key, const void *value)
{
    const macho_section_cb_t *arg = key;
    const macho_section_t *sec = value;
    int cmp = strcmp(arg->segment, sec->segname);
    if(cmp != 0)
    {
        return cmp;
    }
    return strcmp(arg->section, sec->secname);
}

static bool macho_section_internal(const macho_section_t *sectionsByName, size_t nsecs, const char *segment, const char *section, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot)
{
    macho_section_cb_t arg =
    {
        .segment = segment,
        .section = section,
    };
    macho_section_t *sec = bsearch(&arg, sectionsByName, nsecs, sizeof(macho_section_t), &macho_section_cb);
    if(!sec)
    {
        return false;
    }
    if(ptr)  *ptr  = (const void*)sec->mem;
    if(addr) *addr = sec->addr;
    if(size) *size = sec->size;
    if(prot) *prot = sec->prot;
    return true;
}

bool macho_section(macho_t *macho, const char *segment, const char *section, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot)
{
    return macho_section_internal(macho->sectionsByName, macho->nsecs, segment, section, ptr, addr, size, prot);
}

static int macho_segment_for_addr_cb(const void *key, const void *value)
{
    const macho_segment_t *seg = value;
    if((kptr_t)key < seg->addr)
    {
        return -1;
    }
    if((kptr_t)key - seg->addr >= seg->size)
    {
        return 1;
    }
    return 0;
}

bool macho_segment_for_addr(macho_t *macho, kptr_t target, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot)
{
    macho_segment_t *seg = bsearch((const void*)target, macho->segmentsByAddr, macho->nsegs, sizeof(macho_segment_t), &macho_segment_for_addr_cb);
    if(!seg)
    {
        return false;
    }
    if(ptr)  *ptr  = (const void*)seg->mem;
    if(addr) *addr = seg->addr;
    if(size) *size = seg->size;
    if(prot) *prot = seg->prot;
    return true;
}

static int macho_section_for_addr_cb(const void *key, const void *value)
{
    const macho_section_t *sec = value;
    if((kptr_t)key < sec->addr)
    {
        return -1;
    }
    if((kptr_t)key - sec->addr >= sec->size)
    {
        return 1;
    }
    return 0;
}

static bool macho_section_for_addr_internal(const macho_section_t *sectionsByAddr, size_t nsecs, kptr_t target, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot)
{
    macho_section_t *sec = bsearch((const void*)target, sectionsByAddr, nsecs, sizeof(macho_section_t), &macho_section_for_addr_cb);
    if(!sec)
    {
        return false;
    }
    if(ptr)  *ptr  = (const void*)sec->mem;
    if(addr) *addr = sec->addr;
    if(size) *size = sec->size;
    if(prot) *prot = sec->prot;
    return true;
}

bool macho_section_for_addr(macho_t *macho, kptr_t target, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot)
{
    return macho_section_for_addr_internal(macho->sectionsByAddr, macho->nsecs, target, ptr, addr, size, prot);
}

bool macho_segment_for_ptr(macho_t *macho, const void *target, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot)
{
    return macho_segment_for_addr(macho, macho_ptov(macho, target), ptr, addr, size, prot);
}

bool macho_section_for_ptr(macho_t *macho, const void *target, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot)
{
    return macho_section_for_addr(macho, macho_ptov(macho, target), ptr, addr, size, prot);
}

bool macho_foreach_map(macho_t *macho, bool (*cb)(const void *ptr, kptr_t addr, size_t size, uint32_t prot, void *arg), void *arg)
{
    for(size_t i = 0; i < macho->nmapV; ++i)
    {
        macho_map_t *map = &macho->mapV[i];
        if(!cb((const void*)map->mem, map->addr, map->size, map->prot, arg))
        {
            return false;
        }
    }
    return true;
}

bool macho_foreach_segment(macho_t *macho, bool (*cb)(const void *ptr, kptr_t addr, size_t size, uint32_t prot, const char *segment, void *arg), void *arg)
{
    for(size_t i = 0; i < macho->nsegs; ++i)
    {
        macho_segment_t *seg = &macho->segmentsByAddr[i];
        if(!cb((const void*)seg->mem, seg->addr, seg->size, seg->prot, seg->segname, arg))
        {
            return false;
        }
    }
    return true;
}

bool macho_foreach_section(macho_t *macho, bool (*cb)(const void *ptr, kptr_t addr, size_t size, uint32_t prot, const char *segment, const char *section, void *arg), void *arg)
{
    for(size_t i = 0; i < macho->nsecs; ++i)
    {
        macho_section_t *sec = &macho->sectionsByAddr[i];
        if(!cb((const void*)sec->mem, sec->addr, sec->size, sec->prot, sec->segname, sec->secname, arg))
        {
            return false;
        }
    }
    return true;
}

static bool macho_foreach_ptr_walk_chain(fixup_kind_t fixupKind, kptr_t base, macho_map_t *mapV, size_t nmapV, size_t off, bool (*cb)(const kptr_t *ptr, void *arg), void *arg)
{
    const kptr_t *ptr = macho_vtop_internal(mapV, nmapV, base + off, 0); // TODO: non-zero size here?
    if(!ptr)
    {
        ERR("Failed to find start of chained fixup, this should not be possible!");
        __builtin_trap();
    }

    size_t skip = 0;
    do
    {
        if(!cb(ptr, arg))
        {
            return false;
        }
        bool bind = false;
        macho_fixup_internal(fixupKind, base, *ptr, &bind, NULL, NULL, &skip);
        ptr = (const kptr_t*)((uintptr_t)ptr + skip);
    } while(skip > 0);
    return true;
}

static bool macho_foreach_ptr_internal(uintptr_t hdr, fixup_kind_t fixupKind, union fixup_data fixup, kptr_t base, macho_map_t *mapV, size_t nmapV, bool (*cb)(const kptr_t *ptr, void *arg), void *arg)
{
    switch(fixupKind)
    {
        case DYLD_CHAINED_PTR_ARM64E_KERNEL:
        case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
        {
            const fixup_seg_t *segs = fixup.chain;
            for(uint32_t i = 0, max = segs->seg_count; i < max; ++i)
            {
                if(segs->seg_info_offset[i] == 0)
                {
                    continue;
                }
                const fixup_starts_t *starts = (const fixup_starts_t*)((uintptr_t)segs + segs->seg_info_offset[i]);
                for(uint16_t j = 0, m = starts->page_count; j < m; ++j)
                {
                    uint16_t idx = starts->page_start[j];
                    if(idx == 0xffff)
                    {
                        continue;
                    }
                    if(!macho_foreach_ptr_walk_chain(fixupKind, base, mapV, nmapV, starts->segment_offset + (size_t)j * (size_t)starts->page_size + (size_t)idx, cb, arg))
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
        {
            const thread_starts_t *starts = (const thread_starts_t*)(hdr + fixup.thread->offset);
            for(size_t i = 0, max = fixup.thread->size / sizeof(uint32_t) - 1; i < max; ++i)
            {
                uint32_t off = starts->starts[i];
                if(off == 0xffffffff)
                {
                    continue;
                }
                if(!macho_foreach_ptr_walk_chain(fixupKind, base, mapV, nmapV, off, cb, arg))
                {
                    return false;
                }
            }
            return true;
        }

        case DYLD_CHAINED_PTR_NONE:
        {
            kaslrPackedOffsets_t *kxld = fixup.kxld;
            for(uint32_t i = 0, max = kxld->count; i < max; ++i)
            {
                if(!cb((const kptr_t*)(hdr + kxld->offsetsArray[i]), arg))
                {
                    return false;
                }
            }
            return true;
        }
    }
    __builtin_trap();
}

bool macho_foreach_ptr(macho_t *macho, bool (*cb)(const kptr_t *ptr, void *arg), void *arg)
{
    return macho_foreach_ptr_internal((uintptr_t)macho->hdr, macho->fixupKind, macho->fixup, macho->base, macho->mapV, macho->nmapV, cb, arg);
}

bool macho_find_bytes(macho_t *macho, const void *bytes, size_t size, size_t alignment, bool (*cb)(kptr_t addr, void *arg), void *arg)
{
    if(size > macho->size)
    {
        ERR("macho_find_bytes: size > macho->size");
        return false;
    }
    uintptr_t base = (uintptr_t)macho->hdr;
    for(size_t off = 0, max = macho->size - size; off <= max; off += alignment)
    {
        if(memcmp((const void*)(base + off), bytes, size) == 0)
        {
            kptr_t addr = macho_ptov(macho, (const void*)(base + off));
            if(!addr)
            {
                ERR("macho_find_bytes: unmapped offset 0x%zx", off);
                return false;
            }
            if(!cb(addr, arg))
            {
                return false;
            }
        }
    }
    return true;
}

bool macho_have_symbols(macho_t *macho)
{
    return macho->nsyms > 0;
}

static int macho_symbol_cb(const void *key, const void *value)
{
    return strcmp(key, ((const sym_t*)value)->name);
}

kptr_t macho_symbol(macho_t *macho, const char *sym)
{
    const sym_t *s = bsearch(sym, macho->symsByName, macho->nsyms, sizeof(sym_t), &macho_symbol_cb);
    return s ? s->addr : 0;
}

typedef struct
{
    const char *prefix;
    size_t prefixlen;
    const sym_t *bound;
} macho_symbols_for_prefix_cb_t;

static int macho_symbols_for_prefix_cb_start(const void *key, const void *value)
{
    const macho_symbols_for_prefix_cb_t *arg = key;
    const sym_t *sym = value;
    int cmp = strncmp(arg->prefix, sym->name, arg->prefixlen);
    if(cmp != 0)
    {
        return cmp;
    }
    if(sym == arg->bound || strncmp(arg->prefix, (sym-1)->name, arg->prefixlen) != 0)
    {
        return 0;
    }
    return -1;
}

static int macho_symbols_for_prefix_cb_end(const void *key, const void *value)
{
    const macho_symbols_for_prefix_cb_t *arg = key;
    const sym_t *sym = value;
    int cmp = strncmp(arg->prefix, sym->name, arg->prefixlen);
    if(cmp != 0)
    {
        return cmp;
    }
    if(sym == arg->bound || strncmp(arg->prefix, (sym+1)->name, arg->prefixlen) != 0)
    {
        return 0;
    }
    return 1;
}

const sym_t* macho_symbols_for_prefix(macho_t *macho, const char *prefix, size_t *n)
{
    macho_symbols_for_prefix_cb_t arg =
    {
        .prefix = prefix,
        .prefixlen = strlen(prefix),
        .bound = macho->symsByName,
    };
    const sym_t* start = bsearch(&arg, macho->symsByName, macho->nsyms, sizeof(sym_t), &macho_symbols_for_prefix_cb_start);
    if(!start)
    {
        return NULL;
    }
    // If we get here, we have at least 1 element, so doing -1 here is fine.
    arg.bound = macho->symsByName + macho->nsyms - 1;
    const sym_t *end = bsearch(&arg, macho->symsByName, macho->nsyms, sizeof(sym_t), &macho_symbols_for_prefix_cb_end);
    if(!end)
    {
        ERR("macho_symbols_for_prefix: found start but failed to find end, this should not be possible!");
        __builtin_trap();
    }
    *n = end - start + 1;
    return start;
}

typedef struct
{
    kptr_t addr;
    const sym_t *bound;
} macho_symbols_for_addr_cb_t;

static int macho_symbols_for_addr_cb_start(const void *key, const void *value)
{
    const macho_symbols_for_addr_cb_t *arg = key;
    const sym_t *sym = value;
    if(arg->addr < sym->addr)
    {
        return -1;
    }
    if(arg->addr > sym->addr)
    {
        return 1;
    }
    if(sym == arg->bound || arg->addr != (sym-1)->addr)
    {
        return 0;
    }
    return -1;
}

static int macho_symbols_for_addr_cb_end(const void *key, const void *value)
{
    const macho_symbols_for_addr_cb_t *arg = key;
    const sym_t *sym = value;
    if(arg->addr < sym->addr)
    {
        return -1;
    }
    if(arg->addr > sym->addr)
    {
        return 1;
    }
    if(sym == arg->bound || arg->addr != (sym+1)->addr)
    {
        return 0;
    }
    return 1;
}

const sym_t* macho_symbols_for_addr(macho_t *macho, kptr_t addr, size_t *n)
{
    macho_symbols_for_addr_cb_t arg =
    {
        .addr = addr,
        .bound = macho->symsByAddr,
    };
    const sym_t* start = bsearch(&arg, macho->symsByAddr, macho->nsyms, sizeof(sym_t), &macho_symbols_for_addr_cb_start);
    if(!start)
    {
        return NULL;
    }
    // If we get here, we have at least 1 element, so doing -1 here is fine.
    arg.bound = macho->symsByAddr + macho->nsyms - 1;
    const sym_t *end = bsearch(&arg, macho->symsByAddr, macho->nsyms, sizeof(sym_t), &macho_symbols_for_addr_cb_end);
    if(!end)
    {
        ERR("macho_symbols_for_addr: found start but failed to find end, this should not be possible!");
        __builtin_trap();
    }
    *n = end - start + 1;
    return start;
}

kptr_t macho_reloc(macho_t *macho, const char *sym)
{
    const sym_t *s = bsearch(sym, macho->relocByName, macho->nreloc, sizeof(sym_t), &macho_symbol_cb);
    return s ? s->addr : 0;
}

static int macho_reloc_cb(const void *key, const void *value)
{
    return macho_cmp_u64((kptr_t)key, ((const sym_t*)value)->addr);
}

const char* macho_reloc_for_addr(macho_t *macho, kptr_t loc)
{
    const sym_t *s = bsearch((void*)loc, macho->relocByAddr, macho->nreloc, sizeof(sym_t), &macho_reloc_cb);
    return s ? s->name : NULL;
}

static CFTypeRef macho_prelink_info_internal(const macho_section_t *sectionsByName, size_t nsecs)
{
    const void *xml = NULL;
    if(!macho_section_internal(sectionsByName, nsecs, "__PRELINK_INFO", "__info", &xml, NULL, NULL, NULL))
    {
        //ERR("Failed to find PrelinkInfo");
        return NULL;
    }

    CFStringRef err = NULL;
    CFTypeRef info = IOCFUnserialize(xml, NULL, 0, &err);
    if(!info)
    {
        if(err)
        {
            ERR("IOCFUnserialize: %s", CFStringGetCStringPtr(err, kCFStringEncodingUTF8));
            CFRelease(err);
        }
        else
        {
            ERR("IOCFUnserialize: <null>");
        }
        return NULL;
    }
    if(err)
    {
        WRN("IOCFUnserialize populated the error string but returned success???");
        CFRelease(err);
    }
    return info;
}

CFTypeRef macho_prelink_info(macho_t *macho)
{
    if(!macho->prelinkInfo)
    {
        macho->prelinkInfo = macho_prelink_info_internal(macho->sectionsByName, macho->nsecs);
    }
    return macho->prelinkInfo;
}

#if 0
kptr_t off2addr(void *macho, size_t off)
{
    FOREACH_CMD(((mach_hdr_t*)macho), cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            if(off >= seg->fileoff && off < seg->fileoff + seg->filesize)
            {
                return seg->vmaddr + (off - seg->fileoff);
            }
        }
    }
    ERR("Failed to translate macho offset 0x%lx", off);
    exit(-1);
}

void* addr2ptr(void *macho, kptr_t addr)
{
    FOREACH_CMD(((mach_hdr_t*)macho), cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            if(addr >= seg->vmaddr && addr < seg->vmaddr + seg->filesize)
            {
                return (void*)((uintptr_t)macho + seg->fileoff + (addr - seg->vmaddr));
            }
        }
    }
    return NULL;
}

mach_seg_t* seg4ptr(void *macho, void *ptr)
{
    char *p = ptr;
    FOREACH_CMD(((mach_hdr_t*)macho), cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            if(p >= (char*)((uintptr_t)macho + seg->fileoff) && p < (char*)((uintptr_t)macho + seg->fileoff + seg->filesize))
            {
                return seg;
            }
        }
    }
    ERR("Failed to find segment for ptr 0x%llx", (uint64_t)ptr);
    exit(-1);
}

kptr_t kuntag(kptr_t base, fixup_kind_t fixupKind, kptr_t ptr, bool *bind, bool *auth, uint16_t *pac, size_t *skip)
{
    pacptr_t pp;
    pp.ptr = ptr;
    if(fixupKind == DYLD_CHAINED_PTR_64_KERNEL_CACHE)
    {
        if(pp.cache.cache != 0)
        {
            ERR("Cannot resolve pointer with cache level %u: " ADDR, pp.cache.cache, ptr);
            exit(-1);
        }
        if(bind) *bind = false;
        if(auth) *auth = !!(pp.cache.auth && pp.cache.tag);
        if(pac)  *pac  = pp.cache.div;
        if(skip) *skip = pp.cache.next * sizeof(uint32_t);
        return base + pp.cache.target;
    }
    if(fixupKind == DYLD_CHAINED_PTR_ARM64E || fixupKind == DYLD_CHAINED_PTR_ARM64E_KERNEL)
    {
        if(pp.pac.bind)
        {
            if(!bind)
            {
                ERR("Cannot bind pointer " ADDR, ptr);
                exit(-1);
            }
            *bind = true;
        }
        else if(bind)
        {
            *bind = false;
        }
        if(auth) *auth = false;
        if(pac)  *pac  = 0;
        if(skip) *skip = pp.pac.next * sizeof(uint32_t);
        if(pp.pac.auth)
        {
            if(auth) *auth = !!pp.pac.tag;
            if(pac)  *pac  = pp.pac.div;
        }
        if(pp.pac.bind) return pp.pac.off & 0xffff;
        if(pp.pac.auth) return base + pp.pac.off;
        return (kptr_t)pp.raw.lo + (fixupKind == DYLD_CHAINED_PTR_ARM64E ? 0 : base);
    }
    if(bind) *bind = false;
    if(auth) *auth = false;
    if(pac)  *pac  = 0;
    if(skip) *skip = 0;
    return pp.ptr;
}

bool is_in_fixup_chain(void *macho, kptr_t base, void *ptr)
{
    bool bind;
    FOREACH_CMD(((mach_hdr_t*)macho), cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            if(strcmp("__TEXT", seg->segname) == 0)
            {
                mach_sec_t *secs = (mach_sec_t*)(seg + 1);
                for(size_t i = 0; i < seg->nsects; ++i)
                {
                    if(strcmp("__thread_starts", secs[i].sectname) == 0)
                    {
                        uint32_t *start = (uint32_t*)((uintptr_t)macho + secs[i].offset),
                                 *end   = (uint32_t*)((uintptr_t)start  + secs[i].size);
                        if(end > start)
                        {
                            ++start;
                            for(; start < end; ++start)
                            {
                                if(*start == 0xffffffff)
                                {
                                    break;
                                }
                                kptr_t *mem = addr2ptr(macho, base + *start);
                                size_t skip = 0;
                                do
                                {
                                    if((uintptr_t)mem == (uintptr_t)ptr)
                                    {
                                        return true;
                                    }
                                    if((uintptr_t)mem > (uintptr_t)ptr)
                                    {
                                        return false;
                                    }
                                    kuntag(base, DYLD_CHAINED_PTR_ARM64E, *mem, &bind, NULL, NULL, &skip);
                                    mem = (kptr_t*)((uintptr_t)mem + skip);
                                } while(skip > 0);
                            }
                            return false;
                        }
                    }
                }
            }
        }
        else if(cmd->cmd == LC_DYLD_CHAINED_FIXUPS)
        {
            struct linkedit_data_command *data = (struct linkedit_data_command*)cmd;
            fixup_hdr_t *fixup = (fixup_hdr_t*)((uintptr_t)macho + data->dataoff);
            fixup_seg_t *segs = (fixup_seg_t*)((uintptr_t)fixup + fixup->starts_offset);
            for(uint32_t i = 0; i < segs->seg_count; ++i)
            {
                if(segs->seg_info_offset[i] == 0)
                {
                    continue;
                }
                fixup_starts_t *starts = (fixup_starts_t*)((uintptr_t)segs + segs->seg_info_offset[i]);
                uint64_t off = (uintptr_t)ptr - (uintptr_t)macho;
                if(starts->pointer_format == DYLD_CHAINED_PTR_ARM64E_KERNEL)
                {
                    off = off2addr(macho, off) - base;
                }
                if(off < starts->segment_offset || (off - starts->segment_offset) / starts->page_size >= starts->page_count)
                {
                    continue;
                }
                uint16_t j = (off - starts->segment_offset) / starts->page_size;
                uint16_t idx = starts->page_start[j];
                if(idx == 0xffff)
                {
                    continue;
                }
                size_t where = (size_t)starts->segment_offset + (size_t)j * (size_t)starts->page_size + (size_t)idx;
                kptr_t *mem = starts->pointer_format == DYLD_CHAINED_PTR_ARM64E_KERNEL ? addr2ptr(macho, base + where) : (kptr_t*)((uintptr_t)macho + where);
                size_t skip = 0;
                do
                {
                    if((uintptr_t)mem == (uintptr_t)ptr)
                    {
                        return true;
                    }
                    if((uintptr_t)mem > (uintptr_t)ptr)
                    {
                        return false;
                    }
                    kuntag(base, starts->pointer_format, *mem, &bind, NULL, NULL, &skip);
                    mem = (kptr_t*)((uintptr_t)mem + skip);
                } while(skip > 0);
            }
            return false;
        }
    }
    return false;
}

static int validate_fat(void **machop, size_t *machosizep, mach_hdr_t **hdrp, const char *name)
{
    void *macho = *machop;
    size_t machosize = *machosizep;
    mach_hdr_t *hdr = *hdrp;

    if(machosize < sizeof(mach_hdr_t))
    {
        if(name) ERR("Embedded file is too short to be a Mach-O (%s).", name);
        else     ERR("File is too short to be a Mach-O.");
        return -1;
    }

    size_t filesize = machosize;
    fat_hdr_t *fat = (fat_hdr_t*)hdr;
    if(fat->magic == FAT_CIGAM)
    {
        bool found = false;
        fat_arch_t *arch = (fat_arch_t*)(fat + 1);
        for(size_t i = 0; i < SWAP32(fat->nfat_arch); ++i)
        {
            uint32_t cputype = SWAP32(arch[i].cputype);
            if(cputype == CPU_TYPE_ARM64)
            {
                uint32_t offset = SWAP32(arch[i].offset);
                uint32_t newsize = SWAP32(arch[i].size);
                if(offset > filesize || newsize > filesize - offset)
                {
                    if(name) ERR("Embedded fat arch out of bounds (%s).", name);
                    else     ERR("Fat arch out of bounds.");
                    continue;
                }
                if(newsize < sizeof(mach_hdr_t))
                {
                    if(name) ERR("Embedded fat arch is too short to contain a Mach-O (%s).", name);
                    else     ERR("Fat arch is too short to contain a Mach-O.");
                    continue;
                }
                uint32_t subtype = SWAP32(arch[i].cpusubtype);
                mach_hdr_t *candidate = (void*)((uintptr_t)fat + offset);
                if(candidate->cputype != cputype || candidate->cpusubtype != subtype)
                {
                    if(name) ERR("Embedded fat arch doesn't match Mach-O arch (%s).", name);
                    else     ERR("Fat arch doesn't match Mach-O arch.");
                    continue;
                }
                macho = candidate;
                machosize = newsize;
                hdr = macho;
                found = true;
                // Prefer arm64e
                if((subtype & CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E)
                {
                    break;
                }
            }
        }
        if(!found)
        {
            if(name) ERR("No (valid) arm64(e) slice in embedded fat binary (%s).", name);
            else     ERR("No (valid) arm64(e) slice in fat binary.");
            return -1;
        }
        *machop     = macho;
        *machosizep = machosize;
        *hdrp       = hdr;
    }
    return 0;
}

int validate_macho(void **machop, size_t *machosizep, mach_hdr_t **hdrp, const char *name)
{
    void *macho = *machop;
    size_t machosize = *machosizep;
    mach_hdr_t *hdr = *hdrp;
    if(!name)
    {
        int r = validate_fat(&macho, &machosize, &hdr, name);
        if(r != 0)
        {
            return r;
        }
    }

    if(hdr->magic != MACH_MAGIC)
    {
        if(name) ERR("Wrong embedded magic: 0x%08x (%s)", hdr->magic, name);
        else     ERR("Wrong magic: 0x%08x", hdr->magic);
        return -1;
    }
    if(hdr->cputype != CPU_TYPE_ARM64)
    {
        if(name) ERR("Wrong embedded architecture, only arm64(e) is supported (%s).", name);
        else     ERR("Wrong architecture, only arm64(e) is supported.");
        return -1;
    }
    uint32_t subtype = hdr->cpusubtype & CPU_SUBTYPE_MASK;
    if(subtype != CPU_SUBTYPE_ARM64_ALL && subtype != CPU_SUBTYPE_ARM64E)
    {
        if(name) ERR("Unknown embedded cpusubtype: 0x%x (%s)", subtype, name);
        else     ERR("Unknown cpusubtype: 0x%x", subtype);
        return -1;
    }
    if(hdr->filetype != MH_EXECUTE && hdr->filetype != MH_KEXT_BUNDLE && (name != NULL || hdr->filetype != MH_FILESET))
    {
        if(name) ERR("Wrong embedded Mach-O type: 0x%x (%s)", hdr->filetype, name);
        else     ERR("Wrong Mach-O type: 0x%x", hdr->filetype);
        return -1;
    }
    if(hdr->sizeofcmds > machosize - sizeof(mach_hdr_t))
    {
        if(name) ERR("Embedded Mach-O header out of bounds (%s).", name);
        else     ERR("Mach-O header out of bounds.");
        return -1;
    }
    kptr_t kbase = 0, kmin = ~0ULL, kmax = 0;
    fixup_kind_t fixupKind = DYLD_CHAINED_PTR_NONE;
    mach_nlist_t *symtab = NULL;
    char         *strtab = NULL;
    // TODO: replace header & weed out invalid load commands?
    FOREACH_CMD(hdr, cmd)
    {
        if(cmd->cmdsize > hdr->sizeofcmds - ((uintptr_t)cmd - (uintptr_t)(hdr + 1)))
        {
            if(name) ERR("Embedded Mach-O load command out of bounds (%s).", name);
            else     ERR("Mach-O load command out of bounds.");
            return -1;
        }
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            if(seg->fileoff > machosize || seg->filesize > machosize - seg->fileoff)
            {
                if(name) ERR("Embedded Mach-O segment out of bounds: %s (%s)", seg->segname, name);
                else     ERR("Mach-O segment out of bounds: %s", seg->segname);
                return -1;
            }
            if(seg->vmsize > 0)
            {
                if(seg->fileoff == 0)
                {
                    kbase = seg->vmaddr;
                }
                if(seg->vmaddr < kmin)
                {
                    kmin = seg->vmaddr;
                }
                if(seg->vmaddr + seg->vmsize > kmax)
                {
                    kmax = seg->vmaddr + seg->vmsize;
                }
            }
            mach_sec_t *secs = (mach_sec_t*)(seg + 1);
            for(size_t h = 0; h < seg->nsects; ++h)
            {
                if(secs[h].offset > machosize || secs[h].size > machosize - secs[h].offset)
                {
                    if(name) ERR("Embedded Mach-O section out of bounds: %s.%s (%s)", secs[h].segname, secs[h].sectname, name);
                    else     ERR("Mach-O section out of bounds: %s.%s", secs[h].segname, secs[h].sectname);
                    return -1;
                }
                if(strcmp("__TEXT", seg->segname) == 0 && strcmp("__thread_starts", secs[h].sectname) == 0)
                {
                    if(secs[h].size % sizeof(uint32_t) != 0)
                    {
                        if(name) ERR("Embedded Mach-O chained fixup section has bad size: 0x%llx (%s)", secs[h].size, name);
                        else     ERR("Mach-O chained fixup section has bad size: 0x%llx", secs[h].size);
                        return -1;
                    }
                    if(secs[h].size > 0)
                    {
                        uint32_t gran = *(uint32_t*)((uintptr_t)macho + secs[h].offset);
                        if(gran != 0)
                        {
                            if(name) ERR("Embedded Mach-O chained fixup has bad granularity: 0x%x (%s)", gran, name);
                            else     ERR("Mach-O chained fixup has bad granularity: 0x%x", gran);
                            return -1;
                        }
                        if(fixupKind != DYLD_CHAINED_PTR_NONE)
                        {
                            if(name) ERR("Embedded Mach-O has multiple fixup types (%s).", name);
                            else     ERR("Mach-O has multiple fixup types.");
                            return -1;
                        }
                        fixupKind = DYLD_CHAINED_PTR_ARM64E;
                    }
                }
            }
        }
        else if(cmd->cmd == LC_SYMTAB)
        {
            mach_stab_t *stab = (mach_stab_t*)cmd;
            if(stab->stroff > machosize || stab->symoff > machosize || stab->nsyms > (machosize - stab->symoff) / sizeof(mach_nlist_t))
            {
                if(name) ERR("Embedded Mach-O symtab out of bounds (%s).", name);
                else     ERR("Mach-O symtab out of bounds.");
                return -1;
            }
            symtab = (mach_nlist_t*)((uintptr_t)macho + stab->symoff);
            strtab = (char*)((uintptr_t)macho + stab->stroff);
            for(size_t i = 0; i < stab->nsyms; ++i)
            {
                if(symtab[i].n_strx > machosize - stab->stroff)
                {
                    if(name) ERR("Embedded Mach-O symbol out of bounds (%s).", name);
                    else     ERR("Mach-O symbol out of bounds.");
                    return -1;
                }
            }
        }
        else if(cmd->cmd == LC_DYSYMTAB)
        {
            if(!symtab || !strtab)
            {
                if(name) ERR("Embedded Mach-O dsymtab without symtab/strtab (%s).", name);
                else     ERR("Mach-O dsymtab without symtab/strtab.");
                return -1;
            }
            mach_dstab_t *dstab = (mach_dstab_t*)cmd;
            if(dstab->extreloff > machosize || dstab->nextrel > (machosize - dstab->extreloff) / sizeof(mach_reloc_t))
            {
                if(name) ERR("Embedded Mach-O dsymtab out of bounds (%s).", name);
                else     ERR("Mach-O dsymtab out of bounds.");
                return -1;
            }
            mach_reloc_t *reloc = (mach_reloc_t*)((uintptr_t)macho + dstab->extreloff);
            for(size_t i = 0; i < dstab->nextrel; ++i)
            {
                if(!reloc[i].r_extern)
                {
                    if(name) ERR("Embedded Mach-O external relocation entry %lu at 0x%x does not have external bit set (%s).", i, reloc[i].r_address, name);
                    else     ERR("Mach-O external relocation entry %lu at 0x%x does not have external bit set.", i, reloc[i].r_address);
                    return -1;
                }
                if(reloc[i].r_length != 0x3)
                {
                    if(name) ERR("Embedded Mach-O external relocation entry %lu at 0x%x is not 8 bytes (%s).", i, reloc[i].r_address, name);
                    else     ERR("Mach-O external relocation entry %lu at 0x%x is not 8 bytes.", i, reloc[i].r_address);
                    return -1;
                }
            }
            // TODO: verify locreloc
        }
        else if(cmd->cmd == LC_FILESET_ENTRY)
        {
            if(name)
            {
                ERR("Embedded Mach-O has further embedded Mach-Os (%s).", name);
                return -1;
            }
            mach_fileent_t *ent = (mach_fileent_t*)cmd;
            if(ent->fileoff >= machosize || ent->nameoff >= ent->cmdsize)
            {
                ERR("Mach-O file entry out of bounds.");
                return -1;
            }
            void *embedded = macho;
            size_t embeddedsize = machosize;
            mach_hdr_t *mh = (void*)((uintptr_t)macho + ent->fileoff);
            const char *name = (const char*)((uintptr_t)ent + ent->nameoff);
            int r = validate_macho(&embedded, &embeddedsize, &mh, name);
            if(r != 0)
            {
                return r;
            }
        }
        else if(cmd->cmd == LC_DYLD_CHAINED_FIXUPS)
        {
            if(name)
            {
                ERR("Embedded Mach-O has chained fixup load command (%s).", name);
                return -1;
            }
            if(fixupKind != DYLD_CHAINED_PTR_NONE)
            {
                ERR("Mach-O has multiple fixup types.");
                return -1;
            }
            struct linkedit_data_command *data = (struct linkedit_data_command*)cmd;
            if(data->datasize < sizeof(fixup_hdr_t))
            {
                ERR("Mach-O chained fixup data too small to hold fixup chain header.");
                return -1;
            }
            if(data->dataoff >= machosize || data->datasize >= machosize - data->dataoff)
            {
                ERR("Mach-O chained fixup data out of bounds.");
                return -1;
            }
            uintptr_t max = (uintptr_t)macho + data->dataoff + data->datasize;
            fixup_hdr_t *fixup = (fixup_hdr_t*)((uintptr_t)macho + data->dataoff);
            if(fixup->fixups_version != 0)
            {
                ERR("Unsupported chained fixup version: %u", fixup->fixups_version);
                return -1;
            }
            if(fixup->imports_count)
            {
                if(fixup->imports_count > 0xffff)
                {
                    ERR("More imports that the pointer format can handle: 0x%x", fixup->imports_count);
                    return -1;
                }
                if(fixup->imports_format != 0x1 || fixup->symbols_format != 0x0)
                {
                    ERR("Unsupported chained imports or symbols format: 0x%x/0x%x", fixup->imports_format, fixup->symbols_format);
                    return -1;
                }
                fixup_import_t *import = (fixup_import_t*)((uintptr_t)fixup + fixup->imports_offset);
                if(fixup->imports_offset > max - (uintptr_t)fixup - sizeof(*import) || fixup->imports_count > (max - (uintptr_t)import) / sizeof(*import))
                {
                    ERR("Mach-O chained imports out of bounds.");
                    return -1;
                }
                if(fixup->symbols_offset > max - (uintptr_t)fixup - 1)
                {
                    ERR("Mach-O import symbols out of bounds.");
                    return -1;
                }
                const char *syms = (const char*)((uintptr_t)fixup + fixup->symbols_offset);
                for(uint32_t i = 0; i < fixup->imports_count; ++i)
                {
                    fixup_import_t *imp = import + i;
                    if(imp->lib_ordinal != 0xfe)
                    {
                        ERR("Unsupported chained import ordinal: 0x%x", imp->lib_ordinal);
                        return -1;
                    }
                    if(imp->name_offset >= max - (uintptr_t)syms)
                    {
                        ERR("Mach-O chained import out of bounds: 0x%x", imp->name_offset);
                        return -1;
                    }
                }
            }
            fixup_seg_t *segs = (fixup_seg_t*)((uintptr_t)fixup + fixup->starts_offset);
            if((uintptr_t)segs > max - sizeof(*segs) || segs->seg_count > (max - (uintptr_t)segs->seg_info_offset) / sizeof(segs->seg_info_offset[0]))
            {
                ERR("Mach-O chained fixup segments out of bounds.");
                return -1;
            }
            for(uint32_t i = 0; i < segs->seg_count; ++i)
            {
                if(segs->seg_info_offset[i] == 0)
                {
                    continue;
                }
                fixup_starts_t *starts = (fixup_starts_t*)((uintptr_t)segs + segs->seg_info_offset[i]);
                if((uintptr_t)starts > max - sizeof(*starts) || starts->size < sizeof(*starts))
                {
                    ERR("Mach-O chained fixup starts out of bounds (%u).", i);
                    return -1;
                }
                uintptr_t end = (uintptr_t)starts + starts->size;
                if(end > max || (uintptr_t)&starts->page_start[starts->page_count] > end)
                {
                    ERR("Mach-O chained fixup starts out of bounds (%u).", i);
                    return -1;
                }
                if(starts->page_size != 0x1000 && starts->page_size != 0x4000)
                {
                    ERR("Mach-O chained fixup starts has bad page size: 0x%x (%u)", starts->page_size, i);
                    return -1;
                }
                if(starts->pointer_format != DYLD_CHAINED_PTR_ARM64E_KERNEL && starts->pointer_format != DYLD_CHAINED_PTR_64_KERNEL_CACHE)
                {
                    ERR("Unsupported chained fixup pointer format: 0x%x (%u)", starts->pointer_format, i);
                    return -1;
                }
                if(fixupKind != DYLD_CHAINED_PTR_NONE && fixupKind != starts->pointer_format)
                {
                    ERR("Mach-O has multiple fixup types.");
                    return -1;
                }
                fixupKind = starts->pointer_format;
                if(fixupKind == DYLD_CHAINED_PTR_ARM64E_KERNEL)
                {
                    // REVIEW: I guess it's fine for this to overflow?
                    kptr_t start = kbase + starts->segment_offset;
                    if(start >= kmax || start < kmin || starts->page_count > (kmax - start) / starts->page_size)
                    {
                        ERR("Mach-O chained fixup starts describes a region out of bounds (%u).", i);
                        return -1;
                    }
                }
                else
                {
                    if(starts->segment_offset > machosize || starts->page_count > (machosize - starts->segment_offset) / starts->page_size)
                    {
                        ERR("Mach-O chained fixup starts describes a region out of bounds (%u).", i);
                        return -1;
                    }
                }
                for(uint16_t j = 0; j < starts->page_count; ++j)
                {
                    uint16_t idx = starts->page_start[j];
                    if(idx == 0xffff)
                    {
                        continue;
                    }
                    if(idx % sizeof(uint32_t) != 0)
                    {
                        ERR("Mach-O fixup chain misaligned: 0x%x (%u, %u)", idx, i, j);
                        return -1;
                    }
                    if(idx >= starts->page_size)
                    {
                        ERR("Mach-O fixup chain out of bounds: 0x%x (%u, %u)", idx, i, j);
                        return -1;
                    }
                }
            }
        }
    }
    *machop     = macho;
    *machosizep = machosize;
    *hdrp       = hdr;
    return 0;
}

int compare_sym_addrs(const void *a, const void *b)
{
    kptr_t adda = ((const sym_t*)a)->addr,
           addb = ((const sym_t*)b)->addr;
    if(adda == addb) return 0;
    return adda < addb ? -1 : 1;
}

int compare_sym_names(const void *a, const void *b)
{
    const sym_t *syma = a,
                *symb = b;
    return strcmp(syma->name, symb->name);
}

int compare_sym_addr(const void *a, const void *b)
{
    kptr_t adda = *(const kptr_t*)a,
           addb = ((const sym_t*)b)->addr;
    if(adda == addb) return 0;
    return adda < addb ? -1 : 1;
}

int compare_sym_name(const void *a, const void *b)
{
    const char *name = a;
    const sym_t *sym = b;
    return strcmp(name, sym->name);
}

const char* find_sym_by_addr(kptr_t addr, sym_t *asyms, size_t nsyms)
{
    sym_t *sym = bsearch(&addr, asyms, nsyms, sizeof(*asyms), &compare_sym_addr);
    return sym ? sym->name : NULL;
}

kptr_t find_sym_by_name(const char *name, sym_t *bsyms, size_t nsyms)
{
    sym_t *sym = bsearch(name, bsyms, nsyms, sizeof(*bsyms), &compare_sym_name);
    return sym ? sym->addr : 0;
}

bool macho_extract_symbols(void *macho, mach_stab_t *stab, sym_t **symp, size_t *nsymp)
{
    mach_nlist_t *symtab = (mach_nlist_t*)((uintptr_t)macho + stab->symoff);
    char *strtab = (char*)((uintptr_t)macho + stab->stroff);
    size_t nsyms = *nsymp;
    for(size_t i = 0; i < stab->nsyms; ++i)
    {
        if((symtab[i].n_type & N_TYPE) != N_SECT || ((symtab[i].n_type & N_STAB) && !(symtab[i].n_type & N_EXT)))
        {
            continue;
        }
        ++nsyms;
    }
    if(nsyms == *nsymp)
    {
        return true;
    }
    sym_t *syms = realloc(*symp, sizeof(sym_t) * nsyms);
    if(!syms)
    {
        ERRNO("malloc(syms)");
        return false;
    }
    size_t idx = *nsymp;
    for(size_t i = 0; i < stab->nsyms; ++i)
    {
        if((symtab[i].n_type & N_TYPE) != N_SECT || ((symtab[i].n_type & N_STAB) && !(symtab[i].n_type & N_EXT)))
        {
            continue;
        }
        syms[idx].addr = symtab[i].n_value;
        syms[idx].name = &strtab[symtab[i].n_strx];
        DBG("Symbol: " ADDR " %s", syms[idx].addr, syms[idx].name);
        ++idx;
    }
    *symp = syms;
    *nsymp = nsyms;
    return true;
}

bool macho_extract_reloc(void *macho, kptr_t base, mach_dstab_t *dstab, mach_nlist_t *symtab, char *strtab, sym_t **exrelocp, size_t *nexrelocp)
{
    if(dstab->nextrel > 0)
    {
        sym_t *exreloc = *exrelocp;
        size_t nexreloc = *nexrelocp;
        mach_reloc_t *reloc = (mach_reloc_t*)((uintptr_t)macho + dstab->extreloff);
        exreloc = realloc(exreloc, (nexreloc + dstab->nextrel) * sizeof(sym_t));
        if(!exreloc)
        {
            ERRNO("malloc(exreloc)");
            return false;
        }
        for(size_t i = 0; i < dstab->nextrel; ++i)
        {
            kptr_t addr = base + reloc[i].r_address;
            const char *name = &strtab[symtab[reloc[i].r_symbolnum].n_strx];
            DBG("Exreloc " ADDR ": %s", addr, name);
            exreloc[nexreloc].addr = addr;
            exreloc[nexreloc].name = name;
            ++nexreloc;
        }
        *exrelocp = exreloc;
        *nexrelocp = nexreloc;
    }
    return true;
}

bool macho_extract_chained_imports(void *macho, kptr_t base, struct linkedit_data_command *cmd, sym_t **exrelocp, size_t *nexrelocp)
{
    fixup_hdr_t *fixup = (fixup_hdr_t*)((uintptr_t)macho + cmd->dataoff);
    if(fixup->imports_count)
    {
        fixup_import_t *import = (fixup_import_t*)((uintptr_t)fixup + fixup->imports_offset);
        const char *syms = (const char*)((uintptr_t)fixup + fixup->symbols_offset);
        fixup_seg_t *segs = (fixup_seg_t*)((uintptr_t)fixup + fixup->starts_offset);
        size_t nimport = 0;
        for(uint32_t i = 0; i < segs->seg_count; ++i)
        {
            if(segs->seg_info_offset[i] == 0)
            {
                continue;
            }
            fixup_starts_t *starts = (fixup_starts_t*)((uintptr_t)segs + segs->seg_info_offset[i]);
            if(starts->pointer_format != DYLD_CHAINED_PTR_ARM64E_KERNEL)
            {
                ERR("Cannot resolve chained imports for format: 0x%x", starts->pointer_format);
                return false;
            }
            for(uint16_t j = 0; j < starts->page_count; ++j)
            {
                uint16_t idx = starts->page_start[j];
                if(idx == 0xffff)
                {
                    continue;
                }
                kptr_t *mem = addr2ptr(macho, base + (size_t)starts->segment_offset + (size_t)j * (size_t)starts->page_size + (size_t)idx);
                size_t skip = 0;
                do
                {
                    pacptr_t pp;
                    pp.ptr = *mem;
                    if(pp.pac.bind)
                    {
                        if(pp.pac.off > fixup->imports_count) // validate_macho() checks that <= 0xffff
                        {
                            ERR("Chained import number out of bounds: 0x%x", pp.pac.off);
                            return false;
                        }
                        ++nimport;
                    }
                    skip = pp.pac.next * sizeof(uint32_t);
                    mem = (kptr_t*)((uintptr_t)mem + skip);
                } while(skip > 0);
            }
        }
        sym_t *exreloc = *exrelocp;
        size_t nexreloc = *nexrelocp;
        exreloc = realloc(exreloc, (nexreloc + nimport) * sizeof(sym_t));
        if(!exreloc)
        {
            ERRNO("malloc(exreloc)");
            return false;
        }
        for(uint32_t i = 0; i < segs->seg_count; ++i)
        {
            if(segs->seg_info_offset[i] == 0)
            {
                continue;
            }
            fixup_starts_t *starts = (fixup_starts_t*)((uintptr_t)segs + segs->seg_info_offset[i]);
            for(uint16_t j = 0; j < starts->page_count; ++j)
            {
                uint16_t idx = starts->page_start[j];
                if(idx == 0xffff)
                {
                    continue;
                }
                kptr_t addr = base + (size_t)starts->segment_offset + (size_t)j * (size_t)starts->page_size + (size_t)idx;
                kptr_t *mem = addr2ptr(macho, addr);
                size_t skip = 0;
                do
                {
                    pacptr_t pp;
                    pp.ptr = *mem;
                    if(pp.pac.bind)
                    {
                        const char *name = &syms[import[pp.pac.off].name_offset];
                        DBG("Chained import " ADDR ": %s", addr, name);
                        exreloc[nexreloc].addr = addr;
                        exreloc[nexreloc].name = name;
                        ++nexreloc;
                    }
                    skip = pp.pac.next * sizeof(uint32_t);
                    mem  = (kptr_t*)((uintptr_t)mem + skip);
                    addr += skip;
                } while(skip > 0);
            }
        }
        *exrelocp = exreloc;
        *nexrelocp = nexreloc;
    }
    return true;
}
#endif

// XXX TMP TODO: going away
const mach_hdr_t* __tmp_macho_get_hdr(macho_t *macho)
{
    return macho->hdr;
}
