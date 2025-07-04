/* Copyright (c) 2018-2025 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#if 0
There are four significantly different formats we support here:

1. Prelinked kernelcache. This is the oldest format, with filetype MH_EXECUTE
   and non-zero-sized __PRELINK_TEXT/__PLK_TEXT_EXEC where kexts live.
2. Statically linked kernelcache. This was introduced in iOS 12.0 for some devices. Filetype is still MH_EXECUTE,
   but __PRELINK_TEXT/__PLK_TEXT_EXEC are empty and it has kexts compiled directly into the kernel. Only the __TEXT_EXEC
   segments of kexts are still discernible, all other segments have been irreversibly merged with the ones of XNU.
3. Fileset. This uses the MH_FILESET filetype and was first introduced for Apple Silicon Macs in macOS 11.0.
   Since iOS 16.0 it is used for all arm64e devices. This is the only type where XNU is not the top-level binary.
4. Standalone kext. Filetype MH_KEXT_BUNDLE.

We also support standalone XNU (without kexts), but that is a strict subset of types 1 and 2.

Now, documenting some quirks:

- The authoritative source of truth regarding kexts is the __PRELINK_INFO.__info section. This *must* be parsed with
  an IOKit plist parser (i.e. IOCFUnserialize), CoreFoundation will not give correct results. A lot of the info contained
  therein is duplicated in kmod_info and fileset entries, but they can and do mismatch sometimes (e.g. the bundle ID of
  the kext containing the "IOReportHub" class is reported as "com.apple.iokit.IOReportFamily" at runtime by IOObjectCopyBundleIdentifierForClass(),
  but in the static kmod_info it says com.apple.iokit.IOReporting) - only the plist should be trusted.
  For standalone kexts this is even worse, because the correct value is only in the Info.plist, a whole separate file!
- The plist entries contain the keys "_PrelinkExecutableLoadAddr" and "_PrelinkKmodInfo", which are the addresses of the
  kext's Mach-O header and kmod_info, respectively. Except in the case of statically linked kernelcaches, where it contains
  a "ModuleIndex" key instead, which indexes into the sections __PRELINK_INFO.__kmod_start and __PRELINK_INFO.__kmod_info,
  which are only present on this type of kernelcache. For kernelcaches that do have "_PrelinkExecutableLoadAddr", the special
  value 0x7fffffffffffffff means that the kext is codeless and doesn't have a header. However, this value is only used since
  iOS 14.0/macOS 11.0. Before then, codeless kexts did still have a header, and actually a malformed one at that, because their
  "ncmds" says 3 but they really only have 2 load commands (LINKEDIT and LC_SYMTAB). I don't know how or why this happens, but
  these headers happen to also have the MH_INCRLINK, so we use that as a marker to skip them.
- Symbols are a mess.
  - In prelinked kernelcaches, XNU has between 4k and 5k exported symbols if stripped, and between 40k and 50k if unstripped.
    I have never seen embedded kexts with symbols in this type of kernelcache.
  - In statically linked kernelcaches, all symbols are moved to the top level, which is either fully stripped, or has well above
    100k symbols if unstripped.
  - In fileset kernelcaches, the top-level binary has no symbol table, and you need to parse each embedded binary to get its symbols.
  In principle, symbols are never needed unless we're looking at a standalone kext.
- KASLR is a mess as well. There exist at least four different setups:
  - The top-level binary has local relocations in its LC_DYSYMTAB, and each embedded binary does too.
    This is used by prelinked kernelcaches before iOS 10.0, and here iBoot rebases XNU, but not kexts.
    TODO: this is not currently handled correctly by this Mach-O parsing layer.
  - The top-level binary has local relocations in its LC_DYSYMTAB, and the prelink info plist contains
    a "_PrelinkLinkKASLROffsets" key with "packed" KASLR offsets for all kexts.
    This is used by prelinked kernelcaches on iOS 10.0 and later.
  - Chained fixups via __TEXT.__thread_starts. This is used by statically linked kernelcaches and is
    so aggressive that it even affects things like the "vmaddr" field in embedded binaries' Mach-O header.
    In this configuration, iBoot rebases the entire kernelcache, including kexts.
  - Chained fixups via LC_DYLD_CHAINED_FIXUPS load command. This is used by fileset kernelcaches and standalone kexts.
    This supports two different encodings of fixup chain elements, which are of course also different from the __thread_starts one.
  In principle, we would only have to parse KASLR info for chained fixups (since otherwise we can't read the pointers),
  but knowing which values are pointers is actually really useful for vtable bounds detection.
- Function starts are the biggest mess of all.
  - For statically linked kernelcaches, they are present at the top level and span the entire kernelcache.
  - For prelinked kernelcaches, they are also present at the top level but only span XNU, not kexts.
  - For standalone kexts, they are present since macOS 15.0.
  - For fileset kernelcaches, we have five different situations going on:
    - Since iOS 18.0/macOS 15.0, all fileset entries have their own LC_FUNCTION_STARTS load command.
    - Before iOS 18.0/macOS 15.0, only the embedded XNU header has function starts, and they do not span kexts.
    - Before macOS 13.0, the embedded XNU had its segments rebased relative to each other but function starts were not updated accordingly.
    - Between iOS 16.4 and 17.0 (exclusive), some kernelcaches are lacking the terminating zero in function starts data.
    - Between iOS 17.0 and 17.4 (exclusive), devices that have SPTM had their executable segments rearranged relative to each other,
      and the kernelcache builder tried to update the function starts info accordingly, but did not account for the fact that it would
      now need more space, so the emitted info is truncated.
- Fileset kernelcaches have weird segment handling. For one, they have certain segments without any sections,
  which is really annoying because that means we have to use segments in many places where we'd want to be more
  conservative with bounds. For another, offsets are inconsistent. For example, the function starts offset in the
  linkedit data commands are from the beginning of the binary, but the starting point for each starts chain is
  the vmaddress specified in the fileset entry.
#endif

#include <fcntl.h>              // open
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>             // malloc, free, qsort, bsearch, exit
#include <unistd.h>             // close
#include <sys/mman.h>           // mmap, munmap, MAP_FAILED
#include <sys/stat.h>           // fstat
#include <CoreFoundation/CoreFoundation.h>

extern CFTypeRef IOCFUnserializeWithSize(const char *buf, size_t len, CFAllocatorRef allocator, CFOptionFlags options, CFStringRef *err);

#include "macho.h"
#include "util.h"

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
#define CPU_TYPE_ARM64              0x0100000c
#define CPU_SUBTYPE_MASK            0x00ffffff
#define CPU_SUBTYPE_ARM64_ALL              0x0
#define CPU_SUBTYPE_ARM64E                 0x2
#define FAT_CIGAM                   0xbebafeca
#define MH_MAGIC_64                 0xfeedfacf
#define MH_EXECUTE                  0x00000002
#define MH_KEXT_BUNDLE              0x0000000b
#define MH_FILESET                  0x0000000c
#define MH_INCRLINK                 0x00000002
#define MH_DYLIB_IN_CACHE           0x80000000
#define LC_REQ_DYLD                 0x80000000
#define LC_SYMTAB                   0x00000002
#define LC_DYSYMTAB                 0x0000000b
#define LC_SEGMENT_64               0x00000019
#define LC_UUID                     0x0000001b
#define LC_FUNCTION_STARTS          0x00000026
#define LC_DYLD_CHAINED_FIXUPS      0x80000034
#define LC_FILESET_ENTRY            0x80000035
#define SECTION_TYPE                0x000000ff
#define S_ZEROFILL                         0x1
#define S_ATTR_SOME_INSTRUCTIONS    0x00000400
#define S_ATTR_PURE_INSTRUCTIONS    0x80000000
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

#define KMOD_MAX_NAME 64
#pragma pack(4)
typedef struct
{
    kptr_t   next;
    int32_t  info_version;
    uint32_t id;
    char     name[KMOD_MAX_NAME];
    char     version[KMOD_MAX_NAME];
    int32_t  reference_count;
    kptr_t   reference_list;
    kptr_t   address;
    kptr_t   size;
    kptr_t   hdr_size;
    kptr_t   start;
    kptr_t   stop;
} kmod_info_t;
#pragma pack()

// My aliases
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

typedef struct
{
    kptr_t addr;
    uint64_t size;
    const char *bundle;
} macho_bundle_range_t;

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
    kptr_t *fnstarts;
    size_t nfnstarts;
    const char **bundles;
    macho_bundle_range_t *bundleMap;
    size_t nbundles;
};

// High-level funcs needed during initialisation
static kptr_t macho_fixup_internal(fixup_kind_t fixupKind, kptr_t base, kptr_t ptr, bool *bind, bool *auth, uint16_t *pac, size_t *skip);
static kptr_t macho_ptov_internal(const macho_map_t *mapP, size_t nmapP, const void *ptr);
static const void* macho_vtop_internal(const macho_map_t *mapV, size_t nmapV, kptr_t addr, size_t size);
static bool macho_section_for_addr_internal(const macho_section_t *sectionsByAddr, size_t nsecs, kptr_t target, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot);
static bool macho_segment_for_addr_internal(const macho_segment_t *segmentsByAddr, size_t nsegs, kptr_t target, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot);
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

static int macho_cmp_kptr(const void *a, const void *b)
{
    return macho_cmp_u64(*(const kptr_t*)a, *(const kptr_t*)b);
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

static int macho_cmp_bundle_map(const void *a, const void *b)
{
    return macho_cmp_u64(((const macho_bundle_range_t*)a)->addr, ((const macho_bundle_range_t*)b)->addr);
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
    kptr_t *fnstarts = NULL;
    size_t nfnstarts = 0;

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
    size_t nfilesetfnstarts = 0;

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
                {
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
                }

                case LC_DYSYMTAB:
                {
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
                }

                case LC_SEGMENT_64:
                {
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
                }

                // TODO: LC_SEGMENT_SPLIT_INFO?

                case LC_FUNCTION_STARTS:
                {
                    if(cmdsize < sizeof(struct linkedit_data_command))
                    {
                        ERR("LC_FUNCTION_STARTS command too short.");
                        goto out;
                    }
                    if(filetype == MH_FILESET)
                    {
                        ERR("LC_FUNCTION_STARTS command in MH_FILESET Mach-O.");
                        goto out;
                    }
                    if(nfnstarts)
                    {
                        ERR("Multiple LC_FUNCTION_STARTS commands.");
                        goto out;
                    }
                    const struct linkedit_data_command *fndata = (const struct linkedit_data_command*)cmd;
                    if(!fndata->datasize)
                    {
                        ERR("Mach-O function starts with size zero?");
                        goto out;
                    }
                    if(fndata->dataoff > size || fndata->datasize > size - fndata->dataoff)
                    {
                        ERR("Mach-O function starts data out of bounds.");
                        goto out;
                    }
                    const uint8_t *fn = (const uint8_t*)((uintptr_t)hdr + fndata->dataoff);
                    size_t bits = 0;
                    bool end = false;
                    for(size_t k = 0; k < fndata->datasize; ++k)
                    {
                        uint8_t slice = fn[k];
                        if(bits > 63 || (bits == 63 && (slice & 0x7e) != 0))
                        {
                            ERR("Mach-O function starts overflows (offset 0x%zx).", k);
                            goto out;
                        }
                        if(bits == 0)
                        {
                            if(slice == 0)
                            {
                                end = true;
                                break;
                            }
                            if(slice & 0x3)
                            {
                                ERR("Mach-O function starts unaligned (offset 0x%zx).", k);
                                goto out;
                            }
                        }
                        bits += 7;
                        if((slice & 0x80) == 0)
                        {
                            bits = 0;
                            ++nfnstarts;
                        }
                    }
                    if(bits != 0)
                    {
                        ERR("Mach-O function starts incomplete.");
                        goto out;
                    }
                    if(!end)
                    {
                        ERR("Mach-O function starts is missing end marker.");
                        goto out;
                    }
                    if(!nfnstarts)
                    {
                        ERR("Mach-O function starts encodes zero offsets.");
                        goto out;
                    }
                    break;
                }

                case LC_DYLD_CHAINED_FIXUPS:
                {
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
                            if(imp->lib_ordinal == 0xfd) // weak lookup
                            {
                                continue;
                            }
                            if(imp->lib_ordinal != 0xfe) // flat namespace import
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
                }

                case LC_FILESET_ENTRY:
                {
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
                    const mach_hdr_t *mh = (const mach_hdr_t*)((uintptr_t)hdr + ent->fileoff);
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
                    const struct linkedit_data_command *fns = NULL;
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

                            case LC_FUNCTION_STARTS:
                                if(lcsize < sizeof(struct linkedit_data_command))
                                {
                                    ERR("Embedded LC_FUNCTION_STARTS command too short (%s).", name);
                                    goto out;
                                }
                                if(fns)
                                {
                                    ERR("Multiple embedded LC_FUNCTION_STARTS commands (%s).", name);
                                    goto out;
                                }
                                fns = (const struct linkedit_data_command*)lc;
                                if(!fns->datasize)
                                {
                                    ERR("Embedded Mach-O function starts with size zero (%s)?", name);
                                    goto out;
                                }
                                if(fns->dataoff > size || fns->datasize > size - fns->dataoff)
                                {
                                    ERR("Embedded Mach-O function starts data out of bounds (%s).", name);
                                    goto out;
                                }
                                const uint8_t *fn = (const uint8_t*)((uintptr_t)hdr + fns->dataoff);
                                size_t bits = 0;
                                bool end = false;
                                size_t nfn = 0;
                                for(size_t k = 0; k < fns->datasize; ++k)
                                {
                                    uint8_t slice = fn[k];
                                    if(bits > 63 || (bits == 63 && (slice & 0x7e) != 0))
                                    {
                                        ERR("Embedded Mach-O function starts overflows (offset 0x%zx, %s).", k, name);
                                        goto out;
                                    }
                                    if(bits == 0)
                                    {
                                        if(slice == 0)
                                        {
                                            end = true;
                                            break;
                                        }
                                        if(slice & 0x3)
                                        {
                                            ERR("Embedded Mach-O function starts unaligned (offset 0x%zx, %s).", k, name);
                                            goto out;
                                        }
                                    }
                                    bits += 7;
                                    if((slice & 0x80) == 0)
                                    {
                                        bits = 0;
                                        ++nfn;
                                    }
                                }
                                if(bits != 0)
                                {
                                    // Fleset kernelcaches between iOS 17.0 and 17.4 (exclusive) that live under SPTM had XNU's
                                    // executable segments rearranged relative to each other when creating the fileset, and the
                                    // kernelcache builder tried to update the function starts info, but didn't account for the
                                    // fact that this would need more space than before, so this can actually be truncated.
                                    // But that's better than nothing, just work with what we've got...
                                    DBG(2, "Embedded Mach-O function starts incomplete (%s).", name);
                                    //ERR("Embedded Mach-O function starts incomplete (%s).", name);
                                    //goto out;
                                }
                                else if(!end)
                                {
                                    // Some fileset kernelcaches between iOS 16.4 and 17.0 (exclusive) are lacking this end marker.
                                    // Only a few kernelcaches seem to be affected, all of them filesets, and when it happens, it seems
                                    // to affect all devices of a given SoC. I don't know why, but the info seems complete nonetheless.
                                    DBG(2, "Embedded Mach-O function starts is missing end marker (%s).", name);
                                    //ERR("Embedded Mach-O function starts is missing end marker (%s).", name);
                                    //goto out;
                                }
                                if(!nfn)
                                {
                                    ERR("Embedded Mach-O function starts encodes zero offsets (%s).", name);
                                    goto out;
                                }
                                nfnstarts += nfn;
                                ++nfilesetfnstarts;
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
                }

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
                    const mach_hdr_t *mh = (const mach_hdr_t*)((uintptr_t)hdr + ent->fileoff);
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
                    if(idx > starts->page_size) // don't subtract sizeof(kptr_t) here - see note below
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
                if(!macho_validate_fixup_chain(hdr, base, fixupKind, ptr, end, ptrBitmap, &nreloc, 0))
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
                    // TODO: parse nlocrel of kexts for even older kernelcaches (share code with macho_populate_bundles?)
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

    if(nfnstarts)
    {
        fnstarts = malloc(sizeof(kptr_t) * (nfnstarts + 1));
        if(!fnstarts)
        {
            ERRNO("malloc(fnstarts)");
            goto out;
        }

        size_t fnidx = 0;
        const mach_lc_t *cmd = firstcmd;
        for(uint32_t i = 0; i < ncmds; ++i)
        {
            const struct linkedit_data_command *fndata = NULL;
            kptr_t last = 0;
            kptr_t exec[10] = {};
            size_t nexec = 0;
            switch(cmd->cmd)
            {
                case LC_FUNCTION_STARTS:
                    fndata = (const struct linkedit_data_command*)cmd;
                    last = base;
                    break;

                case LC_FILESET_ENTRY:;
                    const mach_fileent_t *ent = (const mach_fileent_t*)cmd;
                    const mach_hdr_t *mh = (const mach_hdr_t*)((uintptr_t)hdr + ent->fileoff);
                    const mach_lc_t * const firstlc = (const mach_lc_t*)(mh + 1);
                    const mach_lc_t *lc = firstlc;
                    for(uint32_t j = 0, num = mh->ncmds; j < num; ++j)
                    {
                        switch(lc->cmd)
                        {
                            case LC_SEGMENT_64:;
                                const mach_seg_t *seg = (const mach_seg_t*)lc;
                                if(!seg->vmsize)
                                {
                                    break;
                                }
                                kptr_t vmaddr = 0;
                                if(seg->initprot & VM_PROT_EXECUTE)
                                {
                                    vmaddr = seg->vmaddr;
                                }
                                else
                                {
                                    const mach_sec_t *sec = (const mach_sec_t*)(seg + 1);
                                    for(uint32_t k = 0; k < seg->nsects; ++k)
                                    {
                                        if(!sec[k].size)
                                        {
                                            continue;
                                        }
                                        if(sec[k].flags & (S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS))
                                        {
                                            vmaddr = sec[k].addr;
                                            break;
                                        }
                                    }
                                }
                                if(vmaddr)
                                {
                                    if(nexec >= 10)
                                    {
                                        ERR("More than 10 executable segments in embedded Mach-O (%s).", (const char*)((uintptr_t)ent + ent->nameoff));
                                        goto out;
                                    }
                                    exec[nexec++] = vmaddr;
                                }
                                break;

                            case LC_FUNCTION_STARTS:
                                fndata = (const struct linkedit_data_command*)lc;
                                last = ent->vmaddr;
                                break;
                        }
                        lc = (const mach_lc_t*)((uintptr_t)lc + lc->cmdsize);
                    }
                    break;

                default:
                    break;
            }
            if(fndata)
            {
                const uint8_t *fn = (const uint8_t*)((uintptr_t)hdr + fndata->dataoff);
                size_t bits = 0;
                uint64_t off = 0;
                bool first = true;
                for(size_t k = 0; k < fndata->datasize; ++k)
                {
                    uint8_t slice = fn[k];
                    if(bits == 0 && slice == 0)
                    {
                        break;
                    }
                    off |= (uint64_t)(slice & 0x7f) << bits;
                    bits += 7;
                    if((slice & 0x80) == 0)
                    {
                        last += off;
                        off = 0;
                        bits = 0;
                        // This is a really cursed case. macOS fileset kernelcaches before macOS 13.0 did not have their
                        // function starts adjusted after XNU's segments have been rebased during kernelcachification,
                        // so they still apply to the old addresses XNU had before it was merged into the fileset.
                        // Trying to use them will break a lot of stuff, so we need to detect this case here and
                        // filter it out. It's better to have no data than to have wrong data.
                        //
                        // In the future, we may actually be able to use this data, because even though some segments are
                        // rearranged relative to each other, the only executable segment affected by this is __LAST, which
                        // does not show up in function starts because it's hand-rolled asm, not emitted by LLVM. So the
                        // targets for our function starts are still in the same linear order (unlike under SPTM), but
                        // we'd still have to come up with a way of finding the correct start address and idk how to do that yet.
                        if(first)
                        {
                            first = false;
                            if(nexec)
                            {
                                bool found = false;
                                for(size_t j = 0; j < nexec; ++j)
                                {
                                    if(last == exec[j])
                                    {
                                        found = true;
                                        break;
                                    }
                                }
                                if(!found)
                                {
                                    // Only handle this gracefully if we have a single fileset entry with funtion starts (i.e. XNU).
                                    if(nfilesetfnstarts == 1)
                                    {
                                        DBG(2, "Detected malformed function starts, skipping...");
                                        break;
                                    }
                                    else
                                    {
                                        ERR("Mach-O function starts don't match the beginning of any segment or section.");
                                        goto out;
                                    }
                                }
                            }
                        }
                        DBG(3, "Fnstart: " ADDR, last);
                        //uint32_t prot = 0;
                        if(!macho_segment_for_addr_internal(segmentsByAddr, nsegs, last, NULL, NULL, NULL, /*&prot*/ NULL))
                        {
                            ERR("Mach-O function start doesn't map to any segment (" ADDR ").", last);
                            goto out;
                        }
                        // TODO: Can't do this, because __KLD on old kernels...
                        /*if(!(prot & VM_PROT_EXECUTE))
                        {
                            ERR("Mach-O function start not in executable segment (" ADDR ").", last);
                            goto out;
                        }*/
                        fnstarts[fnidx++] = last;
                    }
                }
            }
            cmd = (const mach_lc_t*)((uintptr_t)cmd + cmd->cmdsize);
        }

        if(fnidx != nfnstarts)
        {
            // This should only be possible if we bailed out above due to the macOS 11/12 thing, and in that case we have nothing.
            if(fnidx != 0)
            {
                __builtin_trap();
            }
            free(fnstarts);
            fnstarts = NULL;
            nfnstarts = 0;
        }
        else
        {
            // Since there can be multiple chunks, it's possible that these are not in order already.
            qsort(fnstarts, nfnstarts, sizeof(kptr_t), &macho_cmp_kptr);

            // Populate one past the last element with a safe end marker, so we don't mark everything up to 0xffffffffffffffff as belonging to the last func.
            kptr_t last = fnstarts[nfnstarts - 1];
            kptr_t boundaddr = 0;
            size_t boundsize = 0;
            // Use sections for this if possible, otherwise (fileset) just do segment.
            if(!macho_section_for_addr_internal(sectionsByAddr, nsecs, last, NULL, &boundaddr, &boundsize, NULL))
            {
                // Guaranteed to succeed since it succeeded above...
                macho_segment_for_addr_internal(segmentsByAddr, nsegs, last, NULL, &boundaddr, &boundsize, NULL);
            }
            fnstarts[nfnstarts] = boundaddr + boundsize;
        }
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
    macho->fnstarts = fnstarts;
    macho->nfnstarts = nfnstarts;
    macho->bundles = NULL;
    macho->bundleMap = NULL;
    macho->nbundles = 0;

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
    fnstarts = NULL;

out:;
    if(fnstarts) free(fnstarts);
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
    if(macho->bundleMap) free(macho->bundleMap);
    if(macho->bundles) free(macho->bundles);
    if(macho->fnstarts) free(macho->fnstarts);
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

static bool macho_segment_for_addr_internal(const macho_segment_t *segmentsByAddr, size_t nsegs, kptr_t target, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot)
{
    macho_segment_t *seg = bsearch((const void*)target, segmentsByAddr, nsegs, sizeof(macho_segment_t), &macho_segment_for_addr_cb);
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

bool macho_segment_for_addr(macho_t *macho, kptr_t target, const void **ptr, kptr_t *addr, size_t *size, uint32_t *prot)
{
    return macho_segment_for_addr_internal(macho->segmentsByAddr, macho->nsegs, target, ptr, addr, size, prot);
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
    size_t len = 0;
    if(!macho_section_internal(sectionsByName, nsecs, "__PRELINK_INFO", "__info", &xml, NULL, &len, NULL))
    {
        //ERR("Failed to find PrelinkInfo");
        return NULL;
    }

    CFStringRef err = NULL;
    CFTypeRef info = IOCFUnserializeWithSize(xml, len, NULL, 0, &err);
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
    if(CFGetTypeID(info) != CFDictionaryGetTypeID())
    {
        ERR("IOCFUnserialize: wrong type");
        return NULL;
    }
    if(err)
    {
        WRN("IOCFUnserialize populated the error string but returned success???");
        CFRelease(err);
    }
    return info;
}

static CFTypeRef macho_prelink_info(macho_t *macho)
{
    if(!macho->prelinkInfo)
    {
        macho->prelinkInfo = macho_prelink_info_internal(macho->sectionsByName, macho->nsecs);
    }
    return macho->prelinkInfo;
}

static int macho_fnstart_cb(const void *a, const void *b)
{
    kptr_t key = (kptr_t)a;
    const kptr_t *ptr = (const kptr_t*)b;
    if(key < ptr[0])
    {
        return -1;
    }
    if(key >= ptr[1]) // we alloc 1 more and populate it with the end of the section, so this is ok
    {
        return 1;
    }
    return 0;
}

kptr_t macho_fnstart(macho_t *macho, kptr_t addr)
{
    if(!macho->fnstarts)
    {
        return 0;
    }
    kptr_t *ptr = bsearch((const void*)addr, macho->fnstarts, macho->nfnstarts, sizeof(kptr_t), &macho_fnstart_cb);
    return ptr ? *ptr : 0;
}

static bool macho_populate_bundles(macho_t *macho)
{
    const char **bundles = NULL;
    macho_bundle_range_t *bundleMap = NULL;
    size_t nbundles = 0;
    if(macho_is_kext(macho))
    {
        // TODO: find & parse Info.plist?
        const kmod_info_t *kmod = NULL;
        kptr_t kmod_addr = macho_symbol(macho, "_kmod_info");
        if(kmod_addr)
        {
            DBG(2, "kmod: " ADDR, kmod_addr);
            kmod = macho_vtop(macho, kmod_addr, sizeof(kmod_info_t));
        }
        if(!kmod)
        {
            ERR("Failed to find kmod_info.");
            goto bad;
        }
        bundles = malloc(sizeof(*bundles));
        if(!bundles)
        {
            ERRNO("malloc(bundles)");
            goto bad;
        }
        WRN("Using kmod_info for bundle identifier. Result may not match runtime value.");
        *bundles = kmod->name;
        nbundles = 1;
    }
    else
    {
        CFTypeRef info = macho_prelink_info(macho);
        if(!info)
        {
            bundles = malloc(sizeof(*bundles));
            if(!bundles)
            {
                ERRNO("malloc(bundles)");
                goto bad;
            }
        }
        else
        {
            const kptr_t *kmod_info_ptr = NULL;
            size_t kmod_info_size = 0;
            bool have_kmod_info = macho_section(macho, "__PRELINK_INFO", "__kmod_info", (const void**)&kmod_info_ptr, NULL, &kmod_info_size, NULL);

            const kptr_t *kmod_start_ptr = NULL;
            size_t kmod_start_size = 0;
            bool have_kmod_start = macho_section(macho, "__PRELINK_INFO", "__kmod_start", (const void**)&kmod_start_ptr, NULL, &kmod_start_size, NULL);

            if(have_kmod_info != have_kmod_start)
            {
                ERR("Mismatching presence of kmod_info/kmod_start.");
                goto bad;
            }
            bool builtin_kmod = have_kmod_info && have_kmod_start;
            if(builtin_kmod)
            {
                if(kmod_start_size != kmod_info_size + sizeof(kptr_t))
                {
                    ERR("Mismatching size of kmod_info/kmod_start.");
                    goto bad;
                }
                if(kmod_info_size % sizeof(kptr_t) != 0 || kmod_start_size % sizeof(kptr_t) != 0)
                {
                    ERR("Bad size of kmod_info/kmod_start.");
                    goto bad;
                }
            }

            CFArrayRef arr = CFDictionaryGetValue(info, CFSTR("_PrelinkInfoDictionary"));
            if(!arr || CFGetTypeID(arr) != CFArrayGetTypeID())
            {
                ERR("PrelinkInfoDictionary missing or wrong type");
                goto bad;
            }
            CFIndex arrlen = CFArrayGetCount(arr);
            bundles = malloc((arrlen + 1) * sizeof(*bundles));
            if(!bundles)
            {
                ERRNO("malloc(bundles)");
                goto bad;
            }
            bundleMap = malloc(arrlen * sizeof(*bundleMap));
            if(!bundleMap)
            {
                ERRNO("malloc(bundleMap)");
                goto bad;
            }
            for(size_t i = 0; i < arrlen; ++i)
            {
                CFDictionaryRef dict = CFArrayGetValueAtIndex(arr, i);
                if(!dict || CFGetTypeID(dict) != CFDictionaryGetTypeID())
                {
                    ERR("Array entry %lu is not a dict.", i);
                    goto bad;
                }
                CFStringRef cfbundle = CFDictionaryGetValue(dict, CFSTR("CFBundleIdentifier"));
                if(!cfbundle || CFGetTypeID(cfbundle) != CFStringGetTypeID())
                {
                    ERR("CFBundleIdentifier missing or wrong type at entry %lu.", i);
                    if(debug >= 2)
                    {
                        CFShow(dict);
                    }
                    goto bad;
                }
                const char *bundle = CFStringGetCStringPtr(cfbundle, kCFStringEncodingUTF8);
                if(!bundle)
                {
                    ERR("Failed to get CFString contents at entry %lu.", i);
                    if(debug >= 2)
                    {
                        CFShow(cfbundle);
                    }
                    goto bad;
                }
                kptr_t loadaddr = 0;
                if(builtin_kmod)
                {
                    CFNumberRef cfidx = CFDictionaryGetValue(dict, CFSTR("ModuleIndex"));
                    if(!cfidx)
                    {
                        DBG(2, "Kext %s is codeless, skipping...", bundle);
                        continue;
                    }
                    if(CFGetTypeID(cfidx) != CFNumberGetTypeID())
                    {
                        ERR("ModuleIndex has wrong type for kext %s.", bundle);
                        goto bad;
                    }
                    uint64_t idx = 0;
                    if(!CFNumberGetValue(cfidx, kCFNumberLongLongType, &idx))
                    {
                        ERR("Failed to get CFNumber contents for kext %s", bundle);
                        if(debug >= 2)
                        {
                            CFShow(cfidx);
                        }
                        goto bad;
                    }
                    if(idx >= kmod_info_size)
                    {
                        ERR("ModuleIndex out of bounds for kext %s.", bundle);
                        goto bad;
                    }
                    loadaddr = macho_fixup(macho, kmod_start_ptr[idx], NULL, NULL, NULL, NULL);
                }
                else
                {
                    CFNumberRef cfaddr = CFDictionaryGetValue(dict, CFSTR("_PrelinkExecutableLoadAddr"));
                    if(!cfaddr)
                    {
                        DBG(2, "Kext %s has no PrelinkExecutableLoadAddr, skipping...", bundle);
                        continue;
                    }
                    if(CFGetTypeID(cfaddr) != CFNumberGetTypeID())
                    {
                        ERR("PrelinkExecutableLoadAddr has wrong type for kext %s.", bundle);
                        if(debug >= 2)
                        {
                            CFShow(cfaddr);
                        }
                        goto bad;
                    }
                    if(!CFNumberGetValue(cfaddr, kCFNumberLongLongType, &loadaddr))
                    {
                        ERR("Failed to get CFNumber contents for kext %s", bundle);
                        if(debug >= 2)
                        {
                            CFShow(cfaddr);
                        }
                        goto bad;
                    }
                    if(loadaddr == 0x7fffffffffffffff)
                    {
                        DBG(2, "Kext %s is codeless, skipping...", bundle);
                        continue;
                    }
                }
                DBG(2, "Kext %s at " ADDR, bundle, loadaddr);
                const void *segptr = NULL;
                kptr_t segaddr = 0;
                size_t segsize = 0;
                if(!macho_segment_for_addr(macho, loadaddr, &segptr, &segaddr, &segsize, NULL))
                {
                    ERR("Failed to get Mach-O header for kext %s.", bundle);
                    goto bad;
                }
                size_t maxsize = segsize - (loadaddr - segaddr);
                if(maxsize < sizeof(mach_hdr_t))
                {
                    ERR("Segment size too small for Mach-O header for kext %s.", bundle);
                    goto bad;
                }
                const mach_hdr_t *mh = (const mach_hdr_t*)((uintptr_t)segptr + (loadaddr - segaddr));
                if(mh->magic != MH_MAGIC_64)
                {
                    ERR("Mach-O header for kext %s has wrong magic: 0x%08x", bundle, mh->magic);
                    goto bad;
                }
                if(mh->cputype != macho->hdr->cputype || (mh->cpusubtype & CPU_SUBTYPE_MASK) != macho->subtype)
                {
                    ERR("Mach-O header for kext %s has mismatching cputype or cpusubtype.", bundle);
                    goto bad;
                }
                if(mh->filetype != MH_KEXT_BUNDLE)
                {
                    ERR("Mach-O header for kext %s has bad type: 0x%x", bundle, mh->filetype);
                    goto bad;
                }
                if(mh->flags & MH_INCRLINK)
                {
                    DBG(2, "Kext %s has MH_INCRLINK set, skipping...", bundle);
                    continue;
                }
                if(mh->sizeofcmds > maxsize - sizeof(mach_hdr_t))
                {
                    ERR("Mach-O header for kext %s overflows segment.", bundle);
                    goto bad;
                }
                kptr_t textaddr = 0;
                uint64_t textsize = 0;
                const mach_lc_t * const firstlc = (const mach_lc_t*)(mh + 1);
                const mach_lc_t *lc = firstlc;
                for(uint32_t j = 0, num = mh->ncmds; j < num; ++j)
                {
                    size_t lcmax = mh->sizeofcmds - ((uintptr_t)lc - (uintptr_t)firstlc);
                    uint32_t lcsize;
                    if(sizeof(mach_lc_t) > lcmax || (lcsize = lc->cmdsize) > lcmax)
                    {
                        ERR("Mach-O header for kext %s load command %u out of bounds.", bundle, j);
                        goto bad;
                    }
                    if(lcsize < sizeof(mach_lc_t))
                    {
                        ERR("Mach-O header for kext %s load command %u too short.", bundle, j);
                        goto bad;
                    }
                    if(lc->cmd == LC_SEGMENT_64)
                    {
                        if(lc->cmdsize < sizeof(mach_seg_t))
                        {
                            ERR("Mach-O header for kext %s LC_SEGMENT_64 command (%u) too short.", bundle, j);
                            goto bad;
                        }
                        const mach_seg_t *seg = (const mach_seg_t*)lc;
                        // We're looking for the code segment
                        if((seg->initprot & VM_PROT_EXECUTE) != 0 && seg->vmsize && seg->filesize)
                        {
                            textaddr = macho_is_ptr(macho, &seg->vmaddr) ? macho_fixup(macho, seg->vmaddr, NULL, NULL, NULL, NULL) : seg->vmaddr;
                            textsize = seg->filesize;
                            break;
                        }
                    }
                    lc = (const mach_lc_t*)((uintptr_t)lc + lc->cmdsize);
                }
                if(!textaddr || !textsize)
                {
                    ERR("Failed to find code segment for kext %s.", bundle);
                    goto bad;
                }
                DBG(3, "Kext %s code segment: " ADDR "-" ADDR, bundle, textaddr, textaddr + textsize);
                bundles[nbundles] = bundle;
                bundleMap[nbundles].addr = textaddr;
                bundleMap[nbundles].size = textsize;
                bundleMap[nbundles].bundle = bundle;
                ++nbundles;
            }
            qsort(bundleMap, nbundles, sizeof(macho_bundle_range_t), &macho_cmp_bundle_map);
        }
        bundles[nbundles++] = "__kernel__";
    }
    macho->bundles = bundles;
    macho->bundleMap = bundleMap;
    macho->nbundles = nbundles;
    return true;
bad:;
    if(bundles) free(bundles);
    if(bundleMap) free(bundleMap);
    return false;
}

const char* const* macho_bundles(macho_t *macho, size_t *n)
{
    if(!macho->nbundles && !macho_populate_bundles(macho))
    {
        return NULL;
    }
    *n = macho->nbundles;
    return macho->bundles;
}

static int macho_bundle_for_addr_cb(const void *key, const void *value)
{
    const macho_bundle_range_t *range = value;
    if((kptr_t)key < range->addr)
    {
        return -1;
    }
    if((kptr_t)key - range->addr >= range->size)
    {
        return 1;
    }
    return 0;
}

const char* macho_bundle_for_addr(macho_t *macho, kptr_t addr)
{
    if(!macho->nbundles && !macho_populate_bundles(macho))
    {
        return NULL;
    }
    if(macho->nbundles == 1)
    {
        return macho->bundles[0];
    }
    macho_bundle_range_t *range = bsearch((const void*)addr, macho->bundleMap, macho->nbundles - 1, sizeof(macho_bundle_range_t), &macho_bundle_for_addr_cb);
    return range ? range->bundle : "__kernel__";
}
