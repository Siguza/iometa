/* Copyright (c) 2018-2020 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#if 0
How this works:

1.  First we find the OSMetaClass constructor, by finding the only function that
    is called with each "IORegistryEntry", "IOService" and "IOUserClient" in x1.
2.  Then we get all locations where that is hardcoded as a pointer (usually for imports), dubbed "refs".
3.  For all refs, we then get all locations where that pointer is loaded and jumped to, in the form:

    adrp xN, ...
    add xN, xN, ...
    br xN

    Together with the original constructor we put those in a list, dubbed "aliases".
4.  We get all places where any alias is called, seek backwards as far as we understand the instructions
    and there are no branches, and do some best-effort emulation to fill registers x0-x3.
    - If we end up with x0 missing, we skip the invocation.
    - If we end up with any of x1-x3 missing, we print a warning because that should never happen.
    - Otherwise, we get name (x1) and size (x3) of the class as well as address of the metaclass (x0) and its parent (x2).
5.  If we want vtables, we first find out at what offset OSObject::getMetaClass is in the vtable.
6.  Then we find all locations returning a metaclass address in one of two possible forms:

    adrp xN, ...
    add x0, xN, ...
    ret

    adr x0, ...
    (nop)
    ret

7.  To all of those locations we search a hardcoded pointer in the kernel.
    If we find one in an array of pointers preceded by two NULL pointers, we accept this as class vtable.
8.  If we want bundle names, we first get the kernel's __PRELINK_INFO segment and feed it to IOCFUnserialize (CoreFoundation can't handle it).
    For all entries with a _PrelinkExecutableLoadAddr, we parse the kext header and check for each metaclass
    whether its address is inside the kext's __DATA segment. If so, we set the bundle name that we can get from CFBundleIdentifier.
9.  In the case of 1469 kernels, _PrelinkExecutableLoadAddr no longer exists as kexts seems to have been compiled directly into the kernel.
    We do however get __PRELINK_INFO.__kmod_info __PRELINK_INFO.__kmod_start in their place, giving us names & mach headers. Pretty much
    everything has been removed, but the leftover __TEXT_EXEC entry is just enough to match against OSMetaClass constructor callsites.
10. Finally we do some filtering and sorting, and print our findings.
#endif

#include <errno.h>
#include <fcntl.h>              // open
#include <stdbool.h>
#include <stdint.h>             // uintptr_t
#include <stdio.h>              // fprintf, stderr
#include <stdlib.h>             // malloc, realloc, qsort, bsearch, exit
#include <string.h>             // strerror, strcmp, strstr, memcpy, memmem
#include <strings.h>            // bzero
#include <sys/mman.h>           // mmap
#include <sys/stat.h>           // fstat
#include <CoreFoundation/CoreFoundation.h>

extern CFTypeRef IOCFUnserialize(const char *buffer, CFAllocatorRef allocator, CFOptionFlags options, CFStringRef *errorString);

#include "a64.h"
#include "cxx.h"

static bool debug = false;
static const char *colorGray   = "\x1b[90m",
                  *colorRed    = "\x1b[1;91m",
                  *colorYellow = "\x1b[1;93m",
                  *colorBlue   = "\x1b[1;94m",
                  *colorPink   = "\x1b[1;95m",
                  *colorCyan   = "\x1b[1;96m",
                  *colorReset  = "\x1b[0m";

#define LOG(str, args...)   do { fprintf(stderr, str "\n", ##args); } while(0)
#define DBG(str, args...)   do { if(debug) LOG("%s[DBG] " str "%s", colorPink, ##args, colorReset); } while(0)
#define WRN(str, args...)   LOG("%s[WRN] " str "%s", colorYellow, ##args, colorReset)
#define ERR(str, args...)   LOG("%s[ERR] " str "%s", colorRed, ##args, colorReset)
#define ERRNO(str, args...) ERR(str ": %s", ##args, strerror(errno))

#define STRINGIFX(x) #x
#define STRINGIFY(x) STRINGIFX(x)

#define SWAP32(x) (((x & 0xff000000) >> 24) | ((x & 0xff0000) >> 8) | ((x & 0xff00) << 8) | ((x & 0xff) << 24))

// Apple notation
#define VM_PROT_READ                       0x1
#define VM_PROT_WRITE                      0x2
#define VM_PROT_EXECUTE                    0x4
#define CPU_TYPE_ARM64              0x0100000c
#define FAT_CIGAM                   0xbebafeca
#define MH_MAGIC_64                 0xfeedfacf
#define MH_EXECUTE                  0x00000002
#define MH_KEXT_BUNDLE              0x0000000b
#define MH_FILESET                  0x0000000c
#define LC_SYMTAB                   0x00000002
#define LC_DYSYMTAB                 0x0000000b
#define LC_SEGMENT_64               0x00000019
#define LC_UUID                     0x0000001b
#define LC_DYLD_CHAINED_FIXUPS      0x80000034
#define LC_FILESET_ENTRY            0x80000035
#define N_STAB                            0xe0
#define N_TYPE                            0x0e
#define N_EXT                             0x01
#define N_UNDF                             0x0
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

// My aliases
#define ADDR                            "0x%016llx"
#define MACH_MAGIC                      MH_MAGIC_64
#define MACH_SEGMENT                    LC_SEGMENT_64
typedef struct fat_header               fat_hdr_t;
typedef struct fat_arch                 fat_arch_t;
typedef struct mach_header_64           mach_hdr_t;
typedef struct load_command             mach_lc_t;
typedef struct segment_command_64       mach_seg_t;
typedef struct section_64               mach_sec_t;
typedef struct symtab_command           mach_stab_t;
typedef struct dysymtab_command         mach_dstab_t;
typedef struct fileset_entry_command    mach_fileent_t;
typedef struct nlist_64                 mach_nlist_t;
typedef struct relocation_info          mach_reloc_t;
typedef uint64_t                        kptr_t;

#define FOREACH_CMD(_hdr, _cmd) \
for( \
    mach_lc_t *_cmd = (mach_lc_t*)(_hdr + 1), *_end = (mach_lc_t*)((uintptr_t)_cmd + _hdr->sizeofcmds - sizeof(mach_lc_t)); \
    _cmd <= _end; \
    _cmd = (mach_lc_t*)((uintptr_t)_cmd + _cmd->cmdsize) \
)

#define STEP_MEM(_type, _mem, _addr, _size, _min) \
for(_type *_mem = (_type*)(_addr), *_end = (_type*)((uintptr_t)(_mem) + (_size)) - (_min); _mem <= _end; ++_mem)

#define ARRDECLEMPTY(type, name) \
struct \
{ \
    size_t size; \
    size_t idx; \
    type *val; \
} name; \
do \
{ \
    (name).size = 0; \
    (name).idx = 0; \
    (name).val = NULL; \
} while(0)

#define ARRDECL(type, name, sz) \
struct \
{ \
    size_t size; \
    size_t idx; \
    type *val; \
} name; \
ARRINIT(name, sz);

#define ARRINIT(name, sz) \
do \
{ \
    (name).size = (sz); \
    (name).idx = 0; \
    (name).val = malloc((name).size * sizeof(*(name).val)); \
    if(!(name).val) \
    { \
        ERRNO("malloc"); \
        exit(-1); \
    } \
} while(0)

#define ARREXPAND(name) \
do \
{ \
    if((name).size <= (name).idx) \
    { \
        (name).size *= 2; \
        (name).val = realloc((name).val, (name).size * sizeof(*(name).val)); \
        if(!(name).val) \
        { \
            ERRNO("realloc(0x%lx)", (name).size); \
            exit(-1); \
        } \
    } \
} while(0)

#define ARRNEXT(name, ptr) \
do \
{ \
    ARREXPAND((name)); \
    (ptr) = &(name).val[(name).idx++]; \
} while(0)

#define ARRPUSH(name, obj) \
do \
{ \
    ARREXPAND((name)); \
    (name).val[(name).idx++] = (obj); \
} while(0)

#define NUM_KEXTS_EXPECT         0x200
#define NUM_METACLASSES_EXPECT  0x1000

#define KMOD_MAX_NAME 64
#pragma pack(4)
typedef struct
{
    kptr_t      next;
    int32_t     info_version;
    uint32_t    id;
    char        name[KMOD_MAX_NAME];
    char        version[KMOD_MAX_NAME];
    int32_t     reference_count;
    kptr_t      reference_list;
    kptr_t      address;
    kptr_t      size;
    kptr_t      hdr_size;
    kptr_t      start;
    kptr_t      stop;
} kmod_info_t;
#pragma pack()

typedef struct
{
    uint32_t count;
    uint32_t offsetsArray[];
} kaslrPackedOffsets_t;

typedef struct
{
    // Both values inclusive
    kptr_t from;
    kptr_t to;
} relocrange_t;

typedef struct
{
    kptr_t addr;
    const char *name;
} sym_t;

typedef struct
{
    const char *class;
    const char *method;
    uint32_t structor :  1,
             reserved : 31;
} symmap_method_t;

typedef struct
{
    struct metaclass *metaclass;
    const char *name;
    symmap_method_t *methods;
    size_t num;
    uint32_t duplicate :  1,
             reserved  : 31;
} symmap_class_t;

typedef struct vtab_entry
{
    struct vtab_entry *chain; // only used for back-propagating name
    const char *class;
    const char *method;
    kptr_t addr;
    uint16_t pac;
    uint16_t structor      :  1,
             authoritative :  1,
             placeholder   :  1,
             overrides     :  1,
             reserved      : 11;
} vtab_entry_t;

typedef struct metaclass
{
    kptr_t addr;
    kptr_t parent;
    kptr_t vtab;
    kptr_t metavtab;
    kptr_t callsite;
    struct metaclass *parentP;
    symmap_class_t *symclass;
    const char *name;
    const char *bundle;
    vtab_entry_t *methods;
    size_t nmethods;
    uint32_t objsize;
    uint32_t methods_done :  1,
             methods_err  :  1,
             visited      :  1,
             duplicate    :  1,
             reserved     : 28;
} metaclass_t;

typedef struct
{
    const char *name;
    uint32_t *fncall;
} metaclass_candidate_t;

// XNU says:
#if 0
A pointer is one of:
{
    uint64_t pointerValue : 51;
    uint64_t offsetToNextPointer : 11;
    uint64_t isBind : 1 = 0;
    uint64_t authenticated : 1 = 0;
}
{
    uint32_t offsetFromSharedCacheBase;
    uint16_t diversityData;
    uint16_t hasAddressDiversity : 1;
    uint16_t hasDKey : 1;
    uint16_t hasBKey : 1;
    uint16_t offsetToNextPointer : 11;
    uint16_t isBind : 1;
    uint16_t authenticated : 1 = 1;
}
#endif

typedef union
{
    kptr_t ptr;
    struct
    {
        int64_t lo  : 51,
                hi  : 13;
    };
    struct
    {
        kptr_t off  : 32,
               pac  : 16,
               tag  :  1,
               dkey :  1,
               bkey :  1,
               next : 11,
               bind :  1,
               auth :  1;
    };
} pacptr_t;

typedef struct
{
    uint32_t bundle    :  1,
             bfilt     :  1,
             cfilt     :  1,
             bsort     :  1,
             csort     :  1,
             extend    :  1,
             inherit   :  1,
             meta      :  1,
             maxmap    :  1,
             overrides :  1,
             ofilt     :  1,
             parent    :  1,
             radare    :  1,
             size      :  1,
             symmap    :  1,
             vtab      :  1,
             _reserved : 16;
} opt_t;

static int compare_range(const void *a, const void *b)
{
    const relocrange_t *range = b;
    kptr_t ptr  = *(const kptr_t*)a,
           from = range->from,
           to   = range->to;
    if(ptr < from) return -1;
    if(ptr > to)   return  1;
    return 0;
}

static int compare_addrs(const void *a, const void *b)
{
    kptr_t adda = *(const kptr_t*)a,
           addb = *(const kptr_t*)b;
    if(adda == addb) return 0;
    return adda < addb ? -1 : 1;
}

static bool is_part_of_vtab(void *kernel, bool chainedFixup, relocrange_t *locreloc, size_t nlocreloc, char **exreloc, kptr_t exreloc_min, kptr_t exreloc_max, kptr_t *vtab, kptr_t vtabaddr, size_t idx)
{
    if(idx == 0)
    {
        return true;
    }
    if(chainedFixup)
    {
        return ((pacptr_t*)vtab)[idx - 1].next * sizeof(uint32_t) == sizeof(kptr_t);
    }
    else
    {
        kptr_t val = vtabaddr + sizeof(kptr_t) * idx;
        if(val >= exreloc_min && val < exreloc_max && exreloc[(val - exreloc_min) / sizeof(kptr_t)] != NULL)
        {
            return true;
        }
        return bsearch(&val, locreloc, nlocreloc, sizeof(*locreloc), &compare_range) != NULL;
    }
}

#define SEG_IS_EXEC(seg) (((seg)->initprot & VM_PROT_EXECUTE) || (!chainedFixup && !have_plk_text_exec && strcmp("__PRELINK_TEXT", (seg)->segname) == 0))

static kptr_t find_stub_for_reloc(void *kernel, mach_hdr_t *hdr, bool chainedFixup, bool have_plk_text_exec, char **exreloc, size_t nexreloc, kptr_t exreloc_min, const char *sym)
{
    kptr_t relocAddr = 0;
    for(size_t i = 0; i < nexreloc; ++i)
    {
        const char *name = exreloc[i];
        if(name && strcmp(name, sym) == 0)
        {
            relocAddr = i * sizeof(kptr_t) + exreloc_min;
            DBG("Found reloc for %s at " ADDR, sym, relocAddr);
            break;
        }
    }
    if(relocAddr)
    {
        FOREACH_CMD(hdr, cmd)
        {
            if(cmd->cmd == MACH_SEGMENT)
            {
                mach_seg_t *seg = (mach_seg_t*)cmd;
                if(seg->filesize > 0 && SEG_IS_EXEC(seg))
                {
                    STEP_MEM(uint32_t, mem, (uintptr_t)kernel + seg->fileoff, seg->filesize, 3)
                    {
                        adr_t *adrp = (adr_t*)mem;
                        ldr_imm_uoff_t *ldr = (ldr_imm_uoff_t*)(mem + 1);
                        br_t *br = (br_t*)(mem + 2);
                        if
                        (
                            is_adrp(adrp) && is_ldr_imm_uoff(ldr) && ldr->sf == 1 && is_br(br) &&   // Types
                            adrp->Rd == ldr->Rn && ldr->Rt == br->Rn                                // Registers
                        )
                        {
                            kptr_t alias = seg->vmaddr + ((uintptr_t)adrp - ((uintptr_t)kernel + seg->fileoff));
                            kptr_t addr = alias & ~0xfff;
                            addr += get_adr_off(adrp);
                            addr += get_ldr_imm_uoff(ldr);
                            if(addr == relocAddr)
                            {
                                return alias;
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}

static kptr_t kuntag(kptr_t kbase, bool chainedFixup, kptr_t ptr, uint16_t *pac)
{
    pacptr_t pp;
    pp.ptr = ptr;
    if(chainedFixup)
    {
        if(pp.auth)
        {
            if(pac) *pac = pp.tag ? pp.pac : 0;
            return kbase + pp.off;
        }
        pp.ptr = (kptr_t)pp.lo;
    }
    if(pac) *pac = 0;
    return pp.ptr;
}

static kptr_t off2addr(void *kernel, size_t off)
{
    FOREACH_CMD(((mach_hdr_t*)kernel), cmd)
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
    ERR("Failed to translate kernel offset 0x%lx", off);
    exit(-1);
}

static void* addr2ptr(void *kernel, kptr_t addr)
{
    FOREACH_CMD(((mach_hdr_t*)kernel), cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            if(addr >= seg->vmaddr && addr < seg->vmaddr + seg->vmsize)
            {
                return (void*)((uintptr_t)kernel + seg->fileoff + (addr - seg->vmaddr));
            }
        }
    }
    return NULL;
}

static mach_seg_t* seg4ptr(void *kernel, void *ptr)
{
    char *p = ptr;
    FOREACH_CMD(((mach_hdr_t*)kernel), cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            if(p >= (char*)((uintptr_t)kernel + seg->fileoff) && p < (char*)((uintptr_t)kernel + seg->fileoff + seg->vmsize))
            {
                return seg;
            }
        }
    }
    ERR("Failed to find segment for ptr 0x%llx", (uint64_t)ptr);
    exit(-1);
}

static void find_str(void *kernel, size_t kernelsize, void *arg, const char *str)
{
    struct
    {
        size_t size;
        size_t idx;
        kptr_t *val;
    } *arr = arg;
    size_t len = strlen(str) + 1;
    for(size_t off = 0; off < kernelsize; )
    {
        const char *ptr = memmem((void*)((uintptr_t)kernel + off), kernelsize - off, str, len);
        if(!ptr)
        {
            break;
        }
        size_t diff = (uintptr_t)ptr - (uintptr_t)kernel;
        kptr_t ref = off2addr(kernel, diff);
        DBG("strref(%s): " ADDR, str, ref);
        ARRPUSH(*arr, ref);
        off = diff + len;
    }
}

static void find_imports(void *kernel, size_t kernelsize, mach_hdr_t *hdr, kptr_t kbase, bool chainedFixup, bool have_plk_text_exec, void *arr, kptr_t func)
{
    if(hdr->filetype != MH_KEXT_BUNDLE)
    {
        ARRDECL(kptr_t, refs, NUM_KEXTS_EXPECT);
        struct
        {
            size_t size;
            size_t idx;
            kptr_t *val;
        } *aliases = arr;
        for(kptr_t *mem = kernel, *end = (kptr_t*)((uintptr_t)kernel + kernelsize); mem < end; ++mem)
        {
            if(kuntag(kbase, chainedFixup, *mem, NULL) == func)
            {
                kptr_t ref = off2addr(kernel, (uintptr_t)mem - (uintptr_t)kernel);
                DBG("ref: " ADDR, ref);
                ARRPUSH(refs, ref);
            }
        }
        FOREACH_CMD(hdr, cmd)
        {
            if(cmd->cmd == MACH_SEGMENT)
            {
                mach_seg_t *seg = (mach_seg_t*)cmd;
                if(seg->filesize > 0 && SEG_IS_EXEC(seg))
                {
                    STEP_MEM(uint32_t, mem, (uintptr_t)kernel + seg->fileoff, seg->filesize, 3)
                    {
                        adr_t *adrp = (adr_t*)mem;
                        ldr_imm_uoff_t *ldr = (ldr_imm_uoff_t*)(mem + 1);
                        br_t *br = (br_t*)(mem + 2);
                        if
                        (
                            is_adrp(adrp) && is_ldr_imm_uoff(ldr) && ldr->sf == 1 && is_br(br) &&   // Types
                            adrp->Rd == ldr->Rn && ldr->Rt == br->Rn                                // Registers
                        )
                        {
                            kptr_t alias = seg->vmaddr + ((uintptr_t)adrp - ((uintptr_t)kernel + seg->fileoff));
                            kptr_t addr = alias & ~0xfff;
                            addr += get_adr_off(adrp);
                            addr += get_ldr_imm_uoff(ldr);
                            for(size_t i = 0; i < refs.idx; ++i)
                            {
                                if(addr == refs.val[i])
                                {
                                    DBG("alias: " ADDR, alias);
                                    ARRPUSH(*aliases, alias);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        free(refs.val);
    }
}

static bool is_linear_inst(void *ptr)
{
    return is_adr(ptr) ||
           is_adrp(ptr) ||
           is_add_imm(ptr) ||
           is_sub_imm(ptr) ||
           is_add_reg(ptr) ||
           is_sub_reg(ptr) ||
           is_ldr_imm_uoff(ptr) ||
           is_ldr_lit(ptr) ||
           is_ldp_pre(ptr) ||
           is_ldp_post(ptr) ||
           is_ldp_uoff(ptr) ||
           is_ldxr(ptr) ||
           is_ldadd(ptr) ||
           is_ldur(ptr) ||
           is_ldr_fp_uoff(ptr) ||
           is_bl(ptr) ||
           is_mov(ptr) ||
           is_movz(ptr) ||
           is_movk(ptr) ||
           is_movn(ptr) ||
           is_movi(ptr) ||
           is_orr(ptr) ||
           is_str_pre(ptr) ||
           is_str_post(ptr) ||
           is_str_uoff(ptr) ||
           is_stp_pre(ptr) ||
           is_stp_post(ptr) ||
           is_stp_uoff(ptr) ||
           is_stxr(ptr) ||
           is_stur(ptr) ||
           is_str_fp_uoff(ptr) ||
           //is_stp_fp_uoff(ptr) ||
           is_ldrb_imm_uoff(ptr) ||
           is_ldrh_imm_uoff(ptr) ||
           is_ldrsb_imm_uoff(ptr) ||
           is_ldrsh_imm_uoff(ptr) ||
           is_ldrsw_imm_uoff(ptr) ||
           is_strb_imm_uoff(ptr) ||
           is_strh_imm_uoff(ptr) ||
           is_pac(ptr) ||
           is_pacsys(ptr) ||
           is_pacga(ptr) ||
           is_aut(ptr) ||
           is_autsys(ptr) ||
           is_nop(ptr);
    // TODO: some floating point instrs (see 10.3.3 kernel)
}

typedef struct
{
    uint64_t x[32];
    __uint128_t q[32];
    uint32_t valid;
    uint32_t qvalid;
    uint32_t wide;
    uint32_t host;
} a64_state_t;

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

#define SPSIZE 0x1000

static bool check_equal(uint32_t *pos, void *arg)
{
    return pos != (uint32_t*)arg;
}

static bool check_bl(uint32_t *pos, void *arg)
{
    if(is_bl((bl_t*)pos))
    {
        *(uint32_t**)arg = pos;
        return false;
    }
    return true;
}

// Best-effort emulation: halt on unknown instructions, keep track of which registers
// hold known values and only operate on those. Ignore non-static memory unless
// it is specifically marked as "host memory".
static emu_ret_t a64_emulate(void *kernel, a64_state_t *state, uint32_t *from, bool (*check)(uint32_t*, void*), void *arg, bool init, bool warnUnknown, emu_fn_behaviour_t fn_behaviour)
{
    if(init)
    {
        for(size_t i = 0; i < 32; ++i)
        {
            state->x[i] = 0;
            state->q[i] = 0;
        }
        state->valid = 0;
        state->wide = 0;
        state->host = 0;
    }
    for(; check(from, arg); ++from)
    {
        void *ptr = from;
        kptr_t addr = off2addr(kernel, (uintptr_t)from - (uintptr_t)kernel);
        if(is_nop(ptr) /*|| is_stp_fp_uoff(ptr)*/ || is_pac(ptr) || is_pacsys(ptr) || is_pacga(ptr) || is_aut(ptr) || is_autsys(ptr))
        {
            // Ignore/no change
        }
        else if(is_str_pre(ptr) || is_str_post(ptr))
        {
            str_imm_t *str = ptr;
            if(state->valid & (1 << str->Rn)) // Only if valid
            {
                kptr_t staddr = state->x[str->Rn] + get_str_imm(str);
                if(is_str_pre(str))
                {
                    state->x[str->Rn] = staddr;
                }
                else if(is_str_post(str))
                {
                    kptr_t tmp = state->x[str->Rn];
                    state->x[str->Rn] = staddr;
                    staddr = tmp;
                }
                if(state->host & (1 << str->Rn))
                {
                    if(!(state->valid & (1 << str->Rt)))
                    {
                        if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                        else            DBG("Cannot store invalid value to host mem at " ADDR, addr);
                        return kEmuUnknown;
                    }
                    if(str->sf)
                    {
                        *(uint64_t*)staddr = state->x[str->Rt];
                    }
                    else
                    {
                        *(uint32_t*)staddr = (uint32_t)state->x[str->Rt];
                    }
                }
            }
        }
        else if(is_str_uoff(ptr) || is_stur(ptr) || is_strb_imm_uoff(ptr) || is_strh_imm_uoff(ptr))
        {
            uint32_t Rt, Rn, size;
            int64_t off;
            if(is_str_uoff(ptr))
            {
                str_uoff_t *str = ptr;
                Rt = str->Rt;
                Rn = str->Rn;
                size = 4 << str->sf;
                off = get_str_uoff(str);
            }
            else if(is_stur(ptr))
            {
                stur_t *stur = ptr;
                Rt = stur->Rt;
                Rn = stur->Rn;
                size = 4 << stur->sf;
                off = get_stur_off(stur);
            }
            else if(is_strb_imm_uoff(ptr))
            {
                strb_imm_uoff_t *strb = ptr;
                Rt = strb->Rt;
                Rn = strb->Rn;
                size = 1;
                off = get_strb_imm_uoff(strb);
            }
            else if(is_strh_imm_uoff(ptr))
            {
                strh_imm_uoff_t *strh = ptr;
                Rt = strh->Rt;
                Rn = strh->Rn;
                size = 2;
                off = get_strh_imm_uoff(strh);
            }
            else
            {
                return kEmuErr;
            }
            if((state->valid & (1 << Rn)) && (state->host & (1 << Rn)))
            {
                if(!(state->valid & (1 << Rt)))
                {
                    if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                    else            DBG("Cannot store invalid value to host mem at " ADDR, addr);
                    return kEmuUnknown;
                }
                kptr_t staddr = state->x[Rn] + off;
                switch(size)
                {
                    case 1: *(uint8_t *)staddr = (uint8_t )state->x[Rt]; break;
                    case 2: *(uint16_t*)staddr = (uint16_t)state->x[Rt]; break;
                    case 4: *(uint32_t*)staddr = (uint32_t)state->x[Rt]; break;
                    case 8: *(uint64_t*)staddr = (uint64_t)state->x[Rt]; break;
                    default:
                        ERR("Bug in a64_emulate: str_uoff with invalid size at " ADDR, addr);
                        exit(-1);
                }
            }
        }
        else if(is_stp_pre(ptr) || is_stp_post(ptr) || is_stp_uoff(ptr))
        {
            stp_t *stp = ptr;
            if(state->valid & (1 << stp->Rn)) // Only if valid
            {
                kptr_t staddr = state->x[stp->Rn] + get_stp_off(stp);
                if(is_stp_pre(stp))
                {
                    state->x[stp->Rn] = staddr;
                }
                else if(is_stp_post(stp))
                {
                    kptr_t tmp = state->x[stp->Rn];
                    state->x[stp->Rn] = staddr;
                    staddr = tmp;
                }
                if(state->host & (1 << stp->Rn))
                {
                    if(!(state->valid & (1 << stp->Rt)) || !(state->valid & (1 << stp->Rt2)))
                    {
                        if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                        else            DBG("Cannot store invalid value to host mem at " ADDR, addr);
                        return kEmuUnknown;
                    }
                    if(stp->sf)
                    {
                        uint64_t *p = (uint64_t*)staddr;
                        p[0] = state->x[stp->Rt];
                        p[1] = state->x[stp->Rt2];
                    }
                    else
                    {
                        uint32_t *p = (uint32_t*)staddr;
                        p[0] = (uint32_t)state->x[stp->Rt];
                        p[1] = (uint32_t)state->x[stp->Rt2];
                    }
                }
            }
        }
        else if(is_stxr(ptr))
        {
            stxr_t *stxr = ptr;
            // Always set success
            state->x[stxr->Rs] = 0;
            state->valid  |= 1 << stxr->Rs;
            state->wide &= ~(1 << stxr->Rs);
            state->host &= ~(1 << stxr->Rs);
            if((state->valid & (1 << stxr->Rn)) && (state->host & (1 << stxr->Rn))) // Only if valid & host
            {
                if(!(state->valid & (1 << stxr->Rt)))
                {
                    if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                    else            DBG("Cannot store invalid value to host mem at " ADDR, addr);
                    return kEmuUnknown;
                }
                kptr_t staddr = state->x[stxr->Rn];
                if(stxr->sf)
                {
                    *(uint64_t*)staddr = state->x[stxr->Rt];
                }
                else
                {
                    *(uint32_t*)staddr = (uint32_t)state->x[stxr->Rt];
                }
            }
        }
        else if(is_adr(ptr) || is_adrp(ptr))
        {
            adr_t *adr = ptr;
            state->x[adr->Rd] = (adr->op1 ? (addr & ~0xfff) : addr) + get_adr_off(adr);
            state->valid |=   1 << adr->Rd;
            state->wide  |=   1 << adr->Rd;
            state->host  &= ~(1 << adr->Rd);
        }
        else if(is_add_imm(ptr) || is_sub_imm(ptr))
        {
            add_imm_t *add = ptr;
            if(!(state->valid & (1 << add->Rn))) // Unset validity
            {
                state->valid &= ~(1 << add->Rd);
            }
            else
            {
                state->x[add->Rd] = state->x[add->Rn] + (is_add_imm(add) ? 1LL : -1LL) * get_add_sub_imm(add);
                state->valid |= 1 << add->Rd;
                state->wide = (state->wide & ~(1 << add->Rd)) | (add->sf << add->Rd);
                state->host = (state->host & ~(1 << add->Rd)) | (((state->host >> add->Rn) & 0x1) << add->Rd);
            }
        }
        else if(is_add_reg(ptr) || is_sub_reg(ptr))
        {
            add_reg_t *add = ptr;
            if(!(state->valid & (1 << add->Rn)) || !(state->valid & (1 << add->Rm))) // Unset validity
            {
                state->valid &= ~(1 << add->Rd);
            }
            else
            {
                uint64_t Rm = state->x[add->Rm];
                switch(add->shift)
                {
                    case 0b00: Rm =          Rm << add->imm; break; // LSL
                    case 0b01: Rm =          Rm >> add->imm; break; // LSR
                    case 0b10: Rm = (int64_t)Rm >> add->imm; break; // ASR
                    default:
                        WRN("Bad add/sub shift at " ADDR, addr);
                        return kEmuErr;
                }
                uint64_t Rd;
                if(is_add_reg(add))
                {
                    Rd = state->x[add->Rn] + Rm;
                }
                else
                {
                    Rd = state->x[add->Rn] - Rm;
                }
                state->x[add->Rd] = add->sf ? Rd : (Rd & 0xffffffffULL);
                state->valid |= 1 << add->Rd;
                state->wide = (state->wide & ~(1 << add->Rd)) | (add->sf << add->Rd);
                // Weird case: we only wanna keep the host flag if exactly one of the source registers has it.
                // If both have it, something's gone wrong, but we wanna be able to add immediates that are loaded into a register.
                state->host = (state->host & ~(1 << add->Rd)) | ((((state->host >> add->Rn) & 0x1) ^ ((state->host >> add->Rm) & 0x1)) << add->Rd);
            }
        }
        else if(is_ldr_imm_uoff(ptr) || is_ldur(ptr) || is_ldrb_imm_uoff(ptr) || is_ldrh_imm_uoff(ptr) || is_ldrsb_imm_uoff(ptr) || is_ldrsh_imm_uoff(ptr) || is_ldrsw_imm_uoff(ptr))
        {
            bool sign = false;
            uint32_t Rt, Rn, sf, size;
            int64_t off;
            if(is_ldr_imm_uoff(ptr))
            {
                ldr_imm_uoff_t *ldr = ptr;
                Rt = ldr->Rt;
                Rn = ldr->Rn;
                sf = ldr->sf;
                size = 4 << ldr->sf;
                off = get_ldr_imm_uoff(ldr);
            }
            else if(is_ldur(ptr))
            {
                ldur_t *ldur = ptr;
                Rt = ldur->Rt;
                Rn = ldur->Rn;
                sf = ldur->sf;
                size = 4 << ldur->sf;
                off = get_ldur_off(ldur);
            }
            else if(is_ldrb_imm_uoff(ptr))
            {
                ldrb_imm_uoff_t *ldrb = ptr;
                Rt = ldrb->Rt;
                Rn = ldrb->Rn;
                sf = 0;
                size = 1;
                off = get_ldrb_imm_uoff(ldrb);
            }
            else if(is_ldrh_imm_uoff(ptr))
            {
                ldrh_imm_uoff_t *ldrh = ptr;
                Rt = ldrh->Rt;
                Rn = ldrh->Rn;
                sf = 0;
                size = 2;
                off = get_ldrh_imm_uoff(ldrh);
            }
            else if(is_ldrsb_imm_uoff(ptr))
            {
                ldrsb_imm_uoff_t *ldrsb = ptr;
                Rt = ldrsb->Rt;
                Rn = ldrsb->Rn;
                sf = ldrsb->sf;
                size = 1;
                off = get_ldrsb_imm_uoff(ldrsb);
                sign = true;
            }
            else if(is_ldrsh_imm_uoff(ptr))
            {
                ldrsh_imm_uoff_t *ldrsh = ptr;
                Rt = ldrsh->Rt;
                Rn = ldrsh->Rn;
                sf = ldrsh->sf;
                size = 2;
                off = get_ldrsh_imm_uoff(ldrsh);
                sign = true;
            }
            else if(is_ldrsw_imm_uoff(ptr))
            {
                ldrsw_imm_uoff_t *ldrsw = ptr;
                Rt = ldrsw->Rt;
                Rn = ldrsw->Rn;
                sf = 1;
                size = 4;
                off = get_ldrsw_imm_uoff(ldrsw);
                sign = true;
            }
            else
            {
                return kEmuErr;
            }
            if(!(state->valid & (1 << Rn))) // Unset validity
            {
                state->valid &= ~(1 << Rt);
            }
            else
            {
                kptr_t laddr = state->x[Rn] + off;
                void *ldr_addr = (state->host & (1 << Rn)) ? (void*)laddr : addr2ptr(kernel, laddr);
                if(!ldr_addr)
                {
                    return kEmuErr;
                }
                uint64_t val;
                switch(size)
                {
                    case 1: val = *(uint8_t *)ldr_addr; break;
                    case 2: val = *(uint16_t*)ldr_addr; break;
                    case 4: val = *(uint32_t*)ldr_addr; break;
                    case 8: val = *(uint64_t*)ldr_addr; break;
                    default:
                        ERR("Bug in a64_emulate: ldr_uoff with invalid size at " ADDR, addr);
                        exit(-1);
                }
                if(sign)
                {
                    switch(size)
                    {
                        case 1: val = ((int64_t)val << 56) >> 56; break;
                        case 2: val = ((int64_t)val << 48) >> 48; break;
                        case 4: val = ((int64_t)val << 32) >> 32; break;
                        default:
                            ERR("Bug in a64_emulate: ldr_uoff with invalid signed size at " ADDR, addr);
                            exit(-1);
                    }
                    if(!sf)
                    {
                        val &= 0xffffffff;
                    }
                }
                state->x[Rt] = val;
                state->valid |= 1 << Rt;
                state->wide = (state->wide & ~(1 << Rt)) | (sf << Rt);
                state->host &= ~(1 << Rt);
            }
        }
        else if(is_ldr_lit(ptr))
        {
            ldr_lit_t *ldr = ptr;
            void *ldr_addr = addr2ptr(kernel, addr + get_ldr_lit_off(ldr));
            if(!ldr_addr)
            {
                return kEmuErr;
            }
            state->x[ldr->Rt] = *(kptr_t*)ldr_addr;
            state->valid |= 1 << ldr->Rt;
            state->wide = (state->wide & ~(1 << ldr->Rt)) | (ldr->sf << ldr->Rt);
            state->host &= ~(1 << ldr->Rt);
        }
        else if(is_ldp_pre(ptr) || is_ldp_post(ptr) || is_ldp_uoff(ptr))
        {
            ldp_t *ldp = ptr;
            if(!(state->valid & (1 << ldp->Rn))) // Unset validity
            {
                state->valid &= ~((1 << ldp->Rt) | (1 << ldp->Rt2));
            }
            else
            {
                kptr_t laddr = state->x[ldp->Rn] + get_ldp_off(ldp);
                if(is_ldp_pre(ldp))
                {
                    state->x[ldp->Rn] = laddr;
                }
                else if(is_ldp_post(ldp))
                {
                    kptr_t tmp = state->x[ldp->Rn];
                    state->x[ldp->Rn] = laddr;
                    laddr = tmp;
                }
                void *ldr_addr = (state->host & (1 << ldp->Rn)) ? (void*)laddr : addr2ptr(kernel, laddr);
                if(!ldr_addr)
                {
                    return kEmuErr;
                }
                if(ldp->sf)
                {
                    uint64_t *p = ldr_addr;
                    state->x[ldp->Rt]  = p[0];
                    state->x[ldp->Rt2] = p[1];
                }
                else
                {
                    uint32_t *p = ldr_addr;
                    state->x[ldp->Rt]  = p[0];
                    state->x[ldp->Rt2] = p[1];
                }
                state->valid |= (1 << ldp->Rt) | (1 << ldp->Rt2);
                state->wide = (state->wide & ~((1 << ldp->Rt) | (1 << ldp->Rt2))) | (ldp->sf << ldp->Rt) | (ldp->sf << ldp->Rt2);
                state->host &= ~((1 << ldp->Rt) | (1 << ldp->Rt2));
            }
        }
        else if(is_ldxr(ptr))
        {
            ldxr_t *ldxr = ptr;
            if(!(state->valid & (1 << ldxr->Rn))) // Unset validity
            {
                state->valid &= ~(1 << ldxr->Rt);
            }
            else
            {
                kptr_t laddr = state->x[ldxr->Rn];
                void *ldr_addr = (state->host & (1 << ldxr->Rn)) ? (void*)laddr : addr2ptr(kernel, laddr);
                if(!ldr_addr)
                {
                    return kEmuErr;
                }
                state->x[ldxr->Rt] = *(kptr_t*)ldr_addr;
                state->valid |= 1 << ldxr->Rt;
                state->wide = (state->wide & ~(1 << ldxr->Rt)) | (ldxr->sf << ldxr->Rt);
                state->host &= ~(1 << ldxr->Rt);
            }
        }
        else if(is_ldadd(ptr))
        {
            ldadd_t *ldadd = ptr;
            if(!(state->valid & (1 << ldadd->Rn))) // Unset validity
            {
                if(ldadd->Rt != 31)
                {
                    state->valid &= ~(1 << ldadd->Rt);
                }
            }
            else
            {
                kptr_t daddr = state->x[ldadd->Rn];
                void *ld_addr = (state->host & (1 << ldadd->Rn)) ? (void*)daddr : addr2ptr(kernel, daddr);
                if(!ld_addr)
                {
                    return kEmuErr;
                }
                kptr_t val = *(kptr_t*)ld_addr;
                if(ldadd->Rt != 31)
                {
                    state->x[ldadd->Rt] = val;
                    state->valid |= 1 << ldadd->Rt;
                    state->wide = (state->wide & ~(1 << ldadd->Rt)) | (ldadd->sf << ldadd->Rt);
                    state->host &= ~(1 << ldadd->Rt);
                }
                if((state->host & (1 << ldadd->Rn)))
                {
                    if(!(state->valid & (1 << ldadd->Rs)))
                    {
                        if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                        else            DBG("Cannot store invalid value to host mem at " ADDR, addr);
                        return kEmuUnknown;
                    }
                    val += state->x[ldadd->Rs];
                    if(ldadd->sf)
                    {
                        *(uint64_t*)ld_addr = val;
                    }
                    else
                    {
                        *(uint32_t*)ld_addr = (uint32_t)val;
                    }
                }
            }
        }
        else if(is_ldr_fp_uoff(ptr))
        {
            str_fp_uoff_t *ldr = ptr;
            if(!(state->valid & (1 << ldr->Rn))) // Unset validity
            {
                state->qvalid &= ~(1 << ldr->Rt);
            }
            else
            {
                kptr_t laddr = state->x[ldr->Rn] + get_fp_uoff(ldr);
                void *ldr_addr = (state->host & (1 << ldr->Rn)) ? (void*)laddr : addr2ptr(kernel, laddr);
                if(!ldr_addr)
                {
                    return kEmuErr;
                }
                switch(get_fp_uoff_size(ldr))
                {
                    case 0: state->q[ldr->Rt] = *(uint8_t    *)ldr_addr; break;
                    case 1: state->q[ldr->Rt] = *(uint16_t   *)ldr_addr; break;
                    case 2: state->q[ldr->Rt] = *(uint32_t   *)ldr_addr; break;
                    case 3: state->q[ldr->Rt] = *(uint64_t   *)ldr_addr; break;
                    case 4: state->q[ldr->Rt] = *(__uint128_t*)ldr_addr; break;
                    default:
                        WRN("SIMD ldr with invalid size at " ADDR, addr);
                        return kEmuErr;
                }
                state->qvalid |= 1 << ldr->Rt;
            }
        }
        else if(is_str_fp_uoff(ptr))
        {
            str_fp_uoff_t *str = ptr;
            if((state->valid & (1 << str->Rn)) && (state->host & (1 << str->Rn)))
            {
                if(!(state->qvalid & (1 << str->Rt)))
                {
                    if(warnUnknown) WRN("Cannot store invalid value to host mem at " ADDR, addr);
                    else            DBG("Cannot store invalid value to host mem at " ADDR, addr);
                    return kEmuUnknown;
                }
                kptr_t staddr = state->x[str->Rn] + get_fp_uoff(str);
                switch(get_fp_uoff_size(str))
                {
                    case 0: *(uint8_t    *)staddr = (uint8_t )state->q[str->Rt]; break;
                    case 1: *(uint16_t   *)staddr = (uint16_t)state->q[str->Rt]; break;
                    case 2: *(uint32_t   *)staddr = (uint32_t)state->q[str->Rt]; break;
                    case 3: *(uint64_t   *)staddr = (uint64_t)state->q[str->Rt]; break;
                    case 4: *(__uint128_t*)staddr =           state->q[str->Rt]; break;
                    default:
                        WRN("SIMD str with invalid size at " ADDR, addr);
                        return kEmuErr;
                }
            }
        }
        else if(is_bl(ptr))
        {
            if(fn_behaviour == kEmuFnEnter)
            {
                state->x[30] = addr + 4;
                state->valid |=   1 << 30;
                state->wide  |=   1 << 30;
                state->host  &= ~(1 << 30);
                from = (uint32_t*)((uintptr_t)from + get_bl_off(ptr));
                --from;
            }
            else
            {
                state->valid &= ~0x4003fffe;
                if(fn_behaviour != kEmuFnAssumeX0 || !((state->valid & 0x1) && (state->host & 0x1)))
                {
                    state->valid &= ~0x1;
                }
                state->qvalid &= 0xff00; // blindly assuming 128bit shit is handled as needed
            }
        }
        else if(is_mov(ptr))
        {
            mov_t *mov = ptr;
            if(!(state->valid & (1 << mov->Rm))) // Unset validity
            {
                state->valid &= ~(1 << mov->Rd);
            }
            else
            {
                state->x[mov->Rd] = state->x[mov->Rm];
                state->valid |= 1 << mov->Rd;
                state->wide = (state->wide & ~(1 << mov->Rd)) | (((state->wide >> mov->Rm) & 0x1 & mov->sf) << mov->Rd);
                state->host = (state->host & ~(1 << mov->Rd)) | (((state->host >> mov->Rm) & 0x1) << mov->Rd);
            }
        }
        else if(is_movz(ptr))
        {
            movz_t *movz = ptr;
            state->x[movz->Rd] = get_movzk_imm(movz);
            state->valid |= 1 << movz->Rd;
            state->wide = (state->wide & ~(1 << movz->Rd)) | (movz->sf << movz->Rd);
            state->host &= ~(1 << movz->Rd);
        }
        else if(is_movk(ptr))
        {
            movk_t *movk = ptr;
            if(state->valid & (1 << movk->Rd)) // Only if valid
            {
                state->x[movk->Rd] = (state->x[movk->Rd] & ~(0xffff << (movk->hw << 4))) | get_movzk_imm(movk);
                state->valid |= 1 << movk->Rd;
                state->wide = (state->wide & ~(1 << movk->Rd)) | (movk->sf << movk->Rd);
                state->host &= ~(1 << movk->Rd);
            }
        }
        else if(is_movn(ptr))
        {
            movn_t *movn = ptr;
            state->x[movn->Rd] = get_movn_imm(movn);
            state->valid |= 1 << movn->Rd;
            state->wide = (state->wide & ~(1 << movn->Rd)) | (movn->sf << movn->Rd);
            state->host &= ~(1 << movn->Rd);
        }
        else if(is_movi(ptr))
        {
            movi_t *movi = ptr;
            state->q[movi->Rd] = get_movi_imm(movi);
            state->qvalid |= 1 << movi->Rd;
        }
        else if(is_orr(ptr))
        {
            orr_t *orr = ptr;
            if(orr->Rn == 31 || (state->valid & (1 << orr->Rn)))
            {
                state->x[orr->Rd] = (orr->Rn == 31 ? 0 : state->x[orr->Rn]) | get_orr_imm(orr);
                state->valid |= 1 << orr->Rd;
                state->wide = (state->wide & ~(1 << orr->Rd)) | (orr->sf << orr->Rd);
                state->host &= ~(1 << orr->Rd);
            }
            else
            {
                state->valid &= ~(1 << orr->Rd);
            }
        }
        else if(is_b(ptr))
        {
            from = (uint32_t*)((uintptr_t)from + get_bl_off(ptr));
            --from;
        }
        else if(is_cbz(ptr) || is_cbnz(ptr))
        {
            cbz_t *cbz = ptr;
            if(!(state->valid & (1 << cbz->Rt)))
            {
                if(warnUnknown) WRN("Cannot decide cbz/cbnz at " ADDR, addr);
                else            DBG("Cannot decide cbz/cbnz at " ADDR, addr);
                return kEmuUnknown;
            }
            if((state->x[cbz->Rt] == 0) == is_cbz(cbz))
            {
                from = (uint32_t*)((uintptr_t)from + get_cbz_off(cbz));
                --from;
            }
        }
        else if(is_tbz(ptr) || is_tbnz(ptr))
        {
            tbz_t *tbz = ptr;
            uint32_t bit = get_tbz_bit(tbz);
            if(!(state->valid & (1 << tbz->Rt)) || (bit >= 32 && !(state->wide & (1 << tbz->Rt))))
            {
                if(warnUnknown) WRN("Cannot decide tbz/tbnz at " ADDR, addr);
                else            DBG("Cannot decide tbz/tbnz at " ADDR, addr);
                return kEmuUnknown;
            }
            if(((state->x[tbz->Rt] & (1 << bit)) == 0) == is_tbz(tbz))
            {
                from = (uint32_t*)((uintptr_t)from + get_tbz_off(tbz));
                --from;
            }
        }
        else if(is_ret(ptr))
        {
            if(fn_behaviour == kEmuFnEnter)
            {
                if(!(state->valid & (1 << 30)) || !(state->wide & (1 << 30)))
                {
                    if(warnUnknown) WRN("Cannot return at " ADDR, addr);
                    else            DBG("Cannot return at " ADDR, addr);
                    return kEmuUnknown;
                }
                if(state->host & (1 << 30))
                {
                    WRN("Cannot return to host address at " ADDR, addr);
                    return kEmuErr;
                }
                // This is really dirty, but... whatcha gonna do?
                if(state->x[30] != 0)
                {
                    from = addr2ptr(kernel, state->x[30]);
                    --from;
                    continue;
                }
            }
            return kEmuRet;
        }
        else
        {
            WRN("Unexpected instruction at " ADDR, addr);
            return kEmuErr;
        }
    }
    return kEmuEnd;
}

static uint32_t* find_function_start(void *kernel, mach_seg_t *seg, const char *name, uint32_t *fnstart, bool have_stack_frame)
{
    while(1)
    {
        --fnstart;
        if(fnstart < (uint32_t*)((uintptr_t)kernel + seg->fileoff))
        {
            // If we expect a stack frame, this is fatal.
            if(have_stack_frame)
            {
                WRN("Hit start of segment at " ADDR " for %s", seg->vmaddr + ((uintptr_t)fnstart - ((uintptr_t)kernel + seg->fileoff)), name);
                return NULL;
            }
            // Otherwise ehh whatever.
            DBG("Hit start of segment at " ADDR " for %s", seg->vmaddr + ((uintptr_t)fnstart - ((uintptr_t)kernel + seg->fileoff)), name);
            ++fnstart;
            break;
        }
        if(!is_linear_inst(fnstart) || (is_bl((bl_t*)fnstart) && !have_stack_frame))
        {
            ++fnstart;
            break;
        }
        stp_t *stp = (stp_t*)fnstart;
        ldp_t *ldp = (ldp_t*)fnstart;
        if((is_stp_pre(stp) || is_stp_uoff(stp)) && stp->Rt == 29 && stp->Rt2 == 30)
        {
            have_stack_frame = false;
        }
        else if((is_ldp_post(ldp) || is_ldp_uoff(ldp)) && ldp->Rt == 29 && ldp->Rt2 == 30)
        {
            have_stack_frame = true;
        }
    }
    return fnstart;
}

// This is a very annoying thing that we only need as a fallback.
// Certain calls to OSMetaClass::OSMetaClass() do not have x0 generated as an immediate,
// but passed in from the caller. If these are the only constructor calls for a given class,
// then we have no choice but to follow those calls back until we get an x0.
static bool multi_call_emulate(void *kernel, uint32_t *fncall, uint32_t *end, a64_state_t *state, void *sp, uint32_t wantvalid, const char *name)
{
    mach_seg_t *seg = seg4ptr(kernel, fncall);
    kptr_t fncalladdr = seg->vmaddr + ((uintptr_t)fncall - ((uintptr_t)kernel + seg->fileoff));

    // This is quite possibly the trickiest part: finding the start of the function.
    // At first glance it seems simple: just find the function prologue. But how do you
    // actually detect the first instruction of the prologue? On arm64e kernels there
    // should be a "pacibsp", but on arm64? Is "sub sp, sp, 0x..." or a pre-index store
    // enough? But either way, there are functions that just rearrange some args and
    // then do a tail call - these functions have no stack frame whatsoever. And
    // at some point clang also started what I call "late stack frames" which only
    // happen after some early-exit conditions have been passed already, so the prologue
    // is no longer guaranteed to constitute the start of the function.
    // The other approach would be to just seek backwards as long as we hit "linear"
    // instructions, as that would at least constitute one *possible* call path.
    // The nasty issue with that are "noreturn" functions like panic and __stack_chk_fail.
    // Those are excruciatingly often ordered right before the following function like so:
    //
    //      ldp x29, x30, [sp, 0x10]
    //      add sp, sp, 0x20
    //      ret
    //      adrp x0, 0x...
    //      add x0, x0, 0x...
    //      bl sym.panic
    //      sub sp, sp, 0x20
    //      stp x29, x30, [sp, 0x10]
    //      add x29, sp, 0x10
    //
    // Without more information on the function called by such a "bl", we simply don't know
    // whether that function can/will return or not. There is but one assumption we can make:
    // We can assume function calls are only made inside stack frames, because "bl" will
    // otherwise corrupt x30. So we simply keep track of whether we have a stack frame
    // (or more precisely, whether x30 was stashed away) by looking out for "ldp/stp x29, x30"
    // when seeking backwards. As long as we're inside a stack frame, "bl" are assumed to be
    // part of the function, once we leave it, they are no longer considered to be "linear".
    // We also always start seeking backwards from a function call, and in the case of "bl"
    // we assume we have a stack frame, in the case of "b" we assume we do not.
    bool have_stack_frame;
    bl_t *bl = (bl_t*)fncall;
    if(is_bl(bl))
    {
        have_stack_frame = true;
    }
    else if(is_b(bl))
    {
        have_stack_frame = false;
    }
    else
    {
        ERR("Bug in multi_call_emulate: fncall at " ADDR " is neither b nor bl", fncalladdr);
        exit(-1);
    }
    uint32_t *fnstart = find_function_start(kernel, seg, name, fncall, have_stack_frame);
    if(!fnstart)
    {
        return false;
    }
    kptr_t fnaddr = seg->vmaddr + ((uintptr_t)fnstart - ((uintptr_t)kernel + seg->fileoff));
    DBG("Function with call " ADDR " starts at " ADDR, fncalladdr, fnaddr);

    bzero(sp, SPSIZE);
    for(size_t i = 0; i < 31; ++i)
    {
        state->x[i] = 0;
        state->q[i] = 0;
    }
    state->q[31]  = 0;
    state->x[31]  = (uintptr_t)sp + SPSIZE;
    state->valid  = 0xfff80000;
    state->qvalid = 0x0000ff00;
    state->wide   = 0xfff80000;
    state->host   = 0x80000000;
    emu_ret_t ret = a64_emulate(kernel, state, fnstart, &check_equal, end, false, false, kEmuFnEnter);
    switch(ret)
    {
        default:
        case kEmuRet:
            // This should be impossible
            ERR("Bug in a64_emulate: got %u for kEmuFnEnter", ret);
            exit(-1);

        case kEmuErr:
            // This is a fatal error, so no point in trying further.
            return false;

        case kEmuEnd:
            // This is the only possibly successful case. Just need to make sure we got everything we need.
            if((state->valid & wantvalid) == wantvalid)
            {
                DBG("Got a satisfying function call stack at " ADDR, fnaddr);
                return true;
            }
            // Otherwise fall through

        case kEmuUnknown:
            // This means we don't have enough info yet, so break into the code below and do another call level.
            break;
    }

    DBG("Searching for function calls to " ADDR, fnaddr);
    STEP_MEM(uint32_t, mem, (uintptr_t)kernel + seg->fileoff, seg->filesize, 1)
    {
        bl_t *bl = (bl_t*)mem;
        if(is_bl(bl) || is_b(bl))
        {
            kptr_t bladdr = seg->vmaddr + ((uintptr_t)bl - ((uintptr_t)kernel + seg->fileoff));
            kptr_t bltarg = bladdr + get_bl_off(bl);
            if(bltarg == fnaddr && multi_call_emulate(kernel, mem, end, state, sp, wantvalid, name))
            {
                return true;
            }
        }
    }
    return false;
}

#if 0
static int compare_strings(const void *a, const void *b)
{
    return strcmp(*(char * const*)a, *(char * const*)b);
}
#endif

static int compare_candidates(const void *a, const void *b)
{
    const metaclass_candidate_t *x = (const metaclass_candidate_t*)a,
                                *y = (const metaclass_candidate_t*)b;
    int r = strcmp(x->name, y->name);
    return r != 0 ? r : !x->fncall - !y->fncall;
}

static int compare_names(const void *a, const void *b)
{
    const metaclass_t *x = *(const metaclass_t**)a,
                      *y = *(const metaclass_t**)b;
    int r;
    if(!x->name || !y->name)
    {
        r = !!x->name - !!y->name;
    }
    else
    {
        r = strcmp(x->name, y->name);
    }
    return r;
}

static int compare_bundles(const void *a, const void *b)
{
    const metaclass_t *x = *(const metaclass_t**)a,
                      *y = *(const metaclass_t**)b;
    int r;
    if(!x->bundle || !y->bundle)
    {
        r = !!x->bundle - !!y->bundle;
    }
    else
    {
        r = strcmp(x->bundle, y->bundle);
    }
    return r != 0 ? r : compare_names(a, b);
}

#if 0
static int compare_inheritance(const void *a, const void *b)
{
    const metaclass_t *x = *(const metaclass_t**)a,
                      *y = *(const metaclass_t**)b;
    for(const metaclass_t *p = y->parentP; p; p = p->parentP)
    {
        if(x == p)
        {
            return -1;
        }
    }
    for(const metaclass_t *p = x->parentP; p; p = p->parentP)
    {
        if(y == p)
        {
            return 1;
        }
    }
    return 0;
}
#endif

static int compare_sym_addrs(const void *a, const void *b)
{
    kptr_t adda = ((const sym_t*)a)->addr,
           addb = ((const sym_t*)b)->addr;
    if(adda == addb) return 0;
    return adda < addb ? -1 : 1;
}

static int compare_sym_names(const void *a, const void *b)
{
    const sym_t *syma = a,
                *symb = b;
    return strcmp(syma->name, symb->name);
}

static int compare_sym_addr(const void *a, const void *b)
{
    kptr_t adda = *(const kptr_t*)a,
           addb = ((const sym_t*)b)->addr;
    if(adda == addb) return 0;
    return adda < addb ? -1 : 1;
}

static int compare_sym_name(const void *a, const void *b)
{
    const char *name = a;
    const sym_t *sym = b;
    return strcmp(name, sym->name);
}

static int compare_symclass(const void *a, const void *b)
{
    const symmap_class_t *cla = a,
                         *clb = b;
    return strcmp(cla->name, clb->name);
}

static int compare_symclass_name(const void *a, const void *b)
{
    const char *key = a;
    const symmap_class_t *cls = b;
    return strcmp(key, cls->name);
}

static const char* find_sym_by_addr(kptr_t addr, sym_t *asyms, size_t nsyms)
{
    sym_t *sym = bsearch(&addr, asyms, nsyms, sizeof(*asyms), &compare_sym_addr);
    return sym ? sym->name : NULL;
}

static kptr_t find_sym_by_name(const char *name, sym_t *bsyms, size_t nsyms)
{
    sym_t *sym = bsearch(name, bsyms, nsyms, sizeof(*bsyms), &compare_sym_name);
    return sym ? sym->addr : 0;
}

static int map_file(const char *file, int prot, void **addrp, size_t *lenp)
{
    int retval = -1;

    int fd = open(file, O_RDONLY);
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

    size_t len = s.st_size;
    void *addr = mmap(NULL, len + 1, prot, MAP_PRIVATE, fd, 0); // +1 so that space afterwards is zero-filled
    if(addr == MAP_FAILED)
    {
        ERRNO("mmap(%s)", file);
        goto out;
    }

    if(addrp) *addrp = addr;
    if(lenp)  *lenp = len;
    retval = 0;

out:;
    // Always close fd - mapped mem will live on
    if(fd != 0)
    {
        close(fd);
    }
    return retval;
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

    fat_hdr_t *fat = (fat_hdr_t*)hdr;
    if(fat->magic == FAT_CIGAM)
    {
        bool found = false;
        fat_arch_t *arch = (fat_arch_t*)(fat + 1);
        for(size_t i = 0; i < SWAP32(fat->nfat_arch); ++i)
        {
            if(SWAP32(arch[i].cputype) == CPU_TYPE_ARM64)
            {
                uint32_t offset = SWAP32(arch[i].offset);
                uint32_t newsize = SWAP32(arch[i].size);
                if(offset > machosize || newsize > machosize - offset)
                {
                    if(name) ERR("Embedded fat arch out of bounds (%s).", name);
                    else     ERR("Fat arch out of bounds.");
                    return -1;
                }
                if(newsize < sizeof(mach_hdr_t))
                {
                    if(name) ERR("Embedded fat arch is too short to contain a Mach-O (%s).", name);
                    else     ERR("Fat arch is too short to contain a Mach-O.");
                    return -1;
                }
                macho = (void*)((uintptr_t)hdr + offset);
                machosize = newsize;
                hdr = macho;
                found = true;
                break;
            }
        }
        if(!found)
        {
            if(name) ERR("No arm64 slice in embedded fat binary (%s).", name);
            else     ERR("No arm64 slice in fat binary.");
            return -1;
        }
        *machop     = macho;
        *machosizep = machosize;
        *hdrp       = hdr;
    }
    return 0;
}

static int validate_macho(void **machop, size_t *machosizep, mach_hdr_t **hdrp, const char *name)
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
        if(name) ERR("Wrong embedded architecture, only arm64 is supported (%s).", name);
        else     ERR("Wrong architecture, only arm64 is supported.");
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
    // TODO: replace header & weed out invalid load commands?
    FOREACH_CMD(hdr, cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            if(seg->fileoff > machosize || seg->filesize > machosize - seg->fileoff)
            {
                if(name) ERR("Embedded Mach-O segment out of bounds: %s (%s)", seg->segname, name);
                else     ERR("Mach-O segment out of bounds: %s", seg->segname);
                return -1;
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
            mach_nlist_t *symtab = (mach_nlist_t*)((uintptr_t)macho + stab->symoff);
            for(size_t i = 0; i < stab->nsyms; ++i)
            {
                if((symtab[i].n_type & N_TYPE) == N_UNDF || ((symtab[i].n_type & N_STAB) && !(symtab[i].n_type & N_EXT))) // XXX: eliminate check for verification?
                {
                    continue;
                }
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
            mach_dstab_t *dstab = (mach_dstab_t*)cmd;
            if(hdr->filetype == MH_KEXT_BUNDLE) // XXX: get rid of this too?
            {
                if(dstab->extreloff > machosize || dstab->nextrel > (machosize - dstab->extreloff) / sizeof(mach_reloc_t))
                {
                    if(name) ERR("Embedded Mach-O dsymtab out of bounds (%s).", name);
                    else     ERR("Mach-O dsymtab out of bounds.");
                    return -1;
                }
                // TODO: verify dstab entries as well
            }
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
        }
    }
    *machop     = macho;
    *machosizep = machosize;
    *hdrp       = hdr;
    return 0;
}

static CFTypeRef get_prelink_info(mach_hdr_t *hdr)
{
    CFTypeRef info = NULL;
    CFStringRef err = NULL;
    FOREACH_CMD(hdr, cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            if(strcmp("__PRELINK_INFO", seg->segname) == 0 && seg->filesize > 0)
            {
                mach_sec_t *secs = (mach_sec_t*)(seg + 1);
                for(size_t h = 0; h < seg->nsects; ++h)
                {
                    if(strcmp("__info", secs[h].sectname) == 0)
                    {
                        const char *xml = (const char*)((uintptr_t)hdr + secs[h].offset);
                        info = IOCFUnserialize(xml, NULL, 0, &err);
                        if(!info)
                        {
                            ERR("IOCFUnserialize: %s", CFStringGetCStringPtr(err, kCFStringEncodingUTF8));
                            goto out;
                        }
                        break;
                    }
                }
                break;
            }
        }
    }
    if(!info)
    {
        ERR("Failed to find PrelinkInfo");
        goto out;
    }
out:;
    if(err) CFRelease(err);
    return info;
}

static inline bool isws(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r'; // disregard newline by design
}

static inline bool isan(char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_';
}

static int parse_symmap(char *mem, size_t len, size_t *num, symmap_class_t **entries)
{
    int retval = -1;
    ARRDECL(symmap_class_t, map, NUM_METACLASSES_EXPECT);

    // One loop iteration = one line of data.
    // At the end of an iteration, mem points to the newline at the end of the line.
    // Since we skip leading whitespace, this saves us the ++mem as third for() argument,
    // which in turn saves us a lot of headache with making sure we stay < end.
    bool zero_nl = false;
    size_t line = 1;
    struct
    {
        const char *class;
        struct
        {
            size_t size;
            size_t idx;
            symmap_method_t *val;
        } arr;
    } current;
    current.class = NULL;
    ARRINIT(current.arr, 0x100);
#define PUSHENT() \
do \
{ \
    symmap_class_t *ent; \
    ARRNEXT(map, ent); \
    symmap_method_t *methods = NULL; \
    if(current.arr.idx > 0) \
    { \
        size_t sz = current.arr.idx * sizeof(*methods); \
        methods = malloc(sz); \
        if(!methods) \
        { \
            ERRNO("malloc(symmap methods)"); \
            goto bad; \
        } \
        memcpy(methods, current.arr.val, sz); \
    } \
    ent->metaclass = NULL; \
    ent->name = current.class; \
    ent->num = current.arr.idx; \
    ent->methods = methods; \
    ent->duplicate = 0; \
} while(0)
    for(char *end = mem + len; mem < end;)
    {
        char ch;

        // Skip leading whitespace and empty lines
        while(mem < end)
        {
            ch = *mem;
            if(ch == '\n')
            {
                if(zero_nl)
                {
                    *mem = '\0';
                    zero_nl = false;
                }
                ++line;
            }
            else if(!isws(ch))
            {
                break;
            }
            ++mem;
        }
        if(mem >= end) break;
        DBG("Symmap line %lu", line);

        ch = *mem;

        // Comment, jump to end of line
        if(ch == '#')
        {
            do
            {
                ++mem;
            } while(mem < end && *mem != '\n');
        }
        // This is a method
        else if(ch == '-')
        {
            DBG("Got symmap method");

            // Must have seen a class name before
            if(!current.class)
            {
                ERR("Symbol map, line %lu: method declaration before first class declaration", line);
                goto bad;
            }
            ++mem; // Skip dash
            // Skip leading whitespace
            while(mem < end && isws(*mem))
            {
                ++mem;
            }
            // Empty lines are permitted as "no name assigned"
            if(mem >= end || *mem == '\n')
            {
                symmap_method_t *ent;
                ARRNEXT(current.arr, ent);
                ent->class = NULL;
                ent->method = NULL;
                ent->structor = 0;
                ent->reserved = 0;
                if(mem >= end) break;
                goto next;
            }

            bool structor = false;
            const char *classname = NULL,
                       *methname  = NULL,
                       *namestart = mem;
            // Seek end of identifier
            while(mem < end && isan(*mem))
            {
                ++mem;
            }
            if(mem >= end)
            {
                ERR("Symbol map, line %lu: incomplete method declaration", line);
                goto bad;
            }
            // If we are at "::", this is a class name
            if(mem < end - 1 && mem[0] == ':' && mem[1] == ':')
            {
                *mem = '\0'; // terminate class name
                mem += 2;
                classname = namestart;
                namestart = mem;
            }
            if(mem < end && *mem == '~')
            {
                ++mem;
            }
            while(mem < end && isan(*mem))
            {
                ++mem;
            }
            if(mem >= end)
            {
                ERR("Symbol map, line %lu: incomplete method declaration (identifier)", line);
                goto bad;
            }
            ch = *mem;
            if(ch != '(')
            {
                ERR("Symbol map, line %lu: expected '(', got '%c' (0x%hhu)", line, ch, (unsigned char)ch);
                goto bad;
            }
            while(mem < end && *mem != '\n')
            {
                ++mem;
            }
            methname = namestart;
            zero_nl = true; // Defer termination to next loop iteration
            if(!classname)
            {
                classname = current.class;
                // Do this here so structors can be suppressed by prefixing with "ClassName::".
                size_t sz = strlen(classname);
                const char *tmp = methname;
                if(tmp[0] == '~')
                {
                    ++tmp;
                }
                if(strncmp(classname, tmp, sz) == 0 && tmp[sz] == '(')
                {
                    structor = true;
                }
            }
            symmap_method_t *ent;
            ARRNEXT(current.arr, ent);
            ent->class = classname;
            ent->method = methname;
            ent->structor = !!structor;
            ent->reserved = 0;
        }
        // This is a class name
        else
        {
            DBG("Got symmap class");

            const char *classname = mem;
            while(mem < end && isan(*mem))
            {
                ++mem;
            }
            if(mem < end && (ch = *mem) != '\n')
            {
                ERR("Symbol map, line %lu: expected newline, got '%c' (0x%hhu)", line, ch, (unsigned char)ch);
                goto bad;
            }
            zero_nl = true; // Defer termination to next loop iteration
            if(current.class)
            {
                PUSHENT();
            }
            current.class = classname;
            current.arr.idx = 0; // don't realloc or anything
        }

    next:;
        if(mem < end && *mem != '\n')
        {
            ERR("Symbol map, line %lu: error in parse_symmap implementation, loop does not end on newline", line);
            goto bad;
        }
    }
    // Can ignore zero_nl here, since mmap() guarantees zeroed mem afterwards, and we mapped len + 1.
    if(current.class)
    {
        PUSHENT();
        current.class = NULL;
    }
    size_t sz = map.idx * sizeof(*map.val);
    symmap_class_t *ptr = malloc(sz);
    if(!ptr)
    {
        ERRNO("malloc(symmap final)");
        goto bad;
    }
    memcpy(ptr, map.val, sz);
    qsort(ptr, map.idx, sizeof(*map.val), &compare_symclass);

    // Mark duplicates and warn if methods don't match
    for(size_t i = 1; i < map.idx; ++i)
    {
        symmap_class_t *prev = &ptr[i-1],
                       *cur  = &ptr[i];
        if(strcmp(prev->name, cur->name) == 0)
        {
            DBG("Duplicate symmap class: %s", cur->name);
            cur->duplicate = 1;
            if(prev->num != cur->num)
            {
                WRN("Duplicate symmap classes %s have different number of methods (%lu vs %lu)", cur->name, prev->num, cur->num);
            }
            else
            {
                for(size_t j = 0; j < cur->num; ++j)
                {
                    symmap_method_t *one = &prev->methods[j],
                                    *two = &cur ->methods[j];
                    if(!one->method && !two->method) // note the AND
                    {
                        continue;
                    }
                    if(!one->method || !two->method || strcmp(one->class, two->class) != 0 || strcmp(one->method, two->method) != 0)
                    {
                        WRN("Mismatching method names of duplicate symmap class %s: %s::%s vs %s::%s", cur->name, one->class, one->method, two->class, two->method);
                    }
                }
            }
        }
    }

    *entries = ptr;
    *num = map.idx;

    retval = 0;
    goto out;

bad:;
    for(size_t i = 0; i < map.idx; ++i)
    {
        free(map.val[i].methods);
        map.val[i].methods = NULL;
    }
out:;
    if(current.arr.val)
    {
        free(current.arr.val);
        current.arr.val = NULL;
    }
    if(map.val)
    {
        free(map.val);
        map.val = NULL;
    }
    return retval;
#undef PUSHENT
}

static void print_syment(const char *owner, const char *class, const char *method)
{
    if(!method)
    {
        // Quick exit - preserve empty placeholder
        printf("-\n");
        return;
    }
    printf("- ");
    if(strcmp(class, owner) != 0)
    {
        printf("%s::", class);
    }
    printf("%s\n", method);
}

static void print_symmap(metaclass_t *meta)
{
    printf("%s\n", meta->name);
    metaclass_t *parent = meta->parentP;
    while(parent && !parent->vtab)
    {
        parent = parent->parentP;
    }
    for(size_t i = parent ? parent->nmethods : 0; i < meta->nmethods; ++i)
    {
        vtab_entry_t *ent = &meta->methods[i];
        print_syment(meta->name, ent->class, ent->placeholder ? NULL : ent->method);
    }
}

// Turn special chars to underscores for now.
// Eventually this should be replaced by the mangled name.
static const char* radarify(const char *sym)
{
    static char *buf = NULL;
    static size_t buflen = 0;
    size_t len = strlen(sym) + 1;
    if(len > buflen)
    {
        if(buf) free(buf);
        buf = malloc(len);
        buflen = len;
    }
    size_t from = 0,
           to   = 0,
           last = 0;
    while(from < len)
    {
        char c = sym[from++];
        if(
            (c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c == '.') ||
            (c == ':')
        )
        {
            last = to;
        }
        else
        {
            c = '_';
        }
        buf[to++] = c;
    }
    buf[last+1] = '\0';
    return buf;
}

static void print_metaclass(metaclass_t *meta, int namelen, opt_t opt)
{
    if(opt.radare)
    {
        if(meta->vtab != 0 && meta->vtab != -1)
        {
            printf("f sym.vtablefor%s 0 " ADDR "\n", meta->name, meta->vtab);
            printf("fN sym.vtablefor%s vtablefor%s\n", meta->name, meta->name);
        }
        if(meta->addr)
        {
            printf("f sym.%s::gMetaClass 0 " ADDR "\n", meta->name, meta->addr);
            printf("fN sym.%s::gMetaClass %s::gMetaClass\n", meta->name, meta->name);
        }
        if(meta->metavtab != 0 && meta->metavtab != -1)
        {
            printf("f sym.vtablefor%s::MetaClass 0 " ADDR "\n", meta->name, meta->metavtab);
            printf("fN sym.vtablefor%s::MetaClass vtablefor%s::MetaClass\n", meta->name, meta->name);
        }
        for(size_t i = 0; i < meta->nmethods; ++i)
        {
            vtab_entry_t *ent = &meta->methods[i];
            if(!ent->overrides || ent->addr == -1)
            {
                continue;
            }
            const char *r2name = radarify(ent->method);
            printf("f sym.%s::%s 0 " ADDR "\n", ent->class, r2name, ent->addr);
            printf("\"fN sym.%s::%s %s::%s\"\n", ent->class, r2name, ent->class, ent->method);
        }
    }
    else
    {
        if(opt.vtab)
        {
            if(meta->vtab == -1)
            {
                printf("%svtab=??????????????????%s ", colorRed, colorReset);
            }
            else
            {
                printf("vtab=" ADDR " ", meta->vtab);
            }
        }
        if(opt.size)
        {
            printf("size=0x%08x ", meta->objsize);
        }
        if(opt.meta)
        {
            printf("meta=" ADDR " parent=" ADDR " metavtab=" ADDR " ", meta->addr, meta->parent, meta->metavtab);
        }
        printf("%s%-*s%s", colorCyan, namelen, meta->name, colorReset);
        if(opt.bundle)
        {
            if(meta->bundle)
            {
                printf(" (%s%s%s)", colorBlue, meta->bundle, colorReset);
            }
            else
            {
                printf(" (%s???%s)", colorRed, colorReset);
            }
        }
        printf("\n");
        if(opt.overrides)
        {
            metaclass_t *parent = meta->parentP;
            while(parent && !parent->vtab)
            {
                parent = parent->parentP;
            }
            for(size_t i = 0; i < meta->nmethods; ++i)
            {
                vtab_entry_t *ent = &meta->methods[i];
                if(!ent->overrides && !opt.inherit)
                {
                    continue;
                }
                const char *color = ent->addr == -1 ? colorRed : !ent->overrides ? colorGray : "";
                vtab_entry_t *pent = (parent && i < parent->nmethods) ? &parent->methods[i] : NULL;
                size_t hex = i * sizeof(kptr_t);
                int hexlen = 5;
                for(size_t h = hex; h >= 0x10; h >>= 4) --hexlen;
                printf("%s    %*s%lx func=" ADDR " overrides=" ADDR " pac=0x%04hx %s::%s%s\n", color, hexlen, "0x", hex, ent->addr, pent ? pent->addr : 0, ent->pac, ent->class, ent->method, colorReset);
            }
        }
    }
}

static void add_metaclass(void *kernel, void *arg, a64_state_t *state, uint32_t *callsite, bool want_vtabs)
{
    struct
    {
        size_t size;
        size_t idx;
        metaclass_t *val;
    } *metas = arg;
    const char *name = addr2ptr(kernel, state->x[1]);
    DBG("Adding metaclass: %s", name);

    metaclass_t *meta;
    ARRNEXT(*metas, meta);
    meta->addr = state->x[0];
    meta->parent = state->x[2];
    meta->vtab = 0;
    meta->metavtab = 0;
    meta->callsite = off2addr(kernel, (uintptr_t)callsite - (uintptr_t)kernel);
    meta->parentP = NULL;
    meta->symclass = NULL;
    meta->name = name;
    meta->bundle = NULL;
    meta->methods = NULL;
    meta->nmethods = 0;
    meta->objsize = state->x[3];
    meta->methods_done = 0;
    meta->methods_err = 0;
    meta->visited = 0;
    meta->duplicate = 0;
    meta->reserved = 0;
    if(want_vtabs)
    {
        kptr_t x0 = state->x[0];
        for(uint32_t *m = callsite + 1; is_linear_inst(m) || is_cbz((cbz_t*)m) || is_cbnz((cbz_t*)m) || is_tbz((tbz_t*)m) || is_tbnz((tbz_t*)m); ++m)
        {
            // Kinda trash, but works... and it's at least a possible path
            if(is_cbz((cbz_t*)m) || is_cbnz((cbz_t*)m) || is_tbz((tbz_t*)m) || is_tbnz((tbz_t*)m))
            {
                continue;
            }
            emu_ret_t ret = a64_emulate(kernel, state, m, &check_equal, m + 1, false, true, kEmuFnIgnore);
            if(ret != kEmuEnd)
            {
                DBG("a64_emulate returned %u", ret);
                break;
            }
            str_uoff_t *stru = (str_uoff_t*)m;
            if(is_str_uoff(stru) && (state->valid & (1 << stru->Rn)) && state->x[stru->Rn] + get_str_uoff(stru) == x0)
            {
                DBG("Got str at " ADDR, off2addr(kernel, (uintptr_t)stru - (uintptr_t)kernel));
                if(!(state->valid & (1 << stru->Rt)))
                {
                    DBG("Store has no valid source register");
                }
                else
                {
                    meta->metavtab = state->x[stru->Rt];
                }
                break;
            }
        }
        if(!meta->metavtab)
        {
            WRN("Failed to find metavtab for %s", name);
        }
    }
}

static void constructor_cb(void *kernel, kptr_t kbase, mach_seg_t *seg, bool chainedFixup, bool want_vtabs, void *metas, void *names, a64_state_t *state, uint32_t *fnstart, uint32_t *bl, kptr_t bladdr, void *arg)
{
    const char *name = NULL;
    uint32_t *fncall = NULL;
    if((state->valid & 0x2) && (state->wide & 0x2))
    {
        name = addr2ptr(kernel, state->x[1]);
        if(!name)
        {
            DBG("meta->name: " ADDR " (untagged: " ADDR ")", state->x[1], kuntag(kbase, chainedFixup, state->x[1], NULL));
            ERR("Name of MetaClass lies outside all segments at " ADDR, bladdr);
            exit(-1);
        }
    }
    DBG("Constructor candidate for %s", name ? name : "???");
    if((state->valid & 0xe) != 0xe)
    {
        // Check for alt constructor
        if((state->valid & 0xe) == 0x0)
        {
            for(size_t i = 0; i < 32; ++i)
            {
                state->x[i] = 0;
                state->q[i] = 0;
            }
            // NOTE: Will have to revise this if the constructors ever diverge in x0-x3
            state->x[0]  = 0x6174656d656b6166; // "fakemeta"
            state->x[1]  = 0x656d616e656b6166; // "fakename"
            state->x[2]  = 0x00727470656b6166; // "fakeptr"
            state->x[3]  = 0x656b6166; // "fake"
            state->valid  = 0xf;
            state->qvalid = 0x0;
            state->wide   = 0x7;
            state->host   = 0x0;
            if(a64_emulate(kernel, state, fnstart, &check_equal, bl, false, true, kEmuFnIgnore) == kEmuEnd)
            {
                if((state->valid & 0xf) == 0xf && (state->wide & 0xf) == 0x7 && state->x[0] == 0x6174656d656b6166 && state->x[1] == 0x656d616e656b6166 && state->x[2] == 0x00727470656b6166 && state->x[3] == 0x656b6166)
                {
                    kptr_t addr = seg->vmaddr + ((uintptr_t)fnstart - ((uintptr_t)kernel + seg->fileoff));
                    DBG("OSMetaClassAltConstructor: " ADDR, addr);
                    // We wanna land here even if we already got OSMetaClassAltConstructor off symtab, in order to suppress the warning below.
                    // But we obviously never wanna store a result or fail on multiple candidates in that case.
                    if(arg)
                    {
                        if(*(kptr_t*)arg)
                        {
                            ERR("More than one candidate for OSMetaClassAltConstructor");
                            exit(-1);
                        }
                        *(kptr_t*)arg = addr;
                    }
                    // Do NOT fall through
                    return;
                }
            }
        }
        WRN("Skipping constructor call without x1-x3 (%x) at " ADDR, state->valid, bladdr);
        // Fall through
    }
    else if((state->valid & 0x1) != 0x1)
    {
        DBG("Skipping constructor call without x0 at " ADDR, bladdr);
        fncall = bl;
        // Fall through
    }
    else if((state->wide & 0xf) != 0x7)
    {
        WRN("Skipping constructor call with unexpected register widths (%x) at " ADDR, state->wide, bladdr);
        // Fall through
    }
    else
    {
        DBG("Processing constructor call at " ADDR " (%s)", bladdr, name);
        add_metaclass(kernel, metas, state, bl, want_vtabs);
        // Do NOT fall through
        return;
    }
    // We only get here on failure:
    if(name)
    {
        struct
        {
            size_t size;
            size_t idx;
            metaclass_candidate_t *val;
        } *namelist = names;
        metaclass_candidate_t *cand;
        ARRNEXT(*namelist, cand);
        cand->name = name;
        cand->fncall = fncall;
    }
}

static void alt_constructor_cb(void *kernel, kptr_t kbase, mach_seg_t *seg, bool chainedFixup, bool want_vtabs, void *metas, void *names, a64_state_t *state, uint32_t *fnstart, uint32_t *bl, kptr_t bladdr, void *arg)
{
    const char *name = NULL;
    if((state->valid & 0x2) && (state->wide & 0x2))
    {
        name = addr2ptr(kernel, state->x[1]);
        if(!name)
        {
            DBG("meta->name: " ADDR " (untagged: " ADDR ")", state->x[1], kuntag(kbase, chainedFixup, state->x[1], NULL));
            ERR("Name of MetaClass lies outside all segments at " ADDR, bladdr);
            exit(-1);
        }
    }
    DBG("Alt constructor candidate for %s", name ? name : "???");
    if((state->valid & 0x7e) != 0x7e)
    {
        WRN("Skipping alt constructor call without x1-x6 (%x) at " ADDR, state->valid, bladdr);
        // Fall through
    }
    else if((state->valid & 0x1) != 0x1)
    {
        DBG("Skipping alt constructor call without x0 (%x) at " ADDR, state->valid, bladdr);
        // Fall through
    }
    else if((state->wide & 0x7f) != 0x37)
    {
        WRN("Skipping alt constructor call with unexpected register widths (%x) at " ADDR, state->wide, bladdr);
        // Fall through
    }
    else
    {
        DBG("Processing alt constructor call at " ADDR " (%s)", bladdr, name);
        // NOTE: Will have to revise this if the constructors ever diverge in x0-x3
        add_metaclass(kernel, metas, state, bl, want_vtabs);
        // Do NOT fall through
        return;
    }
    // We only get here on failure:
    if(name)
    {
        // For now, always set NULL for alt constructor
        struct
        {
            size_t size;
            size_t idx;
            metaclass_candidate_t *val;
        } *namelist = names;
        metaclass_candidate_t *cand;
        ARRNEXT(*namelist, cand);
        cand->name = name;
        cand->fncall = NULL;
    }
}

typedef void (*constructor_cb_t)(void*, kptr_t, mach_seg_t*, bool, bool, void*, void*, a64_state_t*, uint32_t*, uint32_t*, kptr_t, void*);

static void find_constructor_calls(void *kernel, mach_hdr_t *hdr, kptr_t kbase, bool chainedFixup, bool have_plk_text_exec, bool want_vtabs, void *arr, void *metas, void *names, constructor_cb_t cb, void *arg)
{
    struct
    {
        size_t size;
        size_t idx;
        kptr_t *val;
    } *aliases = arr;
    FOREACH_CMD(hdr, cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            if(seg->filesize > 0 && SEG_IS_EXEC(seg))
            {
                STEP_MEM(uint32_t, mem, (uintptr_t)kernel + seg->fileoff, seg->filesize, 1)
                {
                    bl_t *bl = (bl_t*)mem;
                    if(is_bl(bl) || is_b(bl))
                    {
                        kptr_t bladdr = seg->vmaddr + ((uintptr_t)bl - ((uintptr_t)kernel + seg->fileoff));
                        kptr_t bltarg = bladdr + get_bl_off(bl);
                        for(size_t i = 0; i < aliases->idx; ++i)
                        {
                            if(bltarg == aliases->val[i])
                            {
                                uint32_t *fnstart = find_function_start(kernel, seg, "OSMetaClass constructor call", mem, is_bl(bl));
                                if(fnstart)
                                {
                                    a64_state_t state;
                                    if(a64_emulate(kernel, &state, fnstart, &check_equal, mem, true, true, kEmuFnIgnore) == kEmuEnd)
                                    {
                                        cb(kernel, kbase, seg, chainedFixup, want_vtabs, metas, names, &state, fnstart, mem, bladdr, arg);
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

static void print_help(const char *self)
{
    fprintf(stderr, "Usage:\n"
                    "    %s [-aAbBCdeGimMnoOpRsSv] [ClassName] [OverrideName] [BundleName] kernel [SymbolMap]\n"
                    "\n"
                    "Description:\n"
                    "    Extract and print C++ class information from an arm64 iOS kernel.\n"
                    "    Flags (those with the -) may be given in any order, the other arguments\n"
                    "    must be given in the order shown above. Class and bundle name filters\n"
                    "    need not be the full names, substrings will match too.\n"
                    "\n"
                    "Print options:\n"
                    "    -a  Synonym for -bmsv\n"
                    "    -A  Synonym for -bimosv\n"
                    "    -b  Print bundle identifier\n"
                    "    -i  Print inherited virtual methods (implies -o)\n"
                    "    -m  Print MetaClass addresses\n"
                    "    -M  Print symbol map (implies -o, takes precedence)\n"
                    "    -MM Same as above, and copy input map for missing classes\n"
                    "    -o  Print overridden/new virtual methods\n"
                    "    -R  Print symbols for radare2 (implies -mov, takes precedence)\n"
                    "    -s  Print object sizes\n"
                    "    -v  Print object vtabs\n"
                    "\n"
                    "Filter options:\n"
                    "    -B  Filter by bundle identifier (kext)\n"
                    "    -C  Filter by class name\n"
                    "    -e  Filter extending ClassName (implies -C)\n"
                    "    -O  Filter by name of overridden method\n"
                    "    -p  Filter parents of ClassName (implies -C)\n"
                    "\n"
                    "Other options:\n"
                    "    -d  Debug output\n"
                    "    -G  Sort (group) by bundle identifier\n"
                    "    -n  Disable color output\n"
                    "    -S  Sort by class name\n"
                    , self);
}

int main(int argc, const char **argv)
{
    int r;
    opt_t opt =
    {
        .bundle    = 0,
        .bfilt     = 0,
        .cfilt     = 0,
        .bsort     = 0,
        .csort     = 0,
        .extend    = 0,
        .inherit   = 0,
        .meta      = 0,
        .maxmap    = 0,
        .overrides = 0,
        .ofilt     = 0,
        .parent    = 0,
        .radare    = 0,
        .size      = 0,
        .symmap    = 0,
        .vtab      = 0,
        ._reserved = 0,
    };
    const char *filt_class    = NULL,
               *filt_bundle   = NULL,
               *filt_override = NULL;

    int aoff = 1;
    for(; aoff < argc; ++aoff)
    {
        if(argv[aoff][0] != '-')
        {
            break;
        }
        for(size_t i = 1; argv[aoff][i] != '\0'; ++i)
        {
            switch(argv[aoff][i])
            {
                case 'd':
                {
                    debug = true;
                    break;
                }
                case 'a':
                {
                    opt.bundle = 1;
                    opt.meta   = 1;
                    opt.size   = 1;
                    opt.vtab   = 1;
                    break;
                }
                case 'A':
                {
                    opt.bundle    = 1;
                    opt.inherit   = 1;
                    opt.meta      = 1;
                    opt.overrides = 1;
                    opt.size      = 1;
                    opt.vtab      = 1;
                    break;
                }
                case 'b':
                {
                    opt.bundle = 1;
                    break;
                }
                case 'B':
                {
                    opt.bfilt = 1;
                    break;
                }
                case 'C':
                {
                    opt.cfilt = 1;
                    break;
                }
                case 'e':
                {
                    opt.extend = 1;
                    opt.cfilt  = 1;
                    break;
                }
                case 'G':
                {
                    opt.bsort = 1;
                    break;
                }
                case 'i':
                {
                    opt.inherit   = 1;
                    opt.overrides = 1;
                    break;
                }
                case 'm':
                {
                    opt.meta = 1;
                    break;
                }
                case 'M':
                {
                    if(opt.symmap)
                    {
                        opt.maxmap = 1;
                    }
                    opt.overrides = 1;
                    opt.symmap    = 1;
                    break;
                }
                case 'n':
                {
                    colorGray   = "";
                    colorRed    = "";
                    colorYellow = "";
                    colorBlue   = "";
                    colorPink   = "";
                    colorCyan   = "";
                    colorReset  = "";
                    break;
                }
                case 'o':
                {
                    opt.overrides = 1;
                    break;
                }
                case 'O':
                {
                    opt.ofilt = 1;
                    break;
                }
                case 'p':
                {
                    opt.parent = 1;
                    opt.cfilt  = 1;
                    break;
                }
                case 'R':
                {
                    opt.meta      = 1;
                    opt.overrides = 1;
                    opt.radare    = 1;
                    opt.vtab      = 1;
                    break;
                }
                case 's':
                {
                    opt.size = 1;
                    break;
                }
                case 'S':
                {
                    opt.csort = 1;
                    break;
                }
                case 'v':
                {
                    opt.vtab = 1;
                    break;
                }
                default:
                {
                    ERR("Unrecognised option: -%c", argv[aoff][i]);
                    fputs("\n", stderr);
                    print_help(argv[0]);
                    return -1;
                }
            }
        }
    }

    bool have_symmap = false;
    int wantargs = 1 + (opt.bfilt ? 1 : 0) + (opt.cfilt ? 1 : 0) + (opt.ofilt ? 1 : 0);
    if(argc - aoff == wantargs + 1)
    {
        ++wantargs;
        have_symmap = true;
    }
    if(argc - aoff != wantargs)
    {
        if(argc > 1)
        {
            ERR("Too %s arguments.", (argc - aoff < wantargs) ? "few" : "many");
            fputs("\n", stderr);
        }
        else
        {
            fprintf(stderr, "iometa"
#ifdef VERSION
                            " v" STRINGIFY(VERSION)
#endif
#ifdef TIMESTAMP
                            ", compiled on " STRINGIFY(TIMESTAMP)
#endif
                            "\n\n"
            );
        }
        print_help(argv[0]);
        return -1;
    }

    if(opt.symmap && (opt.bfilt || opt.cfilt || opt.ofilt || opt.bsort || opt.csort || opt.extend || opt.parent))
    {
        ERR("Cannot use filters or sorting with -M.");
        return -1;
    }
    if(opt.symmap && opt.radare)
    {
        ERR("Only one of -M and -R may be given.");
        return -1;
    }
    if(opt.extend && opt.parent)
    {
        ERR("Only one of -e and -p may be given.");
        return -1;
    }
    if(opt.bsort && opt.csort)
    {
        ERR("Only one of -G and -S may be given.");
        return -1;
    }

    if(opt.cfilt)
    {
        filt_class = argv[aoff++];
    }
    if(opt.bfilt)
    {
        filt_bundle = argv[aoff++];
    }
    if(opt.ofilt)
    {
        filt_override = argv[aoff++];
    }
    bool want_vtabs = opt.vtab || opt.overrides || opt.ofilt;

    void *kernel = NULL;
    size_t kernelsize = 0;
    r = map_file(argv[aoff++], PROT_READ, &kernel, &kernelsize);
    if(r != 0) return r;
    mach_hdr_t *hdr = kernel;
    r = validate_macho(&kernel, &kernelsize, &hdr, NULL);
    if(r != 0) return r;

    struct
    {
        size_t num;
        symmap_class_t *map;
    } symmap = { 0, NULL };
    if(have_symmap)
    {
        void *symmapMem = NULL;
        size_t symmmapLen = 0;
        r = map_file(argv[aoff++], PROT_READ | PROT_WRITE, &symmapMem, &symmmapLen);
        if(r != 0) return r;
        r = parse_symmap(symmapMem, symmmapLen, &symmap.num, &symmap.map);
        if(r != 0) return r;
    }

    ARRDECL(kptr_t, aliases, NUM_KEXTS_EXPECT);
    ARRDECL(kptr_t, altaliases, NUM_KEXTS_EXPECT);

    kptr_t OSMetaClassConstructor = 0,
           OSMetaClassAltConstructor = 0,
           OSMetaClassVtab = 0,
           OSObjectVtab = 0,
           OSObjectGetMetaClass = 0,
           kbase = 0,
           plk_base = 0,
           //initcode = 0,
           pure_virtual = 0;
    bool chainedFixup = false,
         have_plk_text_exec = false;
    mach_nlist_t *symtab = NULL;
    mach_dstab_t *dstab  = NULL;
    char *strtab         = NULL;
    size_t nsyms         = 0,
           nexreloc      = 0;
    sym_t *asyms         = NULL,
          *bsyms         = NULL;
    char **exreloc      = NULL;
    kptr_t exreloc_min = ~0, exreloc_max = 0;
    FOREACH_CMD(hdr, cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            if(seg->fileoff == 0 && seg->filesize > 0)
            {
                kbase = seg->vmaddr;
            }
            /*if(strcmp("__TEXT_EXEC", seg->segname) == 0)
            {
                mach_sec_t *secs = (mach_sec_t*)(seg + 1);
                for(size_t i = 0; i < seg->nsects; ++i)
                {
                    if(strcmp("initcode", secs[i].sectname) == 0)
                    {
                        initcode = secs[i].addr;
                        break;
                    }
                }
            }*/
            if(strcmp("__PRELINK_TEXT", seg->segname) == 0)
            {
                plk_base = seg->vmaddr;
            }
            else if(strcmp("__PLK_TEXT_EXEC", seg->segname) == 0)
            {
                have_plk_text_exec = true;
            }
            else if(strcmp("__TEXT", seg->segname) == 0)
            {
                mach_sec_t *secs = (mach_sec_t*)(seg + 1);
                for(size_t i = 0; i < seg->nsects; ++i)
                {
                    if(strcmp("__thread_starts", secs[i].sectname) == 0)
                    {
                        chainedFixup = secs[i].size > 0;
                        break;
                    }
                }
            }
        }
        else if(cmd->cmd == LC_SYMTAB)
        {
            mach_stab_t *stab = (mach_stab_t*)cmd;
            symtab = (mach_nlist_t*)((uintptr_t)kernel + stab->symoff);
            strtab = (char*)((uintptr_t)kernel + stab->stroff);
            for(size_t i = 0; i < stab->nsyms; ++i)
            {
                if((symtab[i].n_type & N_TYPE) == N_UNDF || ((symtab[i].n_type & N_STAB) && !(symtab[i].n_type & N_EXT)))
                {
                    continue;
                }
                ++nsyms;
            }
            asyms = malloc(sizeof(*asyms) * nsyms);
            if(asyms)
            {
                bsyms = malloc(sizeof(*bsyms) * nsyms);
            }
            if(!asyms || !bsyms)
            {
                ERRNO("malloc(syms)");
                return -1;
            }
            size_t sidx = 0;
            for(size_t i = 0; i < stab->nsyms; ++i)
            {
                if((symtab[i].n_type & N_TYPE) == N_UNDF || ((symtab[i].n_type & N_STAB) && !(symtab[i].n_type & N_EXT)))
                {
                    continue;
                }
                bsyms[sidx].addr = symtab[i].n_value;
                bsyms[sidx].name = &strtab[symtab[i].n_strx];
                DBG("Symbol: " ADDR " %s", bsyms[sidx].addr, bsyms[sidx].name);
                ++sidx;
            }
            DBG("Got %lu symbols", sidx);
            memcpy(asyms, bsyms, nsyms * sizeof(*bsyms));
            qsort(asyms, nsyms, sizeof(*asyms), &compare_sym_addrs);
            qsort(bsyms, nsyms, sizeof(*bsyms), &compare_sym_names);
            if(hdr->filetype == MH_KEXT_BUNDLE)
            {
                OSMetaClassConstructor    = find_sym_by_name("__ZN11OSMetaClassC2EPKcPKS_j.stub", bsyms, nsyms);
                OSMetaClassAltConstructor = find_sym_by_name("__ZN11OSMetaClassC2EPKcPKS_jPP4zoneS1_19zone_create_flags_t.stub", bsyms, nsyms);
            }
            else
            {
                OSMetaClassConstructor    = find_sym_by_name("__ZN11OSMetaClassC2EPKcPKS_j",                                bsyms, nsyms);
                OSMetaClassAltConstructor = find_sym_by_name("__ZN11OSMetaClassC2EPKcPKS_jPP4zoneS1_19zone_create_flags_t", bsyms, nsyms);
                OSMetaClassVtab           = find_sym_by_name("__ZTV11OSMetaClass",                                          bsyms, nsyms);
                OSObjectVtab              = find_sym_by_name("__ZTV8OSObject",                                              bsyms, nsyms);
                OSObjectGetMetaClass      = find_sym_by_name("__ZNK8OSObject12getMetaClassEv",                              bsyms, nsyms);
                if(OSMetaClassVtab)
                {
                    OSMetaClassVtab += 2 * sizeof(kptr_t);
                    DBG("OSMetaClassVtab: " ADDR, OSMetaClassVtab);
                }
                if(OSObjectVtab)
                {
                    OSObjectVtab += 2 * sizeof(kptr_t);
                    DBG("OSObjectVtab: " ADDR, OSObjectVtab);
                }
                if(OSObjectGetMetaClass)
                {
                    DBG("OSObjectGetMetaClass: " ADDR, OSObjectGetMetaClass);
                }
            }
            if(OSMetaClassConstructor)
            {
                DBG("OSMetaClassConstructor: " ADDR, OSMetaClassConstructor);
            }
            if(OSMetaClassAltConstructor)
            {
                DBG("OSMetaClassAltConstructor: " ADDR, OSMetaClassAltConstructor);
            }
        }
        else if(cmd->cmd == LC_DYSYMTAB)
        {
            dstab = (mach_dstab_t*)cmd;
            // Imports for kexts
            if(hdr->filetype == MH_KEXT_BUNDLE)
            {
                mach_reloc_t *reloc = (mach_reloc_t*)((uintptr_t)kernel + dstab->extreloff);
                for(size_t i = 0; i < dstab->nextrel; ++i)
                {
                    kptr_t addr = kbase + reloc[i].r_address;
                    if(!reloc[i].r_extern)
                    {
                        ERR("External relocation entry %lu at " ADDR " does not have external bit set.", i, addr);
                        return -1;
                    }
                    if(reloc[i].r_length != 0x3)
                    {
                        ERR("External relocation entry %lu at " ADDR " is not 8 bytes.", i, addr);
                        return -1;
                    }
                    DBG("Exreloc " ADDR ": %s", addr, &strtab[symtab[reloc[i].r_symbolnum].n_strx]);
                    if(addr < exreloc_min)
                    {
                        exreloc_min = addr;
                    }
                    if(addr > exreloc_max)
                    {
                        exreloc_max = addr;
                    }
                }
                if(exreloc_min < exreloc_max)
                {
                    DBG("exreloc range: " ADDR "-" ADDR, exreloc_min, exreloc_max);
                    exreloc_max += sizeof(kptr_t);
                    nexreloc = (exreloc_max - exreloc_min) / sizeof(kptr_t);
                    size_t relocsize = sizeof(char*) * nexreloc;
                    exreloc = malloc(relocsize);
                    if(!exreloc)
                    {
                        ERRNO("malloc(exreloc)");
                        return -1;
                    }
                    bzero(exreloc, relocsize);
                    for(size_t i = 0; i < dstab->nextrel; ++i)
                    {
                        exreloc[(kbase + reloc[i].r_address - exreloc_min) / sizeof(kptr_t)] = &strtab[symtab[reloc[i].r_symbolnum].n_strx];
                    }
                }
            }
        }
        else if(cmd->cmd == LC_DYLD_CHAINED_FIXUPS)
        {
            chainedFixup = true;
        }
        else if(cmd->cmd == LC_FILESET_ENTRY)
        {
            mach_fileent_t *ent = (mach_fileent_t*)cmd;
            void *macho = kernel;
            size_t machosize = kernelsize;
            mach_hdr_t *mh = (void*)((uintptr_t)kernel + ent->fileoff);
            const char *name = (const char*)((uintptr_t)ent + ent->nameoff);
            int r = validate_macho(&macho, &machosize, &mh, name);
            if(r != 0)
            {
                return r;
            }
            DBG("Processing kext header of %s", name);
        }
    }
    if(!OSMetaClassConstructor)
    {
        if(hdr->filetype == MH_KEXT_BUNDLE)
        {
            DBG("Failed to find OSMetaClassConstructor symbol, trying relocation instead.");
            OSMetaClassConstructor = find_stub_for_reloc(kernel, hdr, chainedFixup, have_plk_text_exec, exreloc, nexreloc, exreloc_min, "__ZN11OSMetaClassC2EPKcPKS_j");
        }
        else
        {
            DBG("Failed to find OSMetaClassConstructor symbol, falling back to binary matching.");
#define NSTRREF 3
            const char *strs[NSTRREF] = { "IORegistryEntry", "IOService", "IOUserClient" };
            struct
            {
                size_t size;
                size_t idx;
                kptr_t *val;
            } strrefs[NSTRREF];
            for(size_t i = 0; i < NSTRREF; ++i)
            {
                ARRINIT(strrefs[i], 4);
                find_str(kernel, kernelsize, &strrefs[i], strs[i]);
                if(strrefs[i].idx == 0)
                {
                    ERR("Failed to find string: %s", strs[i]);
                    return -1;
                }
            }
            struct
            {
                size_t size;
                size_t idx;
                kptr_t *val;
            } constrCand[2];
            ARRINIT(constrCand[0], 4);
            ARRINIT(constrCand[1], 4);
            size_t constrIdx = 0;
#define constrCandPrev (constrCand[(constrIdx - 1) % 2])
#define constrCandCurr (constrCand[constrIdx % 2])
            for(size_t j = 0; j < NSTRREF; ++j)
            {
                ++constrIdx;
                constrCandCurr.idx = 0;
                FOREACH_CMD(hdr, cmd)
                {
                    if(cmd->cmd == MACH_SEGMENT)
                    {
                        mach_seg_t *seg = (mach_seg_t*)cmd;
                        if(seg->filesize > 0 && SEG_IS_EXEC(seg))
                        {
                            uintptr_t start = (uintptr_t)kernel + seg->fileoff;
                            STEP_MEM(uint32_t, mem, start, seg->filesize, 2)
                            {
                                adr_t     *adr = (adr_t*    )(mem + 0);
                                add_imm_t *add = (add_imm_t*)(mem + 1);
                                if
                                (
                                    (is_adr(adr)  && is_nop(mem + 1) && adr->Rd == 1) ||
                                    (is_adrp(adr) && is_add_imm(add) && adr->Rd == add->Rn && add->Rd == 1)
                                )
                                {
                                    kptr_t refloc = off2addr(kernel, (uintptr_t)adr - (uintptr_t)kernel),
                                           ref    = refloc;
                                    if(is_adrp(adr))
                                    {
                                        ref &= ~0xfff;
                                        ref += get_add_sub_imm(add);
                                    }
                                    ref += get_adr_off(adr);
                                    for(size_t i = 0; i < strrefs[j].idx; ++i)
                                    {
                                        if(ref == strrefs[j].val[i])
                                        {
                                            DBG("Found ref to \"%s\" at " ADDR, strs[j], refloc);
                                            goto look_for_bl;
                                        }
                                    }
                                    continue;
                                    look_for_bl:;
                                    STEP_MEM(uint32_t, m, mem + 2, seg->filesize - ((uintptr_t)(mem + 2) - start), 1)
                                    {
                                        kptr_t bladdr = off2addr(kernel, (uintptr_t)m - (uintptr_t)kernel),
                                               blref  = bladdr;
                                        bl_t *bl = (bl_t*)m;
                                        if(is_bl(bl))
                                        {
                                            a64_state_t state;
                                            if(a64_emulate(kernel, &state, mem, &check_equal, m, true, true, kEmuFnIgnore) != kEmuEnd)
                                            {
                                                // a64_emulate should've printed error already
                                                goto skip;
                                            }
                                            if(!(state.valid & (1 << 1)) || !(state.wide & (1 << 1)) || state.x[1] != ref)
                                            {
                                                DBG("Value of x1 changed, skipping...");
                                                goto skip;
                                            }
                                            blref += get_bl_off(bl);
                                            DBG("Considering constructor " ADDR, blref);
                                            size_t idx = -1;
                                            for(size_t i = 0; i < constrCandCurr.idx; ++i)
                                            {
                                                if(constrCandCurr.val[i] == blref)
                                                {
                                                    idx = i;
                                                    break;
                                                }
                                            }
                                            // If we have this already, just skip
                                            if(idx == -1)
                                            {
                                                // first iteration: collect
                                                // subsequent iterations: eliminate
                                                if(j != 0)
                                                {
                                                    idx = -1;
                                                    for(size_t i = 0; i < constrCandPrev.idx; ++i)
                                                    {
                                                        if(constrCandPrev.val[i] == blref)
                                                        {
                                                            idx = i;
                                                            break;
                                                        }
                                                    }
                                                    if(idx == -1)
                                                    {
                                                        DBG("Candidate " ADDR " not in prev list.", bladdr);
                                                        goto skip;
                                                    }
                                                }
                                                ARRPUSH(constrCandCurr, blref);
                                            }
                                            goto skip;
                                        }
                                        else if(!is_linear_inst(m))
                                        {
                                            WRN("Unexpected instruction at " ADDR, bladdr);
                                            goto skip;
                                        }
                                    }
                                    ERR("Reached end of kernel without finding bl from " ADDR, refloc);
                                    return -1;
                                }
                                skip:;
                            }
                        }
                    }
                }
            }
            if(constrCandCurr.idx > 1)
            {
                ERR("Found more than one possible OSMetaClassConstructor.");
                return -1;
            }
            else if(constrCandCurr.idx == 1)
            {
                OSMetaClassConstructor = constrCandCurr.val[0];
                free(constrCand[0].val);
                free(constrCand[1].val);
                for(size_t i = 0; i < NSTRREF; ++i)
                {
                    free(strrefs[i].val);
                }
            }
            // else fall through to below
#undef constrCandPrev
#undef constrCandCurr
#undef NSTRREF
        }
        if(!OSMetaClassConstructor)
        {
            ERR("Failed to find OSMetaClassConstructor.");
            return -1;
        }
        DBG("OSMetaClassConstructor: " ADDR, OSMetaClassConstructor);
    }
    ARRPUSH(aliases, OSMetaClassConstructor);

    find_imports(kernel, kernelsize, hdr, kbase, chainedFixup, have_plk_text_exec, &aliases, OSMetaClassConstructor);

    ARRDECL(metaclass_t, metas, NUM_METACLASSES_EXPECT);
    ARRDECL(metaclass_candidate_t, namelist, 2 * NUM_METACLASSES_EXPECT);

    find_constructor_calls(kernel, hdr, kbase, chainedFixup, have_plk_text_exec, want_vtabs, &aliases, &metas, &namelist, &constructor_cb, OSMetaClassAltConstructor ? NULL : &OSMetaClassAltConstructor);
    if(OSMetaClassAltConstructor)
    {
        ARRPUSH(altaliases, OSMetaClassAltConstructor);
        find_imports(kernel, kernelsize, hdr, kbase, chainedFixup, have_plk_text_exec, &altaliases, OSMetaClassAltConstructor);
        find_constructor_calls(kernel, hdr, kbase, chainedFixup, have_plk_text_exec, want_vtabs, &altaliases, &metas, &namelist, &alt_constructor_cb, NULL);
    }

    // This is a safety check to make sure we're not missing anything.
    DBG("Got %lu names (probably a ton of dupes)", namelist.idx);
    qsort(namelist.val, namelist.idx, sizeof(*namelist.val), &compare_candidates);
    for(size_t i = 0; i < namelist.idx; ++i)
    {
        metaclass_candidate_t *current = &namelist.val[i];
        if(i > 0)
        {
            // compare_candidates() sorts entries without fncall last, and we set it to NULL if it got us nowhere,
            // so if we have duplicate names and we either lack a fncall or prev still has its one, we can safely skip.
            metaclass_candidate_t *prev = &namelist.val[i - 1];
            if(strcmp(current->name, prev->name) == 0 && (prev->fncall || !current->fncall))
            {
                continue;
            }
        }
        for(size_t j = 0; j < metas.idx; ++j)
        {
            if(strcmp(current->name, metas.val[j].name) == 0)
            {
                goto onward;
            }
        }
        if(current->fncall)
        {
            void *sp = malloc(SPSIZE);
            if(!sp)
            {
                ERR("malloc(sp)");
                return -1;
            }
            a64_state_t state;
            bool success = multi_call_emulate(kernel, current->fncall, current->fncall, &state, sp, 0xf, current->name);
            if(success)
            {
                mach_seg_t *seg = seg4ptr(kernel, current->fncall);
                kptr_t bladdr = seg->vmaddr + ((uintptr_t)current->fncall - ((uintptr_t)kernel + seg->fileoff));
                if((state.wide & 0xf) != 0x7)
                {
                    WRN("Skipping constructor call with unexpected registers width (%x) at " ADDR, state.wide, bladdr);
                    // Fall through
                }
                else
                {
                    DBG("Processing triaged constructor call at " ADDR " (%s)", bladdr, current->name);
                    add_metaclass(kernel, &metas, &state, current->fncall, want_vtabs);
                    free(sp);
                    goto onward;
                }
            }
            free(sp);
            current->fncall = NULL;
            // This is annoying now, but we need to make sure we only print one warning per class.
            if(i + 1 < namelist.idx)
            {
                metaclass_candidate_t *next = &namelist.val[i + 1];
                if(strcmp(current->name, next->name) == 0 && next->fncall)
                {
                    goto onward;
                }
            }
        }
        WRN("Failed to find MetaClass constructor for %s", current->name);
        onward:;
    }
    free(namelist.val);
    namelist.val = NULL;
    namelist.size = namelist.idx = 0;

    DBG("Got %lu metaclasses", metas.idx);
    for(size_t i = 0; i < metas.idx; ++i)
    {
        metaclass_t *meta = &metas.val[i];
        if(meta->parent == 0)
        {
            continue;
        }
        for(size_t j = 0; j < metas.idx; ++j)
        {
            metaclass_t *parent = &metas.val[j];
            if(parent->addr == meta->parent)
            {
                meta->parentP = parent;
                break;
            }
        }
        if(!meta->parentP)
        {
            ERR("Failed to find parent of %s (m: " ADDR ", p: " ADDR ")", meta->name, meta->addr, meta->parent);
            return -1;
        }
    }

    CFTypeRef prelink_info = NULL;
    if(want_vtabs)
    {
        ARRDECLEMPTY(relocrange_t, locreloc);
        if(!chainedFixup)
        {
            size_t nlocrel = 0,
                   relidx  = 0;
            mach_reloc_t *reloc = NULL;
            const kaslrPackedOffsets_t *kaslr = NULL;

            // First pass: learn size
            if(dstab)
            {
                reloc = (mach_reloc_t*)((uintptr_t)kernel + dstab->locreloff);
                nlocrel += dstab->nlocrel;
            }
            if(hdr->filetype == MH_EXECUTE)
            {
                if(!plk_base)
                {
                    ERR("Failed to find PrelinkBase");
                    return -1;
                }

                if(!prelink_info) prelink_info = get_prelink_info(hdr);
                if(!prelink_info) return -1;

                CFDataRef data = CFDictionaryGetValue(prelink_info, CFSTR("_PrelinkLinkKASLROffsets"));
                if(!data || CFGetTypeID(data) != CFDataGetTypeID())
                {
                    ERR("PrelinkLinkKASLROffsets missing or wrong type");
                    return -1;
                }
                kaslr = (const kaslrPackedOffsets_t*)CFDataGetBytePtr(data);
                if(!kaslr)
                {
                    ERR("Failed to get PrelinkLinkKASLROffsets byte pointer");
                    return -1;
                }
                nlocrel += kaslr->count;
#if 0
                CFArrayRef arr = CFDictionaryGetValue(prelink_info, CFSTR("_PrelinkInfoDictionary"));
                if(!arr || CFGetTypeID(arr) != CFArrayGetTypeID())
                {
                    ERR("PrelinkInfoDictionary missing or wrong type");
                    return -1;
                }
                CFIndex arrlen = CFArrayGetCount(arr);
                for(size_t i = 0; i < arrlen; ++i)
                {
                    CFDictionaryRef dict = CFArrayGetValueAtIndex(arr, i);
                    if(!dict || CFGetTypeID(dict) != CFDictionaryGetTypeID())
                    {
                        WRN("Array entry %lu is not a dict.", i);
                        continue;
                    }
                    CFNumberRef cfnum = CFDictionaryGetValue(dict, CFSTR("_PrelinkExecutableLoadAddr"));
                    if(!cfnum)
                    {
                        DBG("Kext %lu has no PrelinkExecutableLoadAddr, skipping...", i);
                        continue;
                    }
                    if(CFGetTypeID(cfnum) != CFNumberGetTypeID())
                    {
                        WRN("PrelinkExecutableLoadAddr missing or wrong type for kext %lu", i);
                        continue;
                    }
                    kptr_t kext_base = 0;
                    if(!CFNumberGetValue(cfnum, kCFNumberLongLongType, &kext_base))
                    {
                        WRN("Failed to get CFNumber contents for kext %lu", i);
                        continue;
                    }
                    mach_hdr_t *hdr2 = addr2ptr(kernel, kext_base);
                    if(!hdr2)
                    {
                        WRN("Failed to translate kext header address " ADDR, kext_base);
                        continue;
                    }
                    FOREACH_CMD(hdr2, cmd2)
                    {
                        if(cmd2->cmd == LC_DYSYMTAB)
                        {
                            nlocrel += ((mach_dstab_t*)cmd2)->nlocrel;
                            break;
                        }
                    }
                }
#endif
            }
            DBG("Got %lu local relocations", nlocrel);

            // Alloc mem
            kptr_t *tmp = malloc(nlocrel * sizeof(kptr_t));
            if(!tmp)
            {
                ERRNO("malloc(tmp/locreloc)");
            }

            // Second pass: copy out
            if(dstab)
            {
                for(size_t i = 0; i < dstab->nlocrel; ++i)
                {
                    int32_t off = reloc[i].r_address;
                    if(reloc[i].r_extern)
                    {
                        ERR("Local relocation entry %lu at 0x%x has external bit set.", i, off);
                        return -1;
                    }
                    if(reloc[i].r_length != 0x3)
                    {
                        ERR("Local relocation entry %lu at 0x%x is not 8 bytes.", i, off);
                        return -1;
                    }
                    kptr_t addr = kbase + off;
                    DBG("Locreloc 0x%x: " ADDR, off, addr);
                    tmp[relidx++] = addr;
                }
            }
            if(kaslr)
            {
                for(size_t i = 0; i < kaslr->count; ++i)
                {
                    kptr_t addr = plk_base + kaslr->offsetsArray[i];
                    DBG("KASLR reloc %lu: " ADDR, i, addr);
                    tmp[relidx++] = addr;
                }
            }
#if 0
            if(prelink_info)
            {
                CFArrayRef arr = CFDictionaryGetValue(prelink_info, CFSTR("_PrelinkInfoDictionary"));
                CFIndex arrlen = CFArrayGetCount(arr);
                for(size_t j = 0; j < arrlen; ++j)
                {
                    CFDictionaryRef dict = CFArrayGetValueAtIndex(arr, j);
                    if(!dict || CFGetTypeID(dict) != CFDictionaryGetTypeID())
                    {
                        continue;
                    }
                    CFNumberRef cfnum = CFDictionaryGetValue(dict, CFSTR("_PrelinkExecutableLoadAddr"));
                    if(!cfnum)
                    {
                        continue;
                    }
                    if(CFGetTypeID(cfnum) != CFNumberGetTypeID())
                    {
                        continue;
                    }
                    kptr_t kext_base = 0;
                    if(!CFNumberGetValue(cfnum, kCFNumberLongLongType, &kext_base))
                    {
                        continue;
                    }
                    mach_hdr_t *hdr2 = addr2ptr(kernel, kext_base);
                    if(!hdr2)
                    {
                        continue;
                    }
                    void *kext_linkedit = NULL;
                    FOREACH_CMD(hdr2, cmd2)
                    {
                        if(cmd2->cmd == MACH_SEGMENT)
                        {
                            mach_seg_t *seg = (mach_seg_t*)cmd2;
                            if(strcmp("__LINKEDIT", seg->segname) == 0)
                            {
                                // Don't ask why, this is just how it's done in XNU src
                                kext_linkedit = addr2ptr(kernel, seg->vmaddr - seg->fileoff);
                                //kext_linkedit = addr2ptr(kernel, seg->vmaddr);
                                break;
                            }
                        }
                    }
                    if(!kext_linkedit)
                    {
                        continue;
                    }
                    FOREACH_CMD(hdr2, cmd2)
                    {
                        if(cmd2->cmd == LC_DYSYMTAB)
                        {
                            mach_dstab_t *kext_dstab = (mach_dstab_t*)cmd2;
                            mach_reloc_t *kext_reloc = (mach_reloc_t*)((uintptr_t)kext_linkedit + kext_dstab->locreloff);
                            for(size_t i = 0; i < kext_dstab->nlocrel; ++i)
                            {
                                int32_t off = kext_reloc[i].r_address;
                                if(kext_reloc[i].r_extern)
                                {
                                    ERR("Kext %lu Local relocation entry %lu at 0x%x has external bit set.", j, i, off);
                                    return -1;
                                }
                                if(kext_reloc[i].r_length != 0x3)
                                {
                                    ERR("Kext %lu Local relocation entry %lu at 0x%x is not 8 bytes.", j, i, off);
                                    return -1;
                                }
                                kptr_t addr = kext_base + off;
                                DBG("Kext %lu locreloc 0x%x: " ADDR, j, off, addr);
                                tmp[relidx++] = addr;
                            }
                            break;
                        }
                    }
                }
            }
#endif

            // Squash and merge
            qsort(tmp, nlocrel, sizeof(*tmp), &compare_addrs);
            ARRINIT(locreloc, 0x1000);
            relocrange_t *range = NULL;
            ARRNEXT(locreloc, range);
            range->from = range->to = tmp[0];
            for(size_t i = 1; i < nlocrel; ++i)
            {
                kptr_t val = tmp[i];
                if(val == range->to + sizeof(kptr_t))
                {
                    range->to = val;
                }
                else
                {
                    ARRNEXT(locreloc, range);
                    range->from = range->to = val;
                }
            }
            free(tmp);
            DBG("Got %lu locreloc ranges", locreloc.idx);
        }

        metaclass_t *metaclassHandle = NULL;
        kptr_t OSMetaClassMetaClass = 0;
        for(size_t i = 0; i < metas.idx; ++i)
        {
            if(strcmp(metas.val[i].name, "OSMetaClass") == 0)
            {
                if(OSMetaClassVtab)
                {
                    metas.val[i].vtab = OSMetaClassVtab;
                }
                OSMetaClassMetaClass = metas.val[i].addr;
                metaclassHandle = &metas.val[i];
                break;
            }
        }

        if(hdr->filetype == MH_KEXT_BUNDLE)
        {
            for(size_t i = 0; i < nsyms; ++i)
            {
                if(strncmp(bsyms[i].name, "__ZTV", 5) == 0)
                {
                    char *str = NULL;
                    asprintf(&str, "__ZNK%s12getMetaClassEv", bsyms[i].name + 5);
                    if(!str)
                    {
                        ERRNO("asprintf(ZNK)");
                        return -1;
                    }
                    kptr_t znk = find_sym_by_name(str, bsyms, nsyms);
                    if(znk)
                    {
                        OSObjectVtab = bsyms[i].addr + 2 * sizeof(kptr_t);
                        OSObjectGetMetaClass = znk;
                        DBG("%s: " ADDR, bsyms[i].name, OSObjectVtab);
                        DBG("%s: " ADDR, str, OSObjectGetMetaClass);
                        free(str);
                        goto after;
                    }
                    free(str);
                }
            }
            after:;
        }
        else
        {
            if((metaclassHandle && !metaclassHandle->vtab) || !OSObjectVtab)
            {
                DBG("Missing OSMetaClass vtab, falling back to binary matching.");

                FOREACH_CMD(hdr, cmd)
                {
                    if(cmd->cmd == MACH_SEGMENT)
                    {
                        mach_seg_t *seg = (mach_seg_t*)cmd;
                        if(seg->vmaddr <= OSMetaClassConstructor && seg->vmaddr + seg->vmsize > OSMetaClassConstructor)
                        {
                            kptr_t inset = (OSMetaClassConstructor - seg->vmaddr);
                            uint32_t *start = kernel + seg->fileoff + inset;
                            STEP_MEM(uint32_t, mem, (uintptr_t)start, seg->filesize - inset, 1)
                            {
                                str_uoff_t *str = (str_uoff_t*)mem;
                                if(is_str_uoff(str) && get_str_uoff(str) == 0)
                                {
                                    a64_state_t state;
                                    for(size_t i = 0; i < 32; ++i)
                                    {
                                        state.x[i] = 0;
                                        state.q[i] = 0;
                                    }
                                    state.valid = 1;
                                    state.qvalid = 0;
                                    state.wide = 1;
                                    state.host = 0;
                                    if(a64_emulate(kernel, &state, start, &check_equal, mem, false, true, kEmuFnIgnore) == kEmuEnd)
                                    {
                                        if(!(state.valid & (1 << str->Rn)) || !(state.wide & (1 << str->Rn)) || !(state.valid & (1 << str->Rt)) || !(state.wide & (1 << str->Rt)))
                                        {
                                            DBG("Bad valid/wide flags (%x/%x)", state.valid, state.wide);
                                        }
                                        else
                                        {
                                            OSMetaClassVtab = state.x[str->Rt];
                                            DBG("OSMetaClassVtab " ADDR, OSMetaClassVtab);
                                            if(metaclassHandle && !metaclassHandle->vtab)
                                            {
                                                metaclassHandle->vtab = OSMetaClassVtab;
                                            }
                                        }
                                    }
                                    break;
                                }
                                if(!is_linear_inst(mem))
                                {
                                    DBG("Bailing out due to non-linear instr at " ADDR, OSMetaClassConstructor + ((uintptr_t)mem - (uintptr_t)start));
                                    break;
                                }
                            }
                            break;
                        }
                    }
                }
            }
            if(!OSObjectVtab && !OSObjectGetMetaClass && OSMetaClassMetaClass) // Must happen together
            {
                DBG("Missing OSObject vtab and OSObject::getMetaClass, falling back to binary matching.");

                // vtab
                OSObjectVtab = OSMetaClassVtab;

                // getMetaClass
                FOREACH_CMD(hdr, cmd)
                {
                    if(cmd->cmd == MACH_SEGMENT)
                    {
                        mach_seg_t *seg = (mach_seg_t*)cmd;
                        if(seg->filesize > 0 && SEG_IS_EXEC(seg))
                        {
                            STEP_MEM(uint32_t, mem, (uintptr_t)kernel + seg->fileoff, seg->filesize, 3)
                            {
                                adr_t     *adr = (adr_t*    )(mem + 0);
                                add_imm_t *add = (add_imm_t*)(mem + 1);
                                ret_t     *ret = (ret_t*    )(mem + 2);
                                if
                                (
                                    is_ret(ret) &&
                                    (
                                        (is_adr(adr) && is_nop(mem + 1) && adr->Rd == 0) ||
                                        (is_adrp(adr) && is_add_imm(add) && adr->Rd == add->Rn && add->Rd == 0)
                                    )
                                )
                                {
                                    kptr_t refloc = off2addr(kernel, (uintptr_t)adr - (uintptr_t)kernel),
                                           ref    = refloc;
                                    if(is_adrp(adr))
                                    {
                                        ref &= ~0xfff;
                                        ref += get_add_sub_imm(add);
                                    }
                                    ref += get_adr_off(adr);
                                    if(ref == OSMetaClassMetaClass)
                                    {
                                        if(OSObjectGetMetaClass == -1)
                                        {
                                            ERR("More than one candidate for OSMetaClass::getMetaClass: " ADDR, refloc);
                                        }
                                        else if(OSObjectGetMetaClass != 0)
                                        {
                                            ERR("More than one candidate for OSMetaClass::getMetaClass: " ADDR, OSObjectGetMetaClass);
                                            ERR("More than one candidate for OSMetaClass::getMetaClass: " ADDR, refloc);
                                            OSObjectGetMetaClass = -1;
                                        }
                                        else
                                        {
                                            DBG("OSMetaClass::getMetaClass: " ADDR, refloc);
                                            OSObjectGetMetaClass = refloc;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if(OSObjectGetMetaClass == -1)
                {
                    OSObjectGetMetaClass = 0;
                }
            }
        }
        size_t VtabGetMetaClassIdx = 0;
        // block for variable scoping
        {
            if(!OSObjectVtab)
            {
                ERR("Failed to find OSObjectVtab.");
                return -1;
            }
            if(!OSObjectGetMetaClass)
            {
                ERR("Failed to find OSObjectGetMetaClass.");
                return -1;
            }
            kptr_t *ovtab = addr2ptr(kernel, OSObjectVtab);
            if(!ovtab)
            {
                ERR("OSObjectVtab lies outside all segments.");
                return -1;
            }
            for(size_t i = 0; hdr->filetype == MH_KEXT_BUNDLE || ovtab[i] != 0; ++i) // TODO: fix dirty hack
            {
                if(kuntag(kbase, chainedFixup, ovtab[i], NULL) == OSObjectGetMetaClass)
                {
                    VtabGetMetaClassIdx = i;
                    DBG("VtabGetMetaClassIdx: 0x%lx", VtabGetMetaClassIdx);
                    break;
                }
            }
            if(!VtabGetMetaClassIdx)
            {
                ERR("Failed to find OSObjectGetMetaClass in OSObjectVtab.");
                return -1;
            }
        }

        size_t VtabAllocIdx = 0;
        if(hdr->filetype != MH_KEXT_BUNDLE)
        {
            do
            {
                pure_virtual = find_sym_by_name("___cxa_pure_virtual", bsyms, nsyms);
                if(pure_virtual)
                {
                    break;
                }

                ARRDECL(kptr_t, strref, 4);
                find_str(kernel, kernelsize, &strref, "__cxa_pure_virtual");
                if(strref.idx == 0)
                {
                    DBG("Failed to find string: __cxa_pure_virtual");
                    break;
                }
                DBG("Found \"__cxa_pure_virtual\" %lu times", strref.idx);

                FOREACH_CMD(hdr, cmd)
                {
                    if(cmd->cmd == MACH_SEGMENT)
                    {
                        mach_seg_t *seg = (mach_seg_t*)cmd;
                        if(seg->filesize > 0 && SEG_IS_EXEC(seg))
                        {
                            uintptr_t start = (uintptr_t)kernel + seg->fileoff;
                            STEP_MEM(uint32_t, mem, start, seg->filesize, 6)
                            {
                                adr_t      *adr1 = (adr_t*     )(mem + 0);
                                add_imm_t  *add1 = (add_imm_t* )(mem + 1);
                                str_imm_t  *stri = (str_imm_t* )(mem + 2);
                                str_uoff_t *stru = (str_uoff_t*)(mem + 2);
                                adr_t      *adr2 = (adr_t*     )(mem + 3);
                                add_imm_t  *add2 = (add_imm_t* )(mem + 4);
                                bl_t       *bl   = (bl_t*      )(mem + 5);
                                if
                                (
                                    is_bl(bl) &&
                                    (
                                        (is_adr(adr2)  && is_nop(mem + 4)  && adr2->Rd == 0) ||
                                        (is_adrp(adr2) && is_add_imm(add2) && adr2->Rd == add2->Rn && add2->Rd == 0)
                                    ) &&
                                    (
                                        (is_str_uoff(stru) && stru->Rn == 31 && get_str_uoff(stru) == 0) ||
                                        (is_str_pre(stri)  && stri->Rn == 31)
                                    ) &&
                                    (
                                        // stri and stru have Rt and Rn at same offsets
                                        (is_adr(adr1)  && is_nop(mem + 1)  && adr1->Rd == stru->Rt) ||
                                        (is_adrp(adr1) && is_add_imm(add1) && adr1->Rd == add1->Rn && add1->Rd == stru->Rt)
                                    )
                                )
                                {
                                    kptr_t refloc = off2addr(kernel, (uintptr_t)adr1 - (uintptr_t)kernel),
                                           ref1   = refloc,
                                           ref2   = refloc + 3 * sizeof(uint32_t);
                                    if(is_adrp(adr1))
                                    {
                                        ref1 &= ~0xfff;
                                        ref1 += get_add_sub_imm(add1);
                                    }
                                    ref1 += get_adr_off(adr1);
                                    for(size_t i = 0; i < strref.idx; ++i)
                                    {
                                        if(ref1 == strref.val[i])
                                        {
                                            DBG("Found ref to \"__cxa_pure_virtual\" at " ADDR, refloc);
                                            goto ref_matches;
                                        }
                                    }
                                    continue;

                                    ref_matches:;
                                    if(is_adrp(adr2))
                                    {
                                        ref2 &= ~0xfff;
                                        ref2 += get_add_sub_imm(add2);
                                    }
                                    ref2 += get_adr_off(adr2);
                                    const char *x0 = addr2ptr(kernel, ref2);
                                    if(strcmp(x0, "\"%s\"") != 0)
                                    {
                                        DBG("__cxa_pure_virtual: x0 != \"%%s\"");
                                        continue;
                                    }

                                    uint32_t *loc = mem;
                                    add_imm_t *add = (add_imm_t*)(loc - 1);
                                    if(!(is_add_imm(add) && add->Rd == 29 && add->Rn == 31)) // ignore add amount
                                    {
                                        DBG("__cxa_pure_virtual: add x29, sp, ...");
                                        continue;
                                    }
                                    loc--;
                                    refloc -= sizeof(uint32_t);

                                    stp_t *stp = (stp_t*)(loc - 1);
                                    if(!((is_stp_uoff(stp) || is_stp_pre(stp)) && stp->Rt == 29 && stp->Rt2 == 30 && stp->Rn == 31))
                                    {
                                        DBG("__cxa_pure_virtual: stp x29, x30, [sp, ...]");
                                        continue;
                                    }
                                    loc--;
                                    refloc -= sizeof(uint32_t);

                                    if(is_stp_uoff(stp))
                                    {
                                        sub_imm_t *sub = (sub_imm_t*)(loc - 1);
                                        if(!(is_sub_imm(sub) && sub->Rd == 31 && sub->Rn == 31))
                                        {
                                            DBG("__cxa_pure_virtual: sub sp, sp, ...");
                                            continue;
                                        }
                                        loc--;
                                        refloc -= sizeof(uint32_t);
                                    }
                                    pacsys_t *pac = (pacsys_t*)(loc - 1);
                                    if(is_pacsys(pac))
                                    {
                                        loc--;
                                        refloc -= sizeof(uint32_t);
                                    }
                                    if(pure_virtual == -1)
                                    {
                                        DBG("__cxa_pure_virtual candidate: " ADDR, refloc);
                                    }
                                    else if(pure_virtual != 0)
                                    {
                                        DBG("__cxa_pure_virtual candidate: " ADDR, pure_virtual);
                                        DBG("__cxa_pure_virtual candidate: " ADDR, refloc);
                                        pure_virtual = -1;
                                    }
                                    else
                                    {
                                        pure_virtual = refloc;
                                    }
                                }
                            }
                        }
                    }
                }
            } while(0);
            if(pure_virtual == -1)
            {
                WRN("Multiple __cxa_pure_virtual candidates!");
                pure_virtual = 0;
            }
            else if(pure_virtual)
            {
                DBG("__cxa_pure_virtual: " ADDR, pure_virtual);
            }
            else
            {
                WRN("Failed to find __cxa_pure_virtual");
            }

            if(pure_virtual && OSMetaClassVtab)
            {
                kptr_t *ovtab = addr2ptr(kernel, OSMetaClassVtab);
                if(!ovtab)
                {
                    ERR("OSMetaClassVtab lies outside all segments.");
                    return -1;
                }
                for(size_t i = 0; ovtab[i] != 0; ++i)
                {
                    if(kuntag(kbase, chainedFixup, ovtab[i], NULL) == pure_virtual)
                    {
                        VtabAllocIdx = i;
                        DBG("VtabAllocIdx: 0x%lx", VtabAllocIdx);
                        break;
                    }
                }
                if(!VtabAllocIdx)
                {
                    ERR("Failed to find OSMetaClassAlloc in OSMetaClassVtab.");
                    return -1;
                }
            }
        }

        ARRDECL(kptr_t, candidates, 0x100);
        FOREACH_CMD(hdr, cmd)
        {
            if(cmd->cmd == MACH_SEGMENT)
            {
                mach_seg_t *seg = (mach_seg_t*)cmd;
                if(seg->filesize > 0 && SEG_IS_EXEC(seg))
                {
                    STEP_MEM(uint32_t, mem, (uintptr_t)kernel + seg->fileoff, seg->filesize, 2)
                    {
                        adr_t *adr = (adr_t*)mem;
                        add_imm_t *add = (add_imm_t*)(mem + 1);
                        add_imm_t *add2 = (add_imm_t*)(mem + 2);
                        nop_t *nop = (nop_t*)(mem + 1);
                        ret_t *ret1 = (ret_t*)(mem + 1);
                        ret_t *ret2 = (ret_t*)(mem + 2);
                        ret_t *ret3 = (ret_t*)(mem + 3);
                        bool iz_adrp = is_adrp(adr),
                             iz_add  = is_add_imm(add);
                        if
                        (
                            (iz_adrp && iz_add && is_ret(ret2) && adr->Rd == add->Rn && add->Rd == 0) ||
                            (is_adr(adr) && (is_ret(ret1) || (is_nop(nop) && is_ret(ret2))) && adr->Rd == 0) ||
                            (is_ret(ret3) && is_add_imm(add2) && iz_add && iz_adrp && add2->Rd == 0 && add2->Rn == add->Rd && adr->Rd == add->Rn) // iOS 9
                        )
                        {
                            kptr_t func = seg->vmaddr + ((uintptr_t)adr - ((uintptr_t)kernel + seg->fileoff)),
                                   addr = func;
                            if(iz_adrp)
                            {
                                addr &= ~0xfff;
                            }
                            if(iz_add)
                            {
                                addr += get_adr_off(adr);
                                addr += get_add_sub_imm(add);
                                if(is_add_imm(add2))
                                {
                                    addr += get_add_sub_imm(add2);
                                }
                            }
                            else
                            {
                                addr += get_adr_off(adr);
                            }
                            if(addr != OSMetaClassMetaClass)
                            {
                                for(size_t i = 0; i < metas.idx; ++i)
                                {
                                    metaclass_t *meta = &metas.val[i];
                                    if(meta->addr == addr)
                                    {
                                        DBG("Got func " ADDR " referencing MetaClass %s", func, meta->name);
                                        candidates.idx = 0;
                                        FOREACH_CMD(hdr, cmd2)
                                        {
                                            if(cmd2->cmd == MACH_SEGMENT)
                                            {
                                                mach_seg_t *seg2 = (mach_seg_t*)cmd2;
                                                if
                                                (
                                                    seg2->filesize > (VtabGetMetaClassIdx + 2) * sizeof(kptr_t) &&
                                                    (strcmp("__DATA", seg2->segname) == 0 || strcmp("__DATA_CONST", seg2->segname) == 0 || strcmp("__PRELINK_DATA", seg2->segname) == 0 || strcmp("__PLK_DATA_CONST", seg2->segname) == 0)
                                                )
                                                {
                                                    STEP_MEM(kptr_t, mem2, (kptr_t*)((uintptr_t)kernel + seg2->fileoff) + VtabGetMetaClassIdx + 2, seg2->filesize - (VtabGetMetaClassIdx + 2) * sizeof(kptr_t), 1)
                                                    {
                                                        if(kuntag(kbase, chainedFixup, *mem2, NULL) == func && *(mem2 - VtabGetMetaClassIdx - 1) == 0 && *(mem2 - VtabGetMetaClassIdx - 2) == 0)
                                                        {
                                                            kptr_t ref = off2addr(kernel, (uintptr_t)(mem2 - VtabGetMetaClassIdx) - (uintptr_t)kernel);
                                                            if(meta->vtab == 0)
                                                            {
                                                                meta->vtab = ref;
                                                            }
                                                            else
                                                            {
                                                                if(meta->vtab != -1)
                                                                {
                                                                    DBG("More than one vtab for %s: " ADDR, meta->name, meta->vtab);
                                                                    ARRPUSH(candidates, meta->vtab);
                                                                    meta->vtab = -1;
                                                                }
                                                                DBG("More than one vtab for %s: " ADDR, meta->name, ref);
                                                                ARRPUSH(candidates, ref);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        free(candidates.val);
        candidates.val = NULL;
        candidates.size = candidates.idx = 0;

        for(size_t i = 0; i < metas.idx; ++i)
        {
            metaclass_t *meta = &metas.val[i];
            if((meta->vtab == 0 || meta->vtab == -1) && meta->metavtab && VtabAllocIdx)
            {
                DBG("Attempting to get vtab via %s::MetaClass::alloc", meta->name);
                kptr_t *ovtab = addr2ptr(kernel, meta->metavtab);
                if(!ovtab)
                {
                    ERR("Metavtab of %s lies outside all segments.", meta->name);
                    return -1;
                }
                kptr_t fnaddr = kuntag(kbase, chainedFixup, ovtab[VtabAllocIdx], NULL);
                if(fnaddr != pure_virtual)
                {
                    DBG("Got %s::MetaClass::alloc at " ADDR, meta->name, fnaddr);
                    FOREACH_CMD(hdr, cmd)
                    {
                        if(cmd->cmd == MACH_SEGMENT)
                        {
                            mach_seg_t *seg = (mach_seg_t*)cmd;
                            if(seg->vmaddr <= fnaddr && seg->vmaddr + seg->filesize > fnaddr)
                            {
                                uint32_t *end     = (uint32_t*)((uintptr_t)kernel + seg->fileoff + seg->filesize),
                                         *fnstart = (uint32_t*)((uintptr_t)kernel + seg->fileoff + (fnaddr - seg->vmaddr));
                                void *sp = malloc(SPSIZE),
                                     *obj = NULL;
                                if(!sp)
                                {
                                    ERR("malloc(sp)");
                                    return -1;
                                }
                                uint32_t *m = NULL;
                                a64_state_t state;
                                for(size_t i = 0; i < 32; ++i)
                                {
                                    state.x[i] = 0;
                                    state.q[i] = 0;
                                }
                                state.x[ 0]  = 0x6174656d656b6166; // "fakemeta", fake "this" ptr
                                state.x[31]  = (uintptr_t)sp + SPSIZE;
                                state.valid  = 0xfff80001;
                                state.qvalid = 0x0000ff00;
                                state.wide   = 0xfff80001;
                                state.host   = 0x80000000;
                                switch(a64_emulate(kernel, &state, fnstart, &check_bl, &m, false, true, kEmuFnIgnore))
                                {
                                    case kEmuRet:
                                        if((state.valid & 0x1) == 0x1 && (state.wide & 0x1) == 0x1 && state.x[0] == 0x0)
                                        {
                                            DBG("Ignoring %s::MetaClass::alloc that returns NULL", meta->name);
                                        }
                                        else
                                        {
                                            WRN("Unexpected ret in %s::MetaClass::alloc", meta->name);
                                        }
                                        break;
                                    case kEmuEnd:
                                        {
                                            kptr_t allocsz;
                                            if((state.valid & 0xff) == 0x7 && (state.wide & 0x7) == 0x5 && (state.host & 0x1) == 0x1) // kalloc
                                            {
                                                allocsz = *(kptr_t*)state.x[0];
                                            }
                                            else if((state.valid & 0xff) == 0x1 && (state.wide & 0x1) == 0x0) // new
                                            {
                                                allocsz = state.x[0];
                                            }
                                            else if((state.valid & 0xff) == 0xf && (state.wide & 0xf) == 0x9) // hell do I know
                                            {
                                                allocsz = state.x[1];
                                            }
                                            else
                                            {
                                                if(meta->vtab == -1)
                                                {
                                                    WRN("Bad pre-bl state in %s::MetaClass::alloc (%08x %08x %08x)", meta->name, state.valid, state.wide, state.host);
                                                }
                                                break;
                                            }
                                            if(allocsz != meta->objsize)
                                            {
                                                if(meta->vtab == -1)
                                                {
                                                    WRN("Alloc has wrong size in %s::MetaClass::alloc (0x%llx vs 0x%x)", meta->name, allocsz, meta->objsize);
                                                }
                                                break;
                                            }
                                            if(a64_emulate(kernel, &state, m, &check_equal, m + 1, false, true, kEmuFnIgnore) != kEmuEnd)
                                            {
                                                break;
                                            }
                                            obj = malloc(allocsz);
                                            if(!obj)
                                            {
                                                ERR("malloc(obj)");
                                                return -1;
                                            }
                                            bzero(obj, allocsz);
                                            state.x[0] = (uintptr_t)obj;
                                            state.valid |= 0x1;
                                            state.wide  |= 0x1;
                                            state.host  |= 0x1;
                                            if(a64_emulate(kernel, &state, m + 1, &check_equal, end, false, true, kEmuFnAssumeX0) != kEmuRet)
                                            {
                                                break;
                                            }
                                            if(!(state.valid & 0x1) || !(state.wide & 0x1) || !(state.host & 0x1))
                                            {
                                                WRN("Bad end state in %s::MetaClass::alloc (%08x %08x %08x)", meta->name, state.valid, state.wide, state.host);
                                                break;
                                            }
                                            kptr_t vt = *(kptr_t*)state.x[0];
                                            if(!vt)
                                            {
                                                WRN("Failed to capture vtab via %s::MetaClass::alloc", meta->name);
                                                break;
                                            }
                                            meta->vtab = vt;
                                        }
                                    default:
                                        break;
                                }
                                if(obj) free(obj);
                                free(sp);
                                break;
                            }
                        }
                    }
                }
            }
        }
        for(size_t i = 0; i < metas.idx; ++i)
        {
            if(metas.val[i].vtab == -1)
            {
                WRN("Multiple vtab candidates for %s", metas.val[i].name);
            }
        }

        if(opt.overrides || opt.ofilt)
        {
            for(size_t i = 0; i < metas.idx; ++i)
            {
                again:;
                bool do_again = false;
                metaclass_t *meta = &metas.val[i],
                            *parent = meta->parentP;
                if(meta->methods_done || meta->methods_err)
                {
                    goto done;
                }
                if(parent)
                {
                    while(!parent->methods_err && !parent->methods_done)
                    {
                        do_again = true;
                        meta = parent;
                        parent = meta->parentP;
                        if(!parent)
                        {
                            break;
                        }
                    }
                    if(parent && parent->methods_err)
                    {
                        WRN("Skipping class %s because parent class was skipped.", meta->name);
                        meta->methods_err = 1;
                        goto done;
                    }
                    while(parent && parent->vtab == 0) // Fall through on abstract classes
                    {
                        parent = parent->parentP;
                    }
                }
                if(symmap.map)
                {
                    symmap_class_t *symcls = bsearch(meta->name, symmap.map, symmap.num, sizeof(*symmap.map), &compare_symclass_name);
                    if(symcls)
                    {
                        while(symcls->duplicate)
                        {
                            --symcls;
                        }
                        if(symcls->metaclass)
                        {
                            DBG("Symmap entry for %s has metaclass set already (%s).", meta->name, symcls->metaclass->name);
                        }
                        else
                        {
                            symcls->metaclass = meta;
                        }
                        meta->symclass = symcls;
                    }
                }
                if(meta->vtab == 0)
                {
                    meta->methods_done = 1;
                    if(meta->symclass && meta->symclass->num != 0)
                    {
                        WRN("Symmap entry for %s has %lu methods, but class has no vtab.", meta->name, meta->symclass->num);
                    }
                    goto done;
                }
                if(meta->vtab == -1)
                {
                    WRN("Skipping class %s because vtable is missing.", meta->name);
                    meta->methods_err = 1;
                    goto done;
                }
                // Parent is guaranteed to either be NULL or have a valid vtab here
                kptr_t *mvtab = addr2ptr(kernel, meta->vtab);
                if(!mvtab)
                {
                    WRN("%s vtab lies outside all segments.", meta->name);
                    meta->methods_err = 1;
                    goto done;
                }
                size_t nmeth = 0;
                while(is_part_of_vtab(kernel, chainedFixup, locreloc.val, locreloc.idx, exreloc, exreloc_min, exreloc_max, mvtab, meta->vtab, nmeth))
                {
                    ++nmeth;
                }
                size_t pnmeth = parent ? parent->nmethods : 0;
                if(nmeth < pnmeth)
                {
                    WRN("%s has fewer methods than its parent.", meta->name);
                    meta->methods_err = 1;
                    goto done;
                }
                meta->methods = malloc(nmeth * sizeof(*meta->methods));
                if(!meta->methods)
                {
                    ERRNO("malloc(methods)");
                    return -1;
                }
                meta->nmethods = nmeth;
                bool ignore_symmap = false;
                if(meta->symclass)
                {
                    symmap_class_t *symcls = meta->symclass;
                    if(hdr->filetype == MH_KEXT_BUNDLE)
                    {
                        if(symcls->num > nmeth)
                        {
                            WRN("Symmap entry for %s has %lu methods, vtab has %lu.", meta->name, symcls->num, nmeth);
                            ignore_symmap = true;
                        }
                        else
                        {
                            pnmeth = nmeth - symcls->num;
                        }
                    }
                    else if(symcls->num + pnmeth != nmeth)
                    {
                        WRN("Symmap entry for %s has %lu methods, vtab has %lu.", meta->name, symcls->num, nmeth - pnmeth);
                        ignore_symmap = true;
                    }
                }
                for(size_t idx = 0; idx < nmeth; ++idx)
                {
                    vtab_entry_t *ent   = &meta->methods[idx],
                                 *pent  = (parent && idx < parent->nmethods) ? &parent->methods[idx] : NULL,
                                 *chain = NULL;
                    kptr_t func = 0;
                    const char *cxx_sym = NULL,
                               *class   = NULL,
                               *method  = NULL;
                    uint16_t pac;
                    bool structor      = false,
                         authoritative = false,
                         placeholder   = false,
                         overrides     = false;

                    kptr_t koff = meta->vtab + sizeof(kptr_t) * idx;
                    bool is_in_exreloc = koff >= exreloc_min && koff < exreloc_max && exreloc[(koff - exreloc_min) / sizeof(kptr_t)] != NULL;
                    if(is_in_exreloc)
                    {
                        cxx_sym = exreloc[(koff - exreloc_min) / sizeof(kptr_t)];
                    }
                    else
                    {
                        func = kuntag(kbase, chainedFixup, mvtab[idx], &pac);
                        cxx_sym = find_sym_by_addr(func, asyms, nsyms);
                        overrides = !pent || func != pent->addr;
                    }
                    if((cxx_sym && strcmp(cxx_sym, "___cxa_pure_virtual") == 0) || (pure_virtual && func == pure_virtual))
                    {
                        func = -1;
                    }
                    if(!ignore_symmap && idx >= pnmeth && meta->symclass)
                    {
                        symmap_method_t *smeth = &meta->symclass->methods[idx - pnmeth];
                        class = smeth->class;
                        method = smeth->method;
                        structor = smeth->structor;
                        if(method)
                        {
                            authoritative = true;
                        }
                        else
                        {
                            placeholder = true;
                        }
                    }
                    if(!method && func != -1)
                    {
                        if(cxx_sym)
                        {
                            DBG("Got symbol for virtual function " ADDR ": %s", func, cxx_sym);
                            if(!cxx_demangle(cxx_sym, &class, &method, &structor))
                            {
                                if(is_in_exreloc)
                                {
                                    WRN("Failed to demangle symbol: %s (from reloc)", cxx_sym);
                                }
                                else
                                {
                                    WRN("Failed to demangle symbol: %s (from symtab, addr " ADDR ")", cxx_sym, func);
                                }
                            }
                            else
                            {
                                authoritative = true;
                            }
                        }
                        else
                        {
                            DBG("Found no symbol for virtual function " ADDR, func);
                        }
                    }
                    if(!is_in_exreloc) // TODO: reloc parent?
                    {
                        if(pent && pac != pent->pac && func != -1 && pent->addr != -1) // ignore pure_virtual
                        {
                            WRN("PAC mismatch method 0x%lx: %s 0x%04hx vs 0x%04hx %s", idx * sizeof(kptr_t), meta->name, pac, pent->pac, parent->name);
                        }
                    }

                    if(!method && pent)
                    {
                        method = pent->method;
                        if(!pent->structor)
                        {
                            class = overrides ? meta->name : pent->class;
                            authoritative = pent->authoritative;
                            if(!authoritative)
                            {
                                chain = pent->chain;
                                pent->chain = ent;
                            }
                        }
                        else
                        {
                            const char *cls = pent->class,
                                       *mth = method;
                            bool dest = mth[0] == '~';
                            if(dest)
                            {
                                ++mth;
                            }
                            size_t clslen = strlen(cls);
                            if(strncmp(mth, cls, clslen) != 0)
                            {
                                WRN("Bad %sstructor: %s::%s", dest ? "de" : "con", cls, method);
                                method = NULL;
                            }
                            else
                            {
                                mth += clslen;
                                char *meth = NULL;
                                asprintf(&meth, "%s%s%s", dest ? "~" : "", meta->name, mth);
                                if(!meth)
                                {
                                    ERRNO("asprintf(structor)");
                                    return -1;
                                }
                                method = meth;
                                class = meta->name;
                                structor = true;
                                authoritative = false;
                            }
                        }
                    }
                    if(!method)
                    {
                        char *meth = NULL;
                        asprintf(&meth, "fn_0x%lx()", idx * sizeof(kptr_t));
                        if(!meth)
                        {
                            ERRNO("asprintf(method)");
                            return -1;
                        }
                        method = meth;
                    }
                    if(!class)
                    {
                        class = meta->name;
                    }
                    ent->chain = chain;
                    ent->class = class;
                    ent->method = method;
                    ent->addr = func;
                    ent->pac = pac;
                    ent->structor = !!structor;
                    ent->authoritative = !!authoritative;
                    ent->placeholder = !!placeholder;
                    ent->overrides = !!overrides;
                    ent->reserved = 0;

                    if(authoritative && !structor && pent && !pent->authoritative)
                    {
                        metaclass_t *cls = meta;
                        for(metaclass_t *c = cls->parentP; c && (idx < c->nmethods || !c->vtab); c = c->parentP)
                        {
                            if(c->vtab)
                            {
                                cls = c;
                            }
                        }
                        if(cls)
                        {
                            vtab_entry_t *start = &cls->methods[idx];
                            if(start->authoritative)
                            {
                                WRN("Authoritativity mismatch: %s::%s says no, but %s::%s says yes?!", parent->name, pent->method, cls->name, start->method);
                            }
                            else
                            {
                                for(vtab_entry_t *next = start; next != NULL; )
                                {
                                    next->method = method;
                                    next->authoritative = true;
                                    vtab_entry_t *tmp = next;
                                    next = next->chain;
                                    tmp->chain = NULL;
                                }
                            }
                        }
                    }
                }
                meta->methods_done = 1;
                done:;
                if(do_again)
                {
                    goto again;
                }
            }
        }
    }

    const char **filter = NULL;
    const char *__kernel__ = "__kernel__"; // Single ref for pointer comparisons

    if(opt.bundle || opt.bfilt)
    {
        bool haveBundles = false;
        const char **bundleList = NULL;
        size_t bundleIdx = 0;
        if(hdr->filetype == MH_KEXT_BUNDLE)
        {
            kmod_info_t *kmod = NULL;
            kptr_t kmod_addr = find_sym_by_name("_kmod_info", bsyms, nsyms);
            if(kmod_addr)
            {
                DBG("kmod: " ADDR, kmod_addr);
                kmod = addr2ptr(kernel, kmod_addr);
            }
            if(!kmod)
            {
                ERR("Failed to find kmod_info.");
                return -1;
            }
            __kernel__ = kmod->name;
        }
        else
        {
            DBG("Looking for kmod info...");
            mach_sec_t *kmod_info  = NULL,
                       *kmod_start = NULL;
            FOREACH_CMD(hdr, cmd)
            {
                if(cmd->cmd == MACH_SEGMENT)
                {
                    mach_seg_t *seg = (mach_seg_t*)cmd;
                    if(strcmp("__PRELINK_INFO", seg->segname) == 0)
                    {
                        if(seg->filesize > 0)
                        {
                            mach_sec_t *secs = (mach_sec_t*)(seg + 1);
                            for(size_t h = 0; h < seg->nsects; ++h)
                            {
                                if(strcmp("__kmod_info", secs[h].sectname) == 0)
                                {
                                    kmod_info = &secs[h];
                                }
                                else if(strcmp("__kmod_start", secs[h].sectname) == 0)
                                {
                                    kmod_start = &secs[h];
                                }
                            }
                        }
                        break;
                    }
                }
            }
            DBG("kmod_info:  %s", kmod_info  ? "yes" : "no");
            DBG("kmod_start: %s", kmod_start ? "yes" : "no");
            if(kmod_info && kmod_start)
            {
                if(kmod_info->size % sizeof(kptr_t) != 0 || kmod_start->size % sizeof(kptr_t) != 0)
                {
                    ERR("One of kmod_{info|start} has bad size.");
                    return -1;
                }
                size_t kmod_num = kmod_info->size / sizeof(kptr_t);
                kptr_t *info_ptr  = (kptr_t*)((uintptr_t)kernel + kmod_info->offset),
                       *start_ptr = (kptr_t*)((uintptr_t)kernel + kmod_start->offset);
                if(kmod_info->size != kmod_start->size)
                {
                    if(kmod_start->size == kmod_info->size + sizeof(kptr_t))
                    {
                        mach_hdr_t *exhdr = addr2ptr(kernel, kuntag(kbase, chainedFixup, start_ptr[kmod_num], NULL));
                        if(exhdr && exhdr->ncmds == 2)
                        {
                            mach_seg_t *exseg = (mach_seg_t*)(exhdr + 1);
                            mach_sec_t *exsec = (mach_sec_t*)(exseg + 1);
                            struct uuid_command *exuuid = (struct uuid_command*)((uintptr_t)exseg + exseg->cmdsize);
                            if
                            (
                                exseg->cmd == MACH_SEGMENT && exuuid->cmd == LC_UUID &&
                                strcmp("__TEXT_EXEC", exseg->segname) == 0 && exseg->nsects == 1 && strcmp("__text", exsec->sectname) == 0 && // XXX kuntag(kbase, chainedFixup, exsec->addr, NULL) == initcode &&
                                exuuid->uuid[0x0] == 0 && exuuid->uuid[0x1] == 0 && exuuid->uuid[0x2] == 0 && exuuid->uuid[0x3] == 0 &&
                                exuuid->uuid[0x4] == 0 && exuuid->uuid[0x5] == 0 && exuuid->uuid[0x6] == 0 && exuuid->uuid[0x7] == 0 &&
                                exuuid->uuid[0x8] == 0 && exuuid->uuid[0x9] == 0 && exuuid->uuid[0xa] == 0 && exuuid->uuid[0xb] == 0 &&
                                exuuid->uuid[0xc] == 0 && exuuid->uuid[0xd] == 0 && exuuid->uuid[0xe] == 0 && exuuid->uuid[0xf] == 0
                            )
                            {
                                DBG("Found kmod_start for initcode, ignoring...");
                                goto false_alarm;
                            }
                            ERR("moop");
                        }
                    }
                    ERR("Size mismatch on kmod_{info|start}.");
                    return -1;

                    false_alarm:;
                }
                if(filt_bundle && !bundleList)
                {
                    bundleList = malloc((kmod_num + 1) * sizeof(*bundleList));
                    if(!bundleList)
                    {
                        ERRNO("malloc(bundleList)");
                        return -1;
                    }
                }
                for(size_t i = 0; i < kmod_num; ++i)
                {
                    kptr_t iaddr = kuntag(kbase, chainedFixup, info_ptr[i],  NULL);
                    kptr_t haddr = kuntag(kbase, chainedFixup, start_ptr[i], NULL);
                    kmod_info_t *kmod = addr2ptr(kernel, iaddr);
                    mach_hdr_t  *khdr = addr2ptr(kernel, haddr);
                    if(!kmod)
                    {
                        WRN("Failed to translate kext kmod address " ADDR, iaddr);
                        continue;
                    }
                    DBG("Kext %s at " ADDR, kmod->name, haddr);
                    if(bundleList)
                    {
                        bundleList[bundleIdx++] = kmod->name;
                    }
                    if(!khdr)
                    {
                        WRN("Failed to translate kext header address " ADDR, haddr);
                        continue;
                    }
                    FOREACH_CMD(khdr, kcmd)
                    {
                        if(kcmd->cmd == MACH_SEGMENT)
                        {
                            mach_seg_t *kseg = (mach_seg_t*)kcmd;
                            if(strcmp("__TEXT_EXEC", kseg->segname) == 0)
                            {
                                kptr_t vmaddr = kuntag(kbase, chainedFixup, kseg->vmaddr, NULL);
                                DBG("%s __TEXT_EXEC at " ADDR, kmod->name, vmaddr);
                                for(size_t j = 0; j < metas.idx; ++j)
                                {
                                    metaclass_t *meta = &metas.val[j];
                                    if(meta->callsite >= vmaddr && meta->callsite < vmaddr + kseg->vmsize)
                                    {
                                        meta->bundle = kmod->name;
                                    }
                                }
                            }
                        }
                    }
                }
                for(size_t i = 0; i < metas.idx; ++i) // Kinda lousy, but what better way is there
                {
                    metaclass_t *meta = &metas.val[i];
                    if(!meta->bundle)
                    {
                        meta->bundle = __kernel__;
                    }
                }
                haveBundles = true;
            }
            else if(kmod_info || kmod_start)
            {
                ERR("Have one of kmod_{info|start}, but not the other.");
                return -1;
            }
        }
        if(!haveBundles)
        {
            FOREACH_CMD(hdr, cmd)
            {
                if(cmd->cmd == MACH_SEGMENT)
                {
                    mach_seg_t *seg = (mach_seg_t*)cmd;
                    if(strcmp("__DATA", seg->segname) == 0)
                    {
                        for(size_t i = 0; i < metas.idx; ++i)
                        {
                            metaclass_t *meta = &metas.val[i];
                            if(meta->addr >= seg->vmaddr && meta->addr < seg->vmaddr + seg->vmsize)
                            {
                                meta->bundle = __kernel__;
                            }
                        }
                        break;
                    }
                }
            }
            if(hdr->filetype != MH_KEXT_BUNDLE)
            {
                if(!prelink_info) prelink_info = get_prelink_info(hdr);
                if(!prelink_info) return -1;

                CFArrayRef arr = CFDictionaryGetValue(prelink_info, CFSTR("_PrelinkInfoDictionary"));
                if(!arr || CFGetTypeID(arr) != CFArrayGetTypeID())
                {
                    ERR("PrelinkInfoDictionary missing or wrong type");
                    return -1;
                }
                CFIndex arrlen = CFArrayGetCount(arr);
                if(filt_bundle && !bundleList)
                {
                    bundleList = malloc((arrlen + 1) * sizeof(*bundleList));
                    if(!bundleList)
                    {
                        ERRNO("malloc(bundleList)");
                        return -1;
                    }
                }
                for(size_t i = 0; i < arrlen; ++i)
                {
                    CFDictionaryRef dict = CFArrayGetValueAtIndex(arr, i);
                    if(!dict || CFGetTypeID(dict) != CFDictionaryGetTypeID())
                    {
                        WRN("Array entry %lu is not a dict.", i);
                        continue;
                    }
                    CFStringRef cfstr = CFDictionaryGetValue(dict, CFSTR("CFBundleIdentifier"));
                    if(!cfstr || CFGetTypeID(cfstr) != CFStringGetTypeID())
                    {
                        WRN("CFBundleIdentifier missing or wrong type at entry %lu.", i);
                        if(debug)
                        {
                            CFShow(dict);
                        }
                        continue;
                    }
                    const char *str = CFStringGetCStringPtr(cfstr, kCFStringEncodingUTF8);
                    if(!str)
                    {
                        WRN("Failed to get CFString contents at entry %lu.", i);
                        if(debug)
                        {
                            CFShow(cfstr);
                        }
                        continue;
                    }
                    if(bundleList)
                    {
                        bundleList[bundleIdx++] = str;
                    }
                    CFNumberRef cfnum = CFDictionaryGetValue(dict, CFSTR("_PrelinkExecutableLoadAddr"));
                    if(!cfnum)
                    {
                        DBG("Kext %s has no PrelinkExecutableLoadAddr, skipping...", str);
                        continue;
                    }
                    if(CFGetTypeID(cfnum) != CFNumberGetTypeID())
                    {
                        WRN("PrelinkExecutableLoadAddr missing or wrong type for kext %s", str);
                        if(debug)
                        {
                            CFShow(cfnum);
                        }
                        continue;
                    }
                    kptr_t kext_base = 0;
                    if(!CFNumberGetValue(cfnum, kCFNumberLongLongType, &kext_base))
                    {
                        WRN("Failed to get CFNumber contents for kext %s", str);
                        continue;
                    }
                    DBG("Kext %s at " ADDR, str, kext_base);
                    mach_hdr_t *hdr2 = addr2ptr(kernel, kext_base);
                    if(!hdr2)
                    {
                        WRN("Failed to translate kext header address " ADDR, kext_base);
                        continue;
                    }
                    FOREACH_CMD(hdr2, cmd2)
                    {
                        if(cmd2->cmd == MACH_SEGMENT)
                        {
                            mach_seg_t *seg2 = (mach_seg_t*)cmd2;
                            if(strcmp("__DATA", seg2->segname) == 0)
                            {
                                DBG("%s __DATA at " ADDR, str, seg2->vmaddr);
                                for(size_t j = 0; j < metas.idx; ++j)
                                {
                                    metaclass_t *meta = &metas.val[j];
                                    if(meta->addr >= seg2->vmaddr && meta->addr < seg2->vmaddr + seg2->vmsize)
                                    {
                                        meta->bundle = str;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if(filt_bundle)
        {
            if(!bundleList)
            {
                // NULL return value by malloc would've been caught earlier
                ERR("Failed to find kext info.");
                return -1;
            }
            bundleList[bundleIdx++] = __kernel__;
            // Exact match
            for(size_t i = 0; i < bundleIdx; ++i)
            {
                if(strcmp(bundleList[i], filt_bundle) == 0)
                {
                    filter = malloc(sizeof(*filter) * 2);
                    if(!filter)
                    {
                        ERRNO("malloc(filter)");
                        return -1;
                    }
                    // Since these are strings, we can unique them even if there was more than one exact match
                    filter[0] = filt_bundle;
                    filter[1] = NULL;
                    break;
                }
            }
            // Partial match
            if(!filter)
            {
                size_t num = 0;
                for(size_t i = 0; i < bundleIdx; ++i)
                {
                    if(strstr(bundleList[i], filt_bundle))
                    {
                        ++num;
                    }
                }
                if(num)
                {
                    filter = malloc((num + 1) * sizeof(*filter));
                    if(!filter)
                    {
                        ERRNO("malloc(filter)");
                        return -1;
                    }
                    filter[num] = NULL;
                    num = 0;
                    for(size_t i = 0; i < bundleIdx; ++i)
                    {
                        if(strstr(bundleList[i], filt_bundle))
                        {
                            filter[num++] = bundleList[i];
                        }
                    }
                }
            }
            if(!filter)
            {
                ERR("No bundle matching %s.", filt_bundle);
                return -1;
            }
            free(bundleList);
        }
    }

    metaclass_t **target = NULL;
    if(filt_class)
    {
        // Exact match
        {
            size_t num = 0;
            for(size_t i = 0; i < metas.idx; ++i)
            {
                if(strcmp(metas.val[i].name, filt_class) == 0)
                {
                    ++num;
                }
            }
            if(num)
            {
                target = malloc((num + 1) * sizeof(*target));
                if(!target)
                {
                    ERRNO("malloc(target)");
                    return -1;
                }
                target[num] = NULL;
                num = 0;
                for(size_t i = 0; i < metas.idx; ++i)
                {
                    if(strcmp(metas.val[i].name, filt_class) == 0)
                    {
                        target[num++] = &metas.val[i];
                    }
                }
            }
        }
        // Partial match
        if(!target)
        {
            size_t num = 0;
            for(size_t i = 0; i < metas.idx; ++i)
            {
                if(strstr(metas.val[i].name, filt_class))
                {
                    ++num;
                }
            }
            if(num)
            {
                target = malloc((num + 1) * sizeof(*target));
                if(!target)
                {
                    ERRNO("malloc(target)");
                    return -1;
                }
                target[num] = NULL;
                num = 0;
                for(size_t i = 0; i < metas.idx; ++i)
                {
                    if(strstr(metas.val[i].name, filt_class))
                    {
                        target[num++] = &metas.val[i];
                    }
                }
            }
        }
        if(!target)
        {
            ERR("No class matching %s.", filt_class);
            return -1;
        }
    }
    if(opt.symmap)
    {
        metaclass_t **list = malloc(metas.idx * sizeof(metaclass_t*));
        if(!list)
        {
            ERRNO("malloc(list)");
            return -1;
        }
        size_t lsize = 0;
        for(size_t i = 0; i < metas.idx; ++i)
        {
            list[lsize++] = &metas.val[i];
        }
        qsort(list, lsize, sizeof(*list), &compare_names);

        // Mark duplicates and warn if methods don't match
        for(size_t i = 1; i < lsize; ++i)
        {
            metaclass_t *prev = list[i-1],
                        *cur  = list[i];
            if(strcmp(prev->name, cur->name) == 0)
            {
                DBG("Duplicate class: %s", cur->name);
                cur->duplicate = 1;
                if(prev->nmethods != cur->nmethods)
                {
                    WRN("Duplicate classes %s have different number of methods (%lu vs %lu)", cur->name, prev->nmethods, cur->nmethods);
                }
                else
                {
                    for(size_t j = 0; j < cur->nmethods; ++j)
                    {
                        vtab_entry_t *one = &prev->methods[j],
                                     *two = &cur ->methods[j];
                        if(strcmp(one->class, two->class) != 0 || strcmp(one->method, two->method) != 0)
                        {
                            WRN("Mismatching method names of duplicate class %s: %s::%s vs %s::%s", cur->name, one->class, one->method, two->class, two->method);
                        }
                    }
                }
            }
        }

        if(opt.maxmap)
        {
            // Merge two sorted lists, ugh
            for(size_t i = 0, j = 0; i < symmap.num || j < lsize; )
            {
                if(j >= lsize || (i < symmap.num && strcmp(symmap.map[i].name, list[j]->name) <= 0))
                {
                    symmap_class_t *class = &symmap.map[i++];
                    metaclass_t *meta = class->metaclass;
                    if(class->duplicate)
                    {
                        if(meta)
                        {
                            WRN("Implementation fault: duplicate symclass has metaclass!");
                        }
                        continue;
                    }
                    if(meta)
                    {
                        //if(!meta->duplicate)
                        {
                            print_symmap(meta);
                        }
                    }
                    else
                    {
                        printf("%s\n", class->name);
                        for(size_t k = 0; k < class->num; ++k)
                        {
                            symmap_method_t *ent = &class->methods[k];
                            print_syment(class->name, ent->class, ent->method);
                        }
                    }
                }
                else
                {
                    metaclass_t *meta = list[j++];
                    if(!meta->duplicate && !meta->symclass) // Only print what we haven't printed above already
                    {
                        print_symmap(meta);
                    }
                }
            }
        }
        else
        {
            // Only print existing classes
            for(size_t i = 0; i < lsize; ++i)
            {
                metaclass_t *meta = list[i];
                if(!meta->duplicate)
                {
                    print_symmap(meta);
                }
            }
        }
    }
    else
    {
        metaclass_t **list = malloc(metas.idx * sizeof(metaclass_t*));
        if(!list)
        {
            ERRNO("malloc(list)");
            return -1;
        }
        size_t lsize = 0;
        if(opt.parent)
        {
            for(metaclass_t **ptr = target; *ptr; ++ptr)
            {
                for(metaclass_t *meta = *ptr; meta; )
                {
                    if(meta->visited)
                    {
                        break;
                    }
                    meta->visited = 1;
                    list[lsize++] = meta;
                    meta = meta->parentP;
                }
            }
        }
        else if(target)
        {
            for(metaclass_t **ptr = target; *ptr; ++ptr)
            {
                (*ptr)->visited = 1;
                list[lsize++] = *ptr;
            }
            if(opt.extend)
            {
                for(size_t j = 0; j < lsize; ++j)
                {
                    kptr_t addr = list[j]->addr;
                    for(size_t i = 0; i < metas.idx; ++i)
                    {
                        metaclass_t *meta = &metas.val[i];
                        if(!meta->visited && meta->parent == addr)
                        {
                            list[lsize++] = meta;
                            meta->visited = 1;
                        }
                    }
                }
            }
        }
        else
        {
            for(size_t i = 0; i < metas.idx; ++i)
            {
                list[lsize++] = &metas.val[i];
            }
        }
        if(filter)
        {
            size_t nsize = 0;
            for(size_t i = 0; i < lsize; ++i)
            {
                const char *bundle = list[i]->bundle;
                for(const char **ptr = filter; *ptr; ++ptr)
                {
                    if(strcmp(bundle, *ptr) == 0)
                    {
                        list[nsize++] = list[i];
                    }
                }
            }
            lsize = nsize;
        }
        if(filt_override)
        {
            size_t slen = strlen(filt_override),
                   nsize = 0;
            for(size_t i = 0; i < lsize; ++i)
            {
                metaclass_t *m = list[i];
                for(size_t i = 0; i < m->nmethods; ++i)
                {
                    vtab_entry_t *ent = &m->methods[i];
                    if(ent->overrides && strncmp(ent->method, filt_override, slen) == 0 && ent->method[slen] == '(') // TODO: does this need to be fixed?
                    {
                        list[nsize++] = m;
                        break;
                    }
                }
            }
            lsize = nsize;
        }
        if(opt.bsort || opt.csort)
        {
            qsort(list, lsize, sizeof(*list), opt.bsort ? &compare_bundles : &compare_names);
        }
        size_t namelen = 0;
        if(opt.bundle && !opt.overrides) // Spaced out looks weird
        {
            for(size_t i = 0; i < lsize; ++i)
            {
                size_t nl = strlen(list[i]->name);
                if(nl > namelen)
                {
                    namelen = nl;
                }
            }
        }
        if(opt.radare)
        {
            printf("fs symbols\n");
            if(pure_virtual)
            {
                printf("f sym.___cxa_pure_virtual 0 " ADDR "\n", pure_virtual);
                printf("fN sym.___cxa_pure_virtual ___cxa_pure_virtual\n");
            }
        }
        for(size_t i = 0; i < lsize; ++i)
        {
            print_metaclass(list[i], (int)namelen, opt);
        }
    }

    return 0;
}
