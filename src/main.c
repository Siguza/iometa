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

#include <stdbool.h>
#include <stdint.h>             // uintptr_t
#include <stdio.h>              // fprintf, stderr
#include <stdlib.h>             // malloc, realloc, qsort, bsearch, exit
#include <string.h>             // strcmp, strstr, memcpy, memmem
#include <strings.h>            // bzero
#include <sys/mman.h>           // PROT_READ, PROT_WRITE
#include <CoreFoundation/CoreFoundation.h>

extern CFTypeRef IOCFUnserialize(const char *buffer, CFAllocatorRef allocator, CFOptionFlags options, CFStringRef *errorString);

#include "a64.h"
#include "a64emu.h"
#include "cxx.h"
#include "macho.h"
#include "meta.h"
#include "symmap.h"
#include "util.h"

#define NUM_KEXTS_EXPECT 0x200

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

static kptr_t find_stub_for_reloc(void *kernel, mach_hdr_t *hdr, fixup_kind_t fixupKind, bool have_plk_text_exec, sym_t *exreloc, size_t nexreloc, const char *sym)
{
    kptr_t relocAddr = find_sym_by_name(sym, exreloc, nexreloc);
    if(relocAddr)
    {
        DBG("Found reloc for %s at " ADDR, sym, relocAddr);
        FOREACH_CMD(hdr, cmd)
        {
            if(cmd->cmd == MACH_SEGMENT)
            {
                mach_seg_t *seg = (mach_seg_t*)cmd;
                if(seg->filesize > 0 && SEG_IS_EXEC(seg, fixupKind, have_plk_text_exec))
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

static bool is_part_of_vtab(void *kernel, kptr_t kbase, fixup_kind_t fixupKind, relocrange_t *locreloc, size_t nlocreloc, sym_t *exreloc, size_t nexreloc, kptr_t *vtab, kptr_t vtabaddr, size_t idx)
{
    if(idx == 0)
    {
        return true;
    }
    if(fixupKind != DYLD_CHAINED_PTR_NONE)
    {
        size_t skip = 0;
        kuntag(kbase, fixupKind, vtab[idx - 1], NULL, &skip);
        if(skip == sizeof(kptr_t))
        {
            return true;
        }
        if(skip != 0)
        {
            return false;
        }
        // If skip is == 0, it's possible that a new fixup chain starts right here
        return is_in_fixup_chain(kernel, kbase, &vtab[idx]);
    }
    else
    {
        kptr_t val = vtabaddr + sizeof(kptr_t) * idx;
        const char *sym = find_sym_by_addr(val, exreloc, nexreloc);
        if(sym)
        {
            return true;
        }
        return bsearch(&val, locreloc, nlocreloc, sizeof(*locreloc), &compare_range) != NULL;
    }
}

static void find_str(void *kernel, size_t kernelsize, void *arg, const char *str)
{
    ARRCAST(kptr_t, arr, arg);
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

static void find_imports(void *kernel, size_t kernelsize, mach_hdr_t *hdr, kptr_t kbase, fixup_kind_t fixupKind, bool have_plk_text_exec, void *arr, kptr_t func)
{
    if(hdr->filetype != MH_KEXT_BUNDLE)
    {
        ARRDEF(kptr_t, refs, NUM_KEXTS_EXPECT);
        ARRCAST(kptr_t, aliases, arr);
        // Ideally I'd want a "foreach ptr" kind of thing here, as well as a cache for the fixup structures,
        // but this is one of only two places where that's really needed, so... not worth it yet?
        if(fixupKind == DYLD_CHAINED_PTR_ARM64E)
        {
            FOREACH_CMD(hdr, cmd)
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
                                uint32_t *start = (uint32_t*)((uintptr_t)kernel + secs[i].offset),
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
                                        kptr_t *mem = addr2ptr(kernel, kbase + *start);
                                        size_t skip = 0;
                                        do
                                        {
                                            if(kuntag(kbase, fixupKind, *mem, NULL, &skip) == func)
                                            {
                                                kptr_t ref = off2addr(kernel, (uintptr_t)mem - (uintptr_t)kernel);
                                                DBG("ref: " ADDR, ref);
                                                ARRPUSH(refs, ref);
                                            }
                                            mem = (kptr_t*)((uintptr_t)mem + skip);
                                        } while(skip > 0);
                                    }
                                }
                                break;
                            }
                        }
                        break;
                    }
                }
            }
        }
        else if(fixupKind == DYLD_CHAINED_PTR_64_KERNEL_CACHE)
        {
            FOREACH_CMD(hdr, cmd)
            {
                if(cmd->cmd == LC_DYLD_CHAINED_FIXUPS)
                {
                    struct linkedit_data_command *data = (struct linkedit_data_command*)cmd;
                    fixup_hdr_t *fixup = (fixup_hdr_t*)((uintptr_t)kernel + data->dataoff);
                    fixup_seg_t *segs = (fixup_seg_t*)((uintptr_t)fixup + fixup->starts_offset);
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
                            kptr_t *mem = (kptr_t*)((uintptr_t)kernel + (size_t)starts->segment_offset + (size_t)j * (size_t)starts->page_size + (size_t)idx);
                            size_t skip = 0;
                            do
                            {
                                if(kuntag(kbase, fixupKind, *mem, NULL, &skip) == func)
                                {
                                    kptr_t ref = off2addr(kernel, (uintptr_t)mem - (uintptr_t)kernel);
                                    DBG("ref: " ADDR, ref);
                                    ARRPUSH(refs, ref);
                                }
                                mem = (kptr_t*)((uintptr_t)mem + skip);
                            } while(skip > 0);
                        }
                    }
                    break;
                }
            }
        }
        else
        {
            STEP_MEM(kptr_t, mem, kernel, kernelsize, 1)
            {
                if(kuntag(kbase, fixupKind, *mem, NULL, NULL) == func)
                {
                    kptr_t ref = off2addr(kernel, (uintptr_t)mem - (uintptr_t)kernel);
                    DBG("ref: " ADDR, ref);
                    ARRPUSH(refs, ref);
                }
            }
        }
        FOREACH_CMD(hdr, cmd)
        {
            if(cmd->cmd == MACH_SEGMENT)
            {
                mach_seg_t *seg = (mach_seg_t*)cmd;
                if(seg->filesize > 0 && SEG_IS_EXEC(seg, fixupKind, have_plk_text_exec))
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
        ARRFREE(refs);
    }
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

    ARRDEF(kptr_t, aliases, NUM_KEXTS_EXPECT);
    ARRDEF(kptr_t, altaliases, NUM_KEXTS_EXPECT);

    kptr_t OSMetaClassConstructor = 0,
           OSMetaClassAltConstructor = 0,
           OSMetaClassVtab = 0,
           OSObjectVtab = 0,
           OSObjectGetMetaClass = 0,
           kbase = 0,
           plk_base = 0,
           pure_virtual = 0;
    fixup_kind_t fixupKind = DYLD_CHAINED_PTR_NONE;
    bool have_plk_text_exec = false;
    mach_nlist_t *symtab = NULL;
    char *strtab         = NULL;
    mach_dstab_t *dstab  = NULL;
    size_t nsyms         = 0,
           nexreloc      = 0,
           nsetentries   = 0;
    sym_t *asyms         = NULL,
          *bsyms         = NULL,
          *exrelocA      = NULL,
          *exrelocB      = NULL;
    FOREACH_CMD(hdr, cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            if(seg->fileoff == 0 && seg->filesize > 0)
            {
                kbase = seg->vmaddr;
            }
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
                        if(secs[i].size > 0)
                        {
                            fixupKind = DYLD_CHAINED_PTR_ARM64E;
                        }
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
            if(!macho_extract_symbols(kernel, stab, &asyms, &nsyms))
            {
                return -1;
            }
        }
        else if(cmd->cmd == LC_DYSYMTAB)
        {
            dstab = (mach_dstab_t*)cmd;
            // Imports for kexts
            if(hdr->filetype == MH_KEXT_BUNDLE)
            {
                if(!macho_extract_reloc(kernel, kbase, dstab, symtab, strtab, &exrelocA, &nexreloc))
                {
                    return -1;
                }
            }
        }
        else if(cmd->cmd == LC_DYLD_CHAINED_FIXUPS)
        {
            fixupKind = DYLD_CHAINED_PTR_64_KERNEL_CACHE;
        }
        else if(cmd->cmd == LC_FILESET_ENTRY)
        {
            ++nsetentries;
            mach_fileent_t *ent = (mach_fileent_t*)cmd;
            mach_hdr_t *mh = (void*)((uintptr_t)kernel + ent->fileoff);
            const char *name = (const char*)((uintptr_t)ent + ent->nameoff);
            DBG("Processing embedded header of %s", name);
            // Redefine these in scope only for this entry
            mach_nlist_t *symtab = NULL;
            char *strtab         = NULL;
            FOREACH_CMD(mh, lc)
            {
                if(lc->cmd == LC_SYMTAB)
                {
                    mach_stab_t *stab = (mach_stab_t*)lc;
                    symtab = (mach_nlist_t*)((uintptr_t)kernel + stab->symoff);
                    strtab = (char*)((uintptr_t)kernel + stab->stroff);
                    if(!macho_extract_symbols(kernel, stab, &asyms, &nsyms))
                    {
                        return -1;
                    }
                }
                else if(lc->cmd == LC_DYSYMTAB)
                {
                    if(!macho_extract_reloc(kernel, kbase, (mach_dstab_t*)lc, symtab, strtab, &exrelocA, &nexreloc))
                    {
                        return -1;
                    }
                }
            }
        }
    }

    DBG("Got %lu symbols", nsyms);
    if(nsyms > 0)
    {
        bsyms = malloc(sizeof(sym_t) * nsyms);
        if(!bsyms)
        {
            ERRNO("malloc(syms)");
            return -1;
        }
        memcpy(bsyms, asyms, nsyms * sizeof(sym_t));
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

    DBG("Got %lu exreloc entries", nexreloc);
    if(nexreloc > 0)
    {
        exrelocB = malloc(sizeof(sym_t) * nexreloc);
        if(!exrelocB)
        {
            ERRNO("malloc(exreloc)");
            return -1;
        }
        memcpy(exrelocB, exrelocA, nexreloc * sizeof(sym_t));
        qsort(exrelocA, nexreloc, sizeof(*exrelocA), &compare_sym_addrs);
        qsort(exrelocB, nexreloc, sizeof(*exrelocB), &compare_sym_names);
    }

    if(!OSMetaClassConstructor)
    {
        if(hdr->filetype == MH_KEXT_BUNDLE)
        {
            DBG("Failed to find OSMetaClassConstructor symbol, trying relocation instead.");
            OSMetaClassConstructor = find_stub_for_reloc(kernel, hdr, fixupKind, have_plk_text_exec, exrelocB, nexreloc, "__ZN11OSMetaClassC2EPKcPKS_j");
        }
        else
        {
            DBG("Failed to find OSMetaClassConstructor symbol, falling back to binary matching.");
#define NSTRREF 3
            const char *strs[NSTRREF] = { "IORegistryEntry", "IOService", "IOUserClient" };
            ARRDECL(kptr_t, strrefs)[NSTRREF];
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
            ARRDECL(kptr_t, constrCand)[2];
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
                        if(seg->filesize > 0 && SEG_IS_EXEC(seg, fixupKind, have_plk_text_exec))
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
                                            if(a64_emulate(kernel, kbase, fixupKind, &state, mem, &a64cb_check_equal, m, true, true, kEmuFnIgnore) != kEmuEnd)
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
                ARRFREE(constrCand[0]);
                ARRFREE(constrCand[1]);
                for(size_t i = 0; i < NSTRREF; ++i)
                {
                    ARRFREE(strrefs[i]);
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

    find_imports(kernel, kernelsize, hdr, kbase, fixupKind, have_plk_text_exec, &aliases, OSMetaClassConstructor);

    ARRDEF(metaclass_t, metas, NUM_METACLASSES_EXPECT);
    ARRDEF(metaclass_candidate_t, namelist, 2 * NUM_METACLASSES_EXPECT);

    find_meta_constructor_calls(kernel, hdr, kbase, fixupKind, have_plk_text_exec, want_vtabs, &aliases, &metas, &namelist, bsyms, nsyms, &meta_constructor_cb, OSMetaClassAltConstructor ? NULL : &OSMetaClassAltConstructor);
    if(OSMetaClassAltConstructor)
    {
        ARRPUSH(altaliases, OSMetaClassAltConstructor);
        find_imports(kernel, kernelsize, hdr, kbase, fixupKind, have_plk_text_exec, &altaliases, OSMetaClassAltConstructor);
        find_meta_constructor_calls(kernel, hdr, kbase, fixupKind, have_plk_text_exec, want_vtabs, &altaliases, &metas, &namelist, bsyms, nsyms, &meta_alt_constructor_cb, NULL);
    }

    // This is a safety check to make sure we're not missing anything.
    DBG("Got %lu names (probably a ton of dupes)", namelist.idx);
    qsort(namelist.val, namelist.idx, sizeof(*namelist.val), &compare_meta_candidates);
    for(size_t i = 0; i < namelist.idx; ++i)
    {
        metaclass_candidate_t *current = &namelist.val[i];
        if(i > 0)
        {
            // compare_meta_candidates() sorts entries without fncall last, and we set it to NULL if it got us nowhere,
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
            void *sp = malloc(A64_EMU_SPSIZE);
            if(!sp)
            {
                ERR("malloc(sp)");
                return -1;
            }
            a64_state_t state;
            bool success = multi_call_emulate(kernel, kbase, fixupKind, current->fncall, current->fncall, &state, sp, 0xf, current->name);
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
                    add_metaclass(kernel, kbase, fixupKind, &metas, &state, current->fncall, want_vtabs, bsyms, nsyms);
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
    ARRFREE(namelist);

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
        ARRDEFEMPTY(relocrange_t, locreloc);
        if(fixupKind == DYLD_CHAINED_PTR_NONE)
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

            // Squash and merge
            qsort(tmp, nlocrel, sizeof(*tmp), &compare_addrs);
            ARRINIT(locreloc, 0x2000);
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
                                    if(a64_emulate(kernel, kbase, fixupKind, &state, start, &a64cb_check_equal, mem, false, true, kEmuFnIgnore) == kEmuEnd)
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
                        if(seg->filesize > 0 && SEG_IS_EXEC(seg, fixupKind, have_plk_text_exec))
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
                if(kuntag(kbase, fixupKind, ovtab[i], NULL, NULL) == OSObjectGetMetaClass)
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

                ARRDEF(kptr_t, strref, 4);
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
                        if(seg->filesize > 0 && SEG_IS_EXEC(seg, fixupKind, have_plk_text_exec))
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
                    if(kuntag(kbase, fixupKind, ovtab[i], NULL, NULL) == pure_virtual)
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

        //ARRDEF(kptr_t, candidates, 0x100);
        FOREACH_CMD(hdr, cmd)
        {
            if(cmd->cmd == MACH_SEGMENT)
            {
                mach_seg_t *seg = (mach_seg_t*)cmd;
                if(seg->filesize > 0 && SEG_IS_EXEC(seg, fixupKind, have_plk_text_exec))
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
                                        //candidates.idx = 0;
                                        if(!meta->vtab)
                                        {
                                            if(fixupKind == DYLD_CHAINED_PTR_ARM64E)
                                            {
                                                FOREACH_CMD(hdr, lc)
                                                {
                                                    if(lc->cmd == MACH_SEGMENT)
                                                    {
                                                        mach_seg_t *seg = (mach_seg_t*)lc;
                                                        if(strcmp("__TEXT", seg->segname) == 0)
                                                        {
                                                            mach_sec_t *secs = (mach_sec_t*)(seg + 1);
                                                            for(size_t i = 0; i < seg->nsects; ++i)
                                                            {
                                                                if(strcmp("__thread_starts", secs[i].sectname) == 0)
                                                                {
                                                                    uint32_t *start = (uint32_t*)((uintptr_t)kernel + secs[i].offset),
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
                                                                            kptr_t *mem2 = addr2ptr(kernel, kbase + *start);
                                                                            size_t skip = 0;
                                                                            do
                                                                            {
                                                                                if(kuntag(kbase, fixupKind, *mem2, NULL, &skip) == func)
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
                                                                                            //ARRPUSH(candidates, meta->vtab);
                                                                                            meta->vtab = -1;
                                                                                        }
                                                                                        DBG("More than one vtab for %s: " ADDR, meta->name, ref);
                                                                                        //ARRPUSH(candidates, ref);
                                                                                    }
                                                                                }
                                                                                mem2 = (kptr_t*)((uintptr_t)mem2 + skip);
                                                                            } while(skip > 0);
                                                                        }
                                                                    }
                                                                    break;
                                                                }
                                                            }
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                            else if(fixupKind == DYLD_CHAINED_PTR_64_KERNEL_CACHE)
                                            {
                                                FOREACH_CMD(hdr, lc)
                                                {
                                                    if(lc->cmd == LC_DYLD_CHAINED_FIXUPS)
                                                    {
                                                        struct linkedit_data_command *data = (struct linkedit_data_command*)lc;
                                                        fixup_hdr_t *fixup = (fixup_hdr_t*)((uintptr_t)kernel + data->dataoff);
                                                        fixup_seg_t *segs = (fixup_seg_t*)((uintptr_t)fixup + fixup->starts_offset);
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
                                                                kptr_t *mem2 = (kptr_t*)((uintptr_t)kernel + (size_t)starts->segment_offset + (size_t)j * (size_t)starts->page_size + (size_t)idx);
                                                                size_t skip = 0;
                                                                do
                                                                {
                                                                    if(kuntag(kbase, fixupKind, *mem2, NULL, &skip) == func)
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
                                                                                //ARRPUSH(candidates, meta->vtab);
                                                                                meta->vtab = -1;
                                                                            }
                                                                            DBG("More than one vtab for %s: " ADDR, meta->name, ref);
                                                                            //ARRPUSH(candidates, ref);
                                                                        }
                                                                    }
                                                                    mem2 = (kptr_t*)((uintptr_t)mem2 + skip);
                                                                } while(skip > 0);
                                                            }
                                                        }
                                                        break;
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                FOREACH_CMD(hdr, lc)
                                                {
                                                    if(lc->cmd == MACH_SEGMENT)
                                                    {
                                                        mach_seg_t *seg2 = (mach_seg_t*)lc;
                                                        if
                                                        (
                                                            seg2->filesize > (VtabGetMetaClassIdx + 2) * sizeof(kptr_t) &&
                                                            (strcmp("__DATA", seg2->segname) == 0 || strcmp("__DATA_CONST", seg2->segname) == 0 || strcmp("__PRELINK_DATA", seg2->segname) == 0 || strcmp("__PLK_DATA_CONST", seg2->segname) == 0)
                                                        )
                                                        {
                                                            STEP_MEM(kptr_t, mem2, (kptr_t*)((uintptr_t)kernel + seg2->fileoff) + VtabGetMetaClassIdx + 2, seg2->filesize - (VtabGetMetaClassIdx + 2) * sizeof(kptr_t), 1)
                                                            {
                                                                if(kuntag(kbase, fixupKind, *mem2, NULL, NULL) == func && *(mem2 - VtabGetMetaClassIdx - 1) == 0 && *(mem2 - VtabGetMetaClassIdx - 2) == 0)
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
                                                                            //ARRPUSH(candidates, meta->vtab);
                                                                            meta->vtab = -1;
                                                                        }
                                                                        DBG("More than one vtab for %s: " ADDR, meta->name, ref);
                                                                        //ARRPUSH(candidates, ref);
                                                                    }
                                                                }
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
        //ARRFREE(candidates);

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
                kptr_t fnaddr = kuntag(kbase, fixupKind, ovtab[VtabAllocIdx], NULL, NULL);
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
                                void *sp = malloc(A64_EMU_SPSIZE),
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
                                state.x[31]  = (uintptr_t)sp + A64_EMU_SPSIZE;
                                state.valid  = 0xfff80001;
                                state.qvalid = 0x0000ff00;
                                state.wide   = 0xfff80001;
                                state.host   = 0x80000000;
                                switch(a64_emulate(kernel, kbase, fixupKind, &state, fnstart, &a64cb_check_bl, &m, false, true, kEmuFnIgnore))
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
                                            if(a64_emulate(kernel, kbase, fixupKind, &state, m, &a64cb_check_equal, m + 1, false, true, kEmuFnIgnore) != kEmuEnd)
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
                                            if(a64_emulate(kernel, kbase, fixupKind, &state, m + 1, &a64cb_check_equal, end, false, true, kEmuFnAssumeX0) != kEmuRet)
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
                while(is_part_of_vtab(kernel, kbase, fixupKind, locreloc.val, locreloc.idx, exrelocA, nexreloc, mvtab, meta->vtab, nmeth))
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
                    kptr_t func  = 0;
                    uint16_t pac = 0;
                    const char *cxx_sym = NULL,
                               *class   = NULL,
                               *method  = NULL;
                    bool structor      = false,
                         authoritative = false,
                         overrides     = false,
                         is_in_exreloc = false;

                    kptr_t koff = meta->vtab + sizeof(kptr_t) * idx;
                    cxx_sym = find_sym_by_addr(koff, exrelocA, nexreloc);
                    if(cxx_sym)
                    {
                        is_in_exreloc = true;
                    }
                    else
                    {
                        func = kuntag(kbase, fixupKind, mvtab[idx], &pac, NULL);
                        cxx_sym = find_sym_by_addr(func, asyms, nsyms);
                        overrides = !pent || func != pent->addr;
                    }
                    if((cxx_sym && strcmp(cxx_sym, "___cxa_pure_virtual") == 0) || (pure_virtual && func == pure_virtual))
                    {
                        func = -1;
                    }
                    else if(cxx_sym)
                    {
                        DBG("Got symbol for virtual function " ADDR ": %s", func, cxx_sym);
                        if(cxx_demangle(cxx_sym, &class, &method, &structor))
                        {
                            authoritative = true;
                        }
                        else if(is_in_exreloc)
                        {
                            WRN("Failed to demangle symbol: %s (from reloc)", cxx_sym);
                        }
                        else
                        {
                            WRN("Failed to demangle symbol: %s (from symtab, addr " ADDR ")", cxx_sym, func);
                        }
                    }
                    if(!ignore_symmap && idx >= pnmeth && meta->symclass)
                    {
                        symmap_method_t *smeth = &meta->symclass->methods[idx - pnmeth];
                        if(method && smeth->method && !smeth->structor && strcmp(method, smeth->method) != 0)
                        {
                            WRN("Overriding %s::%s from symtab with %s::%s from symmap", class, method, smeth->class, smeth->method);
                        }
                        class = smeth->class;
                        method = smeth->method;
                        structor = smeth->structor;
                        if(method)
                        {
                            authoritative = true;
                        }
                    }
                    // Ok, this is a nasty thing now. We wanna verify that the method's PAC diversifier
                    // matches that of the parent class, if existent. There is only one case where it
                    // will not match, and literally all of the complexits below is due to that:
                    // If class A has a pure virtual method and B inherits from A but does not override
                    // said method, the compiler will give B's vtable a diversifier as if B had declared
                    // the method, not A. This means that we have to traverse the class hierarchy until
                    // we either find a method entry that is not pure virtual, or we reach the first
                    // class with such a method entry. Then however, if that entry is still pure virtual
                    // and the class'es direct parent class has no vtable (i.e. the compiler optimised
                    // it out), we have to skip the check altogether because it is possible that the
                    // parent class declared the method, in which case the entry we found will have the
                    // wrong diversifier. And this really occurs in practice, for example in the
                    // N104AP kernel for 18A5373a (iPhone 11, iOS 14.0 beta 8).
                    if((hdr->cpusubtype & CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E && !is_in_exreloc && pent && func != -1)
                    {
                        metaclass_t  *bcls = parent;
                        vtab_entry_t *bent = pent;
                        // Skip while pure virtual
                        while(bent->addr == -1)
                        {
                            bcls = bcls->parentP;
                            // Skip while missing vtab
                            while(bcls && bcls->vtab == 0)
                            {
                                bcls = bcls->parentP;
                            }
                            if(!bcls || idx >= bcls->nmethods)
                            {
                                bent = NULL;
                                break;
                            }
                            bent = &bcls->methods[idx];
                        }
                        if(bent && pac != bent->pac)
                        {
                            WRN("PAC mismatch method 0x%lx: %s 0x%04hx vs 0x%04hx %s", idx * sizeof(kptr_t), meta->name, pac, bent->pac, bcls->name);
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

                    // If we're on arm64e and have a symbol that we believe should be correct, we can check if it matches the PAC diversifier.
                    // In order to avoid duplicate work, we wanna skip this if we already did for the parent, but determining if we did that is a bit of a pain.
                    if((hdr->cpusubtype & CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E && !is_in_exreloc && authoritative && (!pent || !pent->authoritative))
                    {
                        // First seek down to the first class that has this method
                        metaclass_t *checkClass = meta;
                        if(pent)
                        {
                            for(metaclass_t *curClass = parent; curClass; curClass = curClass->parentP)
                            {
                                if(curClass->vtab == 0)
                                {
                                    continue;
                                }
                                if(idx >= curClass->nmethods)
                                {
                                    break;
                                }
                                checkClass = curClass;
                            }
                        }
                        DBG("Checking diversifier of %s::%s (sym: %s)", checkClass->name, method, cxx_sym ? cxx_sym : "---");
                        do
                        {
                            char *sym = NULL;
                            if(structor)
                            {
                                // TODO: Everywhere else, I support both con- and destructors, and don't make any assumptions about indices.
                                // But both destructors look exactly the same de-mangled, so this is the only indicator I have, for now.
                                // At least this will spew a warning if things break, I guess.
                                asprintf(&sym, "__ZN%lu%sD%luEv", strlen(checkClass->name), checkClass->name, 1 - idx);
                                if(!sym)
                                {
                                    ERRNO("asprintf(sym)");
                                    return -1;
                                }
                            }
                            else
                            {
                                sym = cxx_mangle(checkClass->name, method);
                                if(!sym)
                                {
                                    WRN("Failed to mangle %s::%s", checkClass->name, method);
                                    break;
                                }
                            }
                            uint16_t div = 0;
                            if(!cxx_compute_pac(sym, &div))
                            {
                                ERR("Failed to compute PAC diversifier. This means something is broken.");
                                return -1;
                            }
                            DBG("Computed PAC 0x%04hx for symbol %s", div, sym);
                            if(!cxx_sym && !pent)
                            {
                                cxx_sym = sym;
                            }
                            else
                            {
                                free(sym);
                            }
                            // With abstract parents, we might have to use the parent class name.
                            // This can go on as long as the hierarchy has no vtable.
                            if(div != pac)
                            {
                                // We don't capture OSMetaClassBase, so treat parent == null as that
                                for(metaclass_t *p = checkClass->parentP; !p || p->vtab == 0 || p->methods[idx].addr == -1; p = p->parentP)
                                {
                                    const char *pname = p ? p->name : "OSMetaClassBase";
                                    if(structor)
                                    {
                                        // TODO: See above
                                        asprintf(&sym, "__ZN%lu%sD%luEv", strlen(pname), pname, 1 - idx);
                                        if(!sym)
                                        {
                                            ERRNO("asprintf(sym)");
                                            return -1;
                                        }
                                    }
                                    else
                                    {
                                        sym = cxx_mangle(pname, method);
                                        if(!sym)
                                        {
                                            ERR("Failed to mangle a method, but mangling with different class succeeded.");
                                            ERR("Failed method was: %s::%s", pname, method);
                                            return -1;
                                        }
                                    }
                                    if(!cxx_compute_pac(sym, &div))
                                    {
                                        ERR("Failed to compute PAC diversifier. This means something is broken.");
                                        return -1;
                                    }
                                    DBG("Computed PAC 0x%04hx for symbol %s", div, sym);
                                    free(sym);
                                    if(!p || div == pac)
                                    {
                                        break;
                                    }
                                }
                                if(div != pac)
                                {
                                    WRN("PAC verification failed for %s::%s", checkClass->name, method);
                                }
                            }
                        } while(0);
                    }

                    // TODO: record C++ symbol

                    ent->chain = chain;
                    ent->class = class;
                    ent->method = method;
                    ent->addr = func;
                    ent->pac = pac;
                    ent->structor = !!structor;
                    ent->authoritative = !!authoritative;
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
        else if(hdr->filetype == MH_FILESET)
        {
            if(filt_bundle && !bundleList)
            {
                bundleList = malloc(nsetentries * sizeof(*bundleList));
                if(!bundleList)
                {
                    ERRNO("malloc(bundleList)");
                    return -1;
                }
            }
            FOREACH_CMD(hdr, cmd)
            {
                if(cmd->cmd == LC_FILESET_ENTRY)
                {
                    mach_fileent_t *ent = (mach_fileent_t*)cmd;
                    mach_hdr_t *mh = (void*)((uintptr_t)kernel + ent->fileoff);
                    const char *name = (const char*)((uintptr_t)ent + ent->nameoff);
                    kptr_t iaddr = 0;
                    FOREACH_CMD(mh, lc)
                    {
                        if(lc->cmd == LC_SYMTAB)
                        {
                            mach_stab_t *stab = (mach_stab_t*)lc;
                            mach_nlist_t *symtab = (mach_nlist_t*)((uintptr_t)kernel + stab->symoff);
                            char *strtab = (char*)((uintptr_t)kernel + stab->stroff);
                            for(size_t i = 0; i < stab->nsyms; ++i)
                            {
                                if((symtab[i].n_type & N_TYPE) != N_SECT || ((symtab[i].n_type & N_STAB) && !(symtab[i].n_type & N_EXT)))
                                {
                                    continue;
                                }
                                if(strcmp("_kmod_info", &strtab[symtab[i].n_strx]) == 0)
                                {
                                    iaddr = symtab[i].n_value;
                                    break;
                                }
                            }
                            break;
                        }
                    }
                    if(!iaddr)
                    {
                        WRN("No kmod_info for %s", name);
                        continue;
                    }
                    kmod_info_t *kmod = addr2ptr(kernel, iaddr);
                    if(!kmod)
                    {
                        WRN("Failed to translate kext kmod address " ADDR, iaddr);
                        continue;
                    }
                    const char *str = kmod->name;
                    if(strcmp("com.apple.kernel", name) == 0 && strcmp("invalid", str) == 0)
                    {
                        str = __kernel__;
                    }
                    if(bundleList)
                    {
                        bundleList[bundleIdx++] = str;
                    }
                    FOREACH_CMD(mh, lc)
                    {
                        if(lc->cmd == MACH_SEGMENT)
                        {
                            mach_seg_t *kseg = (mach_seg_t*)lc;
                            if(strcmp("__TEXT_EXEC", kseg->segname) == 0)
                            {
                                kptr_t vmaddr = kseg->vmaddr;
                                DBG("%s __TEXT_EXEC at " ADDR, str, vmaddr);
                                for(size_t j = 0; j < metas.idx; ++j)
                                {
                                    metaclass_t *meta = &metas.val[j];
                                    if(meta->callsite >= vmaddr && meta->callsite < vmaddr + kseg->vmsize)
                                    {
                                        meta->bundle = str;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            for(size_t i = 0; i < metas.idx; ++i)
            {
                metaclass_t *meta = &metas.val[i];
                if(!meta->bundle)
                {
                    ERR("Metaclass without a bundle: %s (" ADDR ")", meta->name, meta->callsite);
                    return -1;
                }
            }
            haveBundles = true;
        }
        else if(hdr->filetype == MH_EXECUTE)
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
                        mach_hdr_t *exhdr = addr2ptr(kernel, kuntag(kbase, fixupKind, start_ptr[kmod_num], NULL, NULL));
                        if(exhdr && exhdr->ncmds == 2)
                        {
                            mach_seg_t *exseg = (mach_seg_t*)(exhdr + 1);
                            mach_sec_t *exsec = (mach_sec_t*)(exseg + 1);
                            struct uuid_command *exuuid = (struct uuid_command*)((uintptr_t)exseg + exseg->cmdsize);
                            if
                            (
                                exseg->cmd == MACH_SEGMENT && exuuid->cmd == LC_UUID &&
                                strcmp("__TEXT_EXEC", exseg->segname) == 0 && exseg->nsects == 1 && strcmp("__text", exsec->sectname) == 0 &&
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
                    kptr_t iaddr = kuntag(kbase, fixupKind, info_ptr[i],  NULL, NULL);
                    kptr_t haddr = kuntag(kbase, fixupKind, start_ptr[i], NULL, NULL);
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
                                kptr_t vmaddr = kuntag(kbase, fixupKind, kseg->vmaddr, NULL, NULL);
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
            if(hdr->filetype == MH_EXECUTE)
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
            if(hdr->filetype != MH_FILESET)
            {
                bundleList[bundleIdx++] = __kernel__;
            }
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
        qsort(list, lsize, sizeof(*list), &compare_meta_names);

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
            qsort(list, lsize, sizeof(*list), opt.bsort ? &compare_meta_bundles : &compare_meta_names);
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
