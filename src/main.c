/* Copyright (c) 2018-2022 Siguza
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
#include "print.h"
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

static bool get_import_target(adr_t *adrp, kptr_t alias, bool space_for_4, kptr_t *addr)
{
    ldr_imm_uoff_t *ldr1 = (ldr_imm_uoff_t*)(adrp + 1);
    br_t *br = (br_t*)(adrp + 2);
    add_imm_t *add = (add_imm_t*)(adrp + 1);
    ldr_imm_uoff_t *ldr2 = (ldr_imm_uoff_t*)(adrp + 2);
    bra_t *bra = (bra_t*)(adrp + 3);
    if
    (
        is_ldr_imm_uoff(ldr1) && ldr1->sf == 1 && is_br(br) &&  // Types
        adrp->Rd == ldr1->Rn && ldr1->Rt == br->Rn              // Registers
    )
    {
        *addr = (alias & ~0xfffULL) + get_adr_off(adrp) + get_ldr_imm_uoff(ldr1);
        return true;
    }
    else if
    (
        space_for_4 &&
        is_add_imm(add) && add->sf == 1 && is_ldr_imm_uoff(ldr2) && ldr2->sf == 1 && is_bra(bra) && // Types
        adrp->Rd == add->Rn && add->Rd == ldr2->Rn && ldr2->Rt == bra->Rn && ldr2->Rn == bra->Rm && // Registers
        get_ldr_imm_uoff(ldr2) == 0
    )
    {
        *addr = (alias & ~0xfffULL) + get_adr_off(adrp) + get_add_sub_imm(add);
        return true;
    }
    return false;
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
                        if(is_adrp(adrp))
                        {
                            kptr_t inset = ((uintptr_t)adrp - ((uintptr_t)kernel + seg->fileoff));
                            kptr_t alias = seg->vmaddr + inset;
                            kptr_t addr;
                            if(!get_import_target(adrp, alias, seg->filesize - inset >= 4 * sizeof(uint32_t), &addr))
                            {
                                continue;
                            }
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
        bool bind;
        size_t skip = 0;
        kuntag(kbase, fixupKind, vtab[idx - 1], &bind, NULL, NULL, &skip);
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
                                            if(kuntag(kbase, fixupKind, *mem, NULL, NULL, NULL, &skip) == func)
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
        else if(fixupKind == DYLD_CHAINED_PTR_ARM64E_KERNEL || fixupKind == DYLD_CHAINED_PTR_64_KERNEL_CACHE)
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
                            size_t off = (size_t)starts->segment_offset + (size_t)j * (size_t)starts->page_size + (size_t)idx;
                            kptr_t *mem = fixupKind == DYLD_CHAINED_PTR_ARM64E_KERNEL ? addr2ptr(kernel, kbase + off) : (kptr_t*)((uintptr_t)kernel + off);
                            size_t skip = 0;
                            do
                            {
                                if(kuntag(kbase, fixupKind, *mem, NULL, NULL, NULL, &skip) == func)
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
                if(kuntag(kbase, fixupKind, *mem, NULL, NULL, NULL, NULL) == func)
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
                        if(is_adrp(adrp))
                        {
                            kptr_t inset = ((uintptr_t)adrp - ((uintptr_t)kernel + seg->fileoff));
                            kptr_t alias = seg->vmaddr + inset;
                            kptr_t addr;
                            if(!get_import_target(adrp, alias, seg->filesize - inset >= 4 * sizeof(uint32_t), &addr))
                            {
                                continue;
                            }
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
    /*if(!info)
    {
        ERR("Failed to find PrelinkInfo");
        goto out;
    }*/
out:;
    if(err) CFRelease(err);
    return info;
}

static void print_help(const char *self)
{
    fprintf(stderr, "Usage:\n"
                    "    %s [-aAbBCdeGilmMnoOpRsSvz] [ClassName] [OverrideName] [BundleName] kernel [SymbolMap]\n"
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
                    "    -l  Print OSMetaClass subclasses\n"
                    "    -m  Print OSMetaClass addresses\n"
                    "    -M  Print symbol map (implies -o, takes precedence)\n"
                    "    -MM Same as above, and copy input map for missing classes\n"
                    "    -o  Print overridden/new virtual methods\n"
                    "    -R  Print symbols for radare2 (implies -lmov, takes precedence)\n"
                    "    -s  Print object sizes\n"
                    "    -v  Print object vtabs\n"
                    "    -z  Print mangled symbols\n"
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
        .metaclass = 0,
        .maxmap    = 0,
        .overrides = 0,
        .ofilt     = 0,
        .parent    = 0,
        .size      = 0,
        .symmap    = 0,
        .vtab      = 0,
        .mangle    = 0,
        ._reserved = 0,
    };
    const char *filt_class    = NULL,
               *filt_bundle   = NULL,
               *filt_override = NULL;
    print_t *print = NULL;

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
                case 'l':
                {
                    opt.metaclass = 1;
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
                    if(print && print != &radare2_print)
                    {
                        ERR("TODO");
                        return -1;
                    }
                    print = &radare2_print;
                    opt.meta      = 1;
                    opt.metaclass = 1;
                    opt.overrides = 1;
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
                case 'z':
                {
                    opt.mangle = 1;
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

    if(opt.symmap && (opt.bfilt || opt.cfilt || opt.ofilt || opt.bsort || opt.csort || opt.extend || opt.parent || opt.mangle))
    {
        ERR("Cannot use filters, sorting or mangling with -M.");
        return -1;
    }
    if(opt.symmap && print)
    {
        ERR("Only one of -M or -R may be given.");
        return -1;
    }
    if(opt.extend && opt.parent)
    {
        ERR("Only one of -e or -p may be given.");
        return -1;
    }
    if(opt.bsort && opt.csort)
    {
        ERR("Only one of -G or -S may be given.");
        return -1;
    }

    if(!opt.symmap && !print)
    {
        print = &iometa_print;
    }
    if(opt.cfilt)
    {
        filt_class = argv[aoff++];
    }
    if(opt.ofilt)
    {
        filt_override = argv[aoff++];
    }
    if(opt.bfilt)
    {
        filt_bundle = argv[aoff++];
    }
    bool want_vtabs = opt.vtab || opt.overrides || opt.ofilt;

    void *kernel = NULL;
    size_t kernelsize = 0;
    r = map_file(argv[aoff++], PROT_READ, &kernel, &kernelsize);
    if(r != 0) return r;
    mach_hdr_t *hdr = kernel;
    r = validate_macho(&kernel, &kernelsize, &hdr, NULL);
    if(r != 0) return r;

    symmap_t symmap = { 0, NULL };
    if(have_symmap)
    {
        void *symmapMem = NULL;
        size_t symmmapLen = 0;
        r = map_file(argv[aoff++], PROT_READ | PROT_WRITE, &symmapMem, &symmmapLen);
        if(r != 0) return r;
        r = parse_symmap(symmapMem, symmmapLen, &symmap);
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
                fixupKind = starts->pointer_format;
                break;
            }
            // Chained imports for kexts
            if(hdr->filetype == MH_KEXT_BUNDLE)
            {
                if(!macho_extract_chained_imports(kernel, kbase, data, &exrelocA, &nexreloc))
                {
                    return -1;
                }
            }
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
    metaclass_t *OSMetaClass = NULL;

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
            void *sp = malloc(A64_EMU_SPSIZE),
                 *bitstr = malloc((A64_EMU_SPSIZE + 31) / 32);
            if(!sp || !bitstr)
            {
                ERR("malloc(sp) || malloc(bitstr)");
                return -1;
            }
            a64_state_t state;
            bool success = multi_call_emulate(kernel, kbase, fixupKind, current->fncall, current->fncall, &state, sp, bitstr, 0xf, current->name);
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
            free(bitstr);
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
    for(size_t i = 0; i < metas.idx; ++i)
    {
        metaclass_t *meta = &metas.val[i];
        if(meta->vtab != 0)
        {
            // Propagate through entire hierarchy
            for(metaclass_t *p = meta->parentP; p; p = p->parentP)
            {
                if(p->vtab || p->has_dependents)
                {
                    break;
                }
                p->has_dependents = 1;
            }
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

                if(prelink_info)
                {
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
                                    state.flags = 0;
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
            for(size_t i = 0; is_part_of_vtab(kernel, kbase, fixupKind, locreloc.val, locreloc.idx, exrelocA, nexreloc, ovtab, OSObjectVtab, i); ++i)
            {
                bool bind = false;
                if(kuntag(kbase, fixupKind, ovtab[i], &bind, NULL, NULL, NULL) == OSObjectGetMetaClass)
                {
                    if(bind)
                    {
                        continue;
                    }
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
#if 0
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
#endif
                                adr_t      *adr1 = (adr_t*     )(mem + 0);
                                add_imm_t  *add1 = (add_imm_t* )(mem + 1);
                                adr_t      *adr2 = (adr_t*     )(mem + 3);
                                add_imm_t  *add2 = (add_imm_t* )(mem + 4);
                                if
                                (
                                    (is_adr(adr1)  && is_nop((uint32_t*)add1)) ||
                                    (is_adrp(adr1) && is_add_imm(add1) && adr1->Rd == add1->Rn)
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
                                    for(size_t i = 0; i < 5; ++i)
                                    {
                                        if
                                        (
                                            (is_adr(adr2)  && is_nop((uint32_t*)add2) && adr2->Rd == 0) ||
                                            (is_adrp(adr2) && is_add_imm(add2)        && adr2->Rd == add2->Rn && add2->Rd == 0)
                                        )
                                        {
                                            goto x0_matches;
                                        }
                                        ++adr2;
                                        ++add2;
                                    }
                                    DBG("__cxa_pure_virtual: failed to find adr(p) x0");
                                    continue;

                                    x0_matches:;
                                    if(is_adrp(adr2))
                                    {
                                        ref2 &= ~0xfff;
                                        ref2 += get_add_sub_imm(add2);
                                    }
                                    ref2 += get_adr_off(adr2);
                                    const char *x0 = addr2ptr(kernel, ref2);
                                    if(strcmp(x0, "\"%s\"") != 0 && strcmp(x0, "%s @%s:%d"))
                                    {
                                        DBG("__cxa_pure_virtual: x0 != \"%%s\" && x0 != %%s @%%s:%%d");
                                        continue;
                                    }

                                    add_imm_t *add = (add_imm_t*)(mem - 1);
                                    for(size_t i = 0; i < 5; ++i)
                                    {
                                        if(is_add_imm(add) && add->Rd == 29 && add->Rn == 31) // ignore add amount
                                        {
                                            goto x29_matches;
                                        }
                                        --add;
                                    }
                                    DBG("__cxa_pure_virtual: add x29, sp, ...");
                                    continue;

                                    x29_matches:;
                                    uint32_t *loc = (uint32_t*)add;
                                    refloc -= (mem - loc) * sizeof(uint32_t);

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
                for(size_t i = 0; is_part_of_vtab(kernel, kbase, fixupKind, locreloc.val, locreloc.idx, exrelocA, nexreloc, ovtab, OSObjectVtab, i); ++i)
                {
                    if(kuntag(kbase, fixupKind, ovtab[i], NULL, NULL, NULL, NULL) == pure_virtual)
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
                                                                                if(kuntag(kbase, fixupKind, *mem2, NULL, NULL, NULL, &skip) == func)
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
                                            else if(fixupKind == DYLD_CHAINED_PTR_ARM64E_KERNEL || fixupKind == DYLD_CHAINED_PTR_64_KERNEL_CACHE)
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
                                                                size_t off = (size_t)starts->segment_offset + (size_t)j * (size_t)starts->page_size + (size_t)idx;
                                                                kptr_t *mem2 = fixupKind == DYLD_CHAINED_PTR_ARM64E_KERNEL ? addr2ptr(kernel, kbase + off) : (kptr_t*)((uintptr_t)kernel + off);
                                                                size_t skip = 0;
                                                                do
                                                                {
                                                                    if(kuntag(kbase, fixupKind, *mem2, NULL, NULL, NULL, &skip) == func)
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
                                                                if(kuntag(kbase, fixupKind, *mem2, NULL, NULL, NULL, NULL) == func && *(mem2 - VtabGetMetaClassIdx - 1) == 0 && *(mem2 - VtabGetMetaClassIdx - 2) == 0)
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
                kptr_t fnaddr = kuntag(kbase, fixupKind, ovtab[VtabAllocIdx], NULL, NULL, NULL, NULL);
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
                                void *sp      = malloc(A64_EMU_SPSIZE),
                                     *bitstr  = malloc((A64_EMU_SPSIZE + 31) / 32),
                                     *obj     = NULL,
                                     *obitstr = NULL;
                                if(!sp || !bitstr)
                                {
                                    ERR("malloc(sp) || malloc(bitstr)");
                                    return -1;
                                }
                                bzero(sp, A64_EMU_SPSIZE);
                                bzero(bitstr, (A64_EMU_SPSIZE + 31) / 32);
                                uint32_t *m = NULL;
                                a64_state_t state;
                                for(size_t i = 0; i < 32; ++i)
                                {
                                    state.x[i] = 0;
                                    state.q[i] = 0;
                                }
                                state.x[ 0]  = 0x6174656d656b6166; // "fakemeta", fake "this" ptr
                                state.x[31]  = (uintptr_t)sp + A64_EMU_SPSIZE;
                                state.flags  = 0;
                                state.valid  = 0xfff80001;
                                state.qvalid = 0x0000ff00;
                                state.wide   = 0xfff80001;
                                state.host   = 0;
                                HOST_SET(&state, 31, 1);
                                state.hostmem[0].min = (uintptr_t)sp;
                                state.hostmem[0].max = (uintptr_t)sp + A64_EMU_SPSIZE;
                                state.hostmem[0].bitstring = bitstr;
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
                                            if((state.valid & 0xff) == 0x7 && (state.wide & 0x7) == 0x5 && HOST_GET(&state, 0) == 1) // kalloc
                                            {
                                                allocsz = *(kptr_t*)state.x[0];
                                            }
                                            else if((state.valid & 0xff) == 0x1) // new
                                            {
                                                allocsz = state.x[0];
                                            }
                                            else if((state.valid & 0xff) == 0xf && (state.wide & 0xf) == 0x9) // hell do I know
                                            {
                                                allocsz = state.x[1];
                                            }
                                            else
                                            {
                                                //if(meta->vtab == -1)
                                                {
                                                    WRN("Bad pre-bl state in %s::MetaClass::alloc (%08x %08x %016llx)", meta->name, state.valid, state.wide, state.host);
                                                }
                                                break;
                                            }
                                            if(allocsz != meta->objsize)
                                            {
                                                //if(meta->vtab == -1)
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
                                            obitstr = malloc((allocsz + 31) / 32);
                                            if(!obj || !obitstr)
                                            {
                                                ERR("malloc(obj) || malloc(obitstr)");
                                                return -1;
                                            }
                                            bzero(obj, allocsz);
                                            bzero(obitstr, (allocsz + 31) / 32);
                                            state.x[0] = (uintptr_t)obj;
                                            state.valid |= 0x1;
                                            state.wide  |= 0x1;
                                            HOST_SET(&state, 0, 2);
                                            state.hostmem[1].min = (uintptr_t)obj;
                                            state.hostmem[1].max = (uintptr_t)obj + allocsz;
                                            state.hostmem[1].bitstring = obitstr;
                                            uint32_t *e = m + 1;
                                            for(; e < end; ++e)
                                            {
                                                if(is_ret(e))
                                                {
                                                    break;
                                                }
                                            }
                                            if(a64_emulate(kernel, kbase, fixupKind, &state, m + 1, &a64cb_check_equal, e, false, true, kEmuFnEnter) != kEmuEnd)
                                            {
                                                break;
                                            }
                                            if(!(state.valid & 0x1) || !(state.wide & 0x1) || !HOST_GET(&state, 0))
                                            {
                                                WRN("Bad end state in %s::MetaClass::alloc (%08x %08x %016llx)", meta->name, state.valid, state.wide, state.host);
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
                                        break;
                                    default:
                                        break;
                                }
                                if(obj) free(obj);
                                if(obitstr) free(obitstr);
                                free(sp);
                                free(bitstr);
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
                    // If the symmap has methods for this class (which has no vtab), then there are two possibilities:
                    // - The class has children, in which case the symmap is always wrong.
                    // - The class has no children, in which case it's unused and the compiler presumably optimised the vtab out.
                    //   In that case we wanna silence this warning, because if it had children, the symmap would probably be right.
                    if(meta->symclass && meta->symclass->num != 0 && meta->has_dependents)
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
                    WRN("%s has fewer methods than its parent (%lu vs %lu).", meta->name, nmeth, pnmeth);
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
                         auth          = false,
                         is_in_exreloc = false;

                    kptr_t koff = meta->vtab + sizeof(kptr_t) * idx;
                    // TODO: handle multiple symbols for same addr
                    cxx_sym = find_sym_by_addr(koff, exrelocA, nexreloc);
                    if(cxx_sym)
                    {
                        is_in_exreloc = true;
                        if(fixupKind == DYLD_CHAINED_PTR_ARM64E_KERNEL)
                        {
                            bool bind = false;
                            bool a = false;
                            uint16_t p = false;
                            kuntag(kbase, fixupKind, mvtab[idx], &bind, &a, &p, NULL);
                            if(bind)
                            {
                                auth = a;
                                pac  = p;
                            }
                        }
                    }
                    else
                    {
                        func = kuntag(kbase, fixupKind, mvtab[idx], NULL, &auth, &pac, NULL);
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
                        if(method && smeth->method && !smeth->structor && (strcmp(class, smeth->class) != 0 || strcmp(method, smeth->method) != 0))
                        {
                            WRN("Overriding %s::%s from symtab with %s::%s from symmap", class, method, smeth->class, smeth->method);
                            // Clear symbol
                            cxx_sym = NULL;
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
                    // will not match, and literally all of the complexity below is due to that:
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

                    if(pent && pent->auth != auth)
                    {
                        WRN("Auth mismatch: %s::%s is %s, but %s::%s is %s", pent->class, pent->method, pent->auth ? "auth" : "unauth", class, method, auth ? "auth" : "unauth");
                    }

                    // If we're on arm64e and have a symbol that we believe should be correct, we can check if it matches the PAC diversifier.
                    // In order to avoid duplicate work, we wanna skip this if we already did for the parent, but determining if we did that is a bit of a pain.
                    // We also need to outright skip kexts, because there will always be classes whose superclass isn't in the kext,
                    // so we have absolutely no way of determining where any given method of such classes was declared. :|
                    if(auth && (hdr->cpusubtype & CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E && hdr->filetype != MH_KEXT_BUNDLE && !is_in_exreloc && authoritative && (!pent || !pent->authoritative))
                    {
                        // The PAC diversifier is a hash of the mangled symbol of the method in the first class that declares it. Since the symbol contains
                        // the class name, we have to traverse the hierarchy here. In theory we'd just seek down to the first class with a large enough vtable
                        // to contain the current method index, and substitute the class name for the one of that class, and hash the resulting symbol.
                        // But with abstract classes involved, if we don't get a match there, then we have to keep going as long as the parent classes
                        // have no vtable, because any one of them could have been the one to declare the method.
                        // Further, there are two exceptions:
                        // - If we get to the bottom of the hierarchy, then we still have to try "OSMetaClassBase" as class name,
                        //   since that is the true parent class in source, but it isn't captures by the metaclass system.
                        // - If we're at the current class, then we use the provided class name from symbol/symmap rather than the actual class name.

                        if(cxx_sym)
                        {
                            DBG("Checking diversifier of %s::%s (class: %s, sym: %s)", class, method, meta->name, cxx_sym);
                        }
                        else
                        {
                            DBG("Checking diversifier of %s::%s (class: %s)", class, method, meta->name);
                        }

                        // If we have no parent method entry, we can skip seeking here
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
                        metaclass_t *p = checkClass;
                        do
                        {
                            const char *className = p == meta ? class
                                                  : p != NULL ? p->name
                                                  : "OSMetaClassBase";
                            char *sym = NULL;
                            if(structor)
                            {
                                // TODO: Everywhere else I support both con- and destructors and don't make any assumptions about indices.
                                //       But both destructors look exactly the same de-mangled, so this is the only indicator I have, at least for now.
                                //       I guess this will at least spew a warning if things ever break. :|
                                asprintf(&sym, "__ZN%zu%sD%zuEv", strlen(className), className, 1 - idx);
                                if(!sym)
                                {
                                    ERRNO("asprintf(sym)");
                                    return -1;
                                }
                            }
                            else
                            {
                                sym = cxx_mangle(className, method);
                                if(!sym)
                                {
                                    WRN("Failed to mangle %s::%s", className, method);
                                    break;
                                }
                            }

                            uint16_t div = 0;
                            if(!cxx_compute_pac(sym, &div))
                            {
                                ERR("Failed to compute PAC diversifier. This means something is very broken.");
                                return -1;
                            }
                            DBG("Computed PAC 0x%04hx for symbol %s", div, sym);

                            // Optimisation: if we computed the symbol for the current class and don't have one yet,
                            // we may as well keep it. Otherwise this may be done later, but no need to duplicate work.
                            if(p == meta && !cxx_sym)
                            {
                                cxx_sym = sym;
                            }
                            else
                            {
                                free(sym);
                            }

                            if(div == pac)
                            {
                                break;
                            }
                            if(p && (!(p = p->parentP) || !p->vtab))
                            {
                                continue;
                            }
                            WRN("PAC verification failed for %s::%s", checkClass == meta ? class : checkClass->name, method);
                            break;
                        } while(1);
                    }

                    ent->chain = chain;
                    ent->mangled = cxx_sym;
                    ent->class = class;
                    ent->method = method;
                    ent->addr = func;
                    ent->pac = pac;
                    ent->structor = !!structor;
                    ent->authoritative = !!authoritative;
                    ent->overrides = !!overrides;
                    ent->auth = !!auth;
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

            if(opt.metaclass)
            {
                DBG("Populating MetaClass vtabs...");
                symmap_class_t *symcls = NULL;
                size_t nmetameth = -1;
                if(hdr->filetype != MH_KEXT_BUNDLE)
                {
                    for(size_t i = 0; i < metas.idx; ++i)
                    {
                        metaclass_t *meta = &metas.val[i];
                        if(strcmp(meta->name, "OSMetaClass") == 0)
                        {
                            if(!meta->methods_done || meta->methods_err || meta->vtab == 0)
                            {
                                WRN("Bad OSMetaClass state: %u/%u/" ADDR, meta->methods_done, meta->methods_err, meta->vtab);
                            }
                            else
                            {
                                OSMetaClass = meta;
                                nmetameth = meta->nmethods;
                            }
                            break;
                        }
                    }
                }
                else if(symmap.map)
                {
                    symcls = bsearch("OSMetaClass", symmap.map, symmap.num, sizeof(*symmap.map), &compare_symclass_name);
                    if(symcls)
                    {
                        while(symcls->duplicate)
                        {
                            --symcls;
                        }
                        nmetameth = symcls->num;
                    }
                }
                for(size_t i = 0; i < metas.idx; ++i)
                {
                    metaclass_t *meta = &metas.val[i];
                    DBG("Populating vtab for %s::MetaClass", meta->name);
                    kptr_t *mvtab = addr2ptr(kernel, meta->metavtab);
                    if(!mvtab)
                    {
                        ERR("Vtab of %s::MetaClass lies outside all segments.", meta->name);
                        return -1;
                    }
                    size_t nmeth = 0;
                    while(is_part_of_vtab(kernel, kbase, fixupKind, locreloc.val, locreloc.idx, exrelocA, nexreloc, mvtab, meta->metavtab, nmeth))
                    {
                        ++nmeth;
                    }
                    if(nmetameth != -1 && nmeth != nmetameth)
                    {
                        WRN("%s::MetaClass has a different amount of methods than the base class (%lu vs %lu).", meta->name, nmeth, nmetameth);
                        goto done;
                    }
                    meta->metamethods = malloc(nmeth * sizeof(*meta->metamethods));
                    if(!meta->metamethods)
                    {
                        ERRNO("malloc(metamethods)");
                        return -1;
                    }
                    meta->nmetamethods = nmeth;
                    char *mname = NULL;
                    asprintf(&mname, "%s::MetaClass", meta->name);
                    if(!mname)
                    {
                        ERRNO("asprintf(mname)");
                        return -1;
                    }
                    for(size_t idx = 0; idx < nmeth; ++idx)
                    {
                        // TODO: There is a LOT of code duplication here :/
                        vtab_entry_t *ent  = &meta->metamethods[idx],
                                     *pent = (OSMetaClass && idx < OSMetaClass->nmethods) ? &OSMetaClass->methods[idx] : NULL;
                        kptr_t func  = 0;
                        uint16_t pac = 0;
                        const char *cxx_sym = NULL,
                                   *class   = NULL,
                                   *method  = NULL;
                        bool structor      = false,
                             authoritative = false,
                             overrides     = false,
                             auth          = false,
                             is_in_exreloc = false;

                        kptr_t koff = meta->metavtab + sizeof(kptr_t) * idx;
                        cxx_sym = find_sym_by_addr(koff, exrelocA, nexreloc);
                        if(cxx_sym)
                        {
                            is_in_exreloc = true;
                            if(fixupKind == DYLD_CHAINED_PTR_ARM64E_KERNEL)
                            {
                                bool bind = false;
                                bool a = false;
                                uint16_t p = false;
                                kuntag(kbase, fixupKind, mvtab[idx], &bind, &a, &p, NULL);
                                if(bind)
                                {
                                    auth = a;
                                    pac  = p;
                                }
                            }
                        }
                        else
                        {
                            func = kuntag(kbase, fixupKind, mvtab[idx], NULL, &auth, &pac, NULL);
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
                        if(!method && symcls && idx < symcls->num)
                        {
                            symmap_method_t *smeth = &symcls->methods[idx];
                            if(!overrides)
                            {
                                class = smeth->class;
                            }
                            method = smeth->method;
                            structor = smeth->structor;
                            if(method)
                            {
                                authoritative = true;
                            }
                        }
                        if(!method && pent)
                        {
                            method = pent->method;
                            if(!pent->structor)
                            {
                                class = overrides ? mname : pent->class;
                                authoritative = pent->authoritative;
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
                                    char *strname = mname;
                                    while(true)
                                    {
                                        char *m = strstr(strname, "::");
                                        if(!m) break;
                                        strname = m + 2;
                                    }
                                    mth += clslen;
                                    char *meth = NULL;
                                    asprintf(&meth, "%s%s%s", dest ? "~" : "", strname, mth);
                                    if(!meth)
                                    {
                                        ERRNO("asprintf(structor)");
                                        return -1;
                                    }
                                    method = meth;
                                    class = mname;
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
                            class = mname;
                        }
                        // Don't bother with PAC verification here. We expect to mostly override abstract methods,
                        // and those are precisely the ones we'd have to skip anyway, so...

                        ent->chain = NULL;
                        ent->mangled = cxx_sym;
                        ent->class = class;
                        ent->method = method;
                        ent->addr = func;
                        ent->pac = pac;
                        ent->structor = !!structor;
                        ent->authoritative = !!authoritative;
                        ent->overrides = !!overrides;
                        ent->auth = !!auth;
                        ent->reserved = 0;
                    }
                }
            }

            if(opt.mangle)
            {
                for(size_t i = 0; i < metas.idx; ++i)
                {
                    metaclass_t *meta = &metas.val[i];
                    for(size_t idx = 0; idx < meta->nmethods; ++idx)
                    {
                        vtab_entry_t *ent = &meta->methods[idx];
                        if(!ent->mangled)
                        {
                            if(ent->structor)
                            {
                                // TODO: See above
                                char *sym = NULL;
                                asprintf(&sym, "__ZN%lu%sD%luEv", strlen(ent->class), ent->class, 1 - idx);
                                if(!sym)
                                {
                                    ERRNO("asprintf(ent->mangled)");
                                    return -1;
                                }
                                ent->mangled = sym;
                            }
                            else
                            {
                                ent->mangled = cxx_mangle(ent->class, ent->method);
                                if(!ent->mangled)
                                {
                                    ERR("Failed to mangle %s::%s", ent->class, ent->method);
                                    return -1;
                                }
                            }
                        }
                    }
                    if(opt.metaclass)
                    {
                        for(size_t idx = 0; idx < meta->nmetamethods; ++idx)
                        {
                            vtab_entry_t *ent = &meta->metamethods[idx];
                            if(!ent->mangled)
                            {
                                if(ent->structor)
                                {
                                    // TODO: See above
                                    int i = 0;
                                    char buf[512];
                                    buf[0] = '\0';
#define P(fmt, ...) \
do \
{ \
i += snprintf(buf + i, sizeof(buf) - i, (fmt), ##__VA_ARGS__); \
if(i >= sizeof(buf)) return -1; \
} while(0)
                                    P("__ZN");
                                    const char *strname = ent->class;
                                    while(true)
                                    {
                                        const char *m = strstr(strname, "::");
                                        if(!m)
                                        {
                                            P("%lu%s", strlen(strname), strname);
                                            break;
                                        }
                                        P("%lu%.*s", m - strname, (int)(m - strname), strname);
                                        strname = m + 2;
                                    }
                                    P("D%luEv", 1 - idx);
#undef P
                                    ent->mangled = strdup(buf);
                                    if(!ent->mangled)
                                    {
                                        ERRNO("strdup(ent->mangled)");
                                        return -1;
                                    }
                                }
                                else
                                {
                                    ent->mangled = cxx_mangle(ent->class, ent->method);
                                    if(!ent->mangled)
                                    {
                                        ERR("Failed to mangle %s::%s", ent->class, ent->method);
                                        return -1;
                                    }
                                }
                            }
                        }
                    }
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
                        mach_hdr_t *exhdr = addr2ptr(kernel, kuntag(kbase, fixupKind, start_ptr[kmod_num], NULL, NULL, NULL, NULL));
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
                    kptr_t iaddr = kuntag(kbase, fixupKind, info_ptr[i],  NULL, NULL, NULL, NULL);
                    kptr_t haddr = kuntag(kbase, fixupKind, start_ptr[i], NULL, NULL, NULL, NULL);
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
                                kptr_t vmaddr = kuntag(kbase, fixupKind, kseg->vmaddr, NULL, NULL, NULL, NULL);
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

                if(!prelink_info)
                {
                    if(filt_bundle)
                    {
                        bundleList = malloc(sizeof(*bundleList));
                        if(!bundleList)
                        {
                            ERRNO("malloc(bundleList)");
                            return -1;
                        }
                    }
                }
                else
                {
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

    // Symmap will always need special handling due to maxmap
    bool ok = opt.symmap ? print_symmap(&metas, &symmap, opt) : print_all(&metas, opt, OSMetaClass, filt_class, filt_override, filter, pure_virtual, OSMetaClassConstructor, OSMetaClassAltConstructor, print);
    if(!ok)
    {
        return -1;
    }

    return 0;
}
