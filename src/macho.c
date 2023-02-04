/* Copyright (c) 2018-2020 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>             // exit, realloc

#include "macho.h"
#include "util.h"

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
