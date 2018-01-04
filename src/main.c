#include <errno.h>
#include <fcntl.h>              // open
#include <stdbool.h>
#include <stdint.h>             // uintptr_t
#include <stdio.h>              // fprintf, stderr
#include <stdlib.h>             // malloc, realloc, exit
#include <string.h>             // strerror
#include <sys/mman.h>           // mmap
#include <sys/stat.h>           // fstat
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

static bool debug = true; // XXX

#define LOG(str, args...) do { fprintf(stderr, str "\n", ##args); } while(0)
#define DBG(str, args...) do { if(debug) LOG("\x1b[1;95m[DBG] " str "\x1b[0m", ##args); } while(0)
#define ERR(str, args...) LOG("\x1b[1;91m[ERR] " str "\x1b[0m", ##args)
#define ERRNO(str) ERR(str ": %s", strerror(errno))

#define ADDR "0x%016llx"
#define MACH_MAGIC MH_MAGIC_64
#define MACH_SEGMENT LC_SEGMENT_64
typedef struct mach_header_64 mach_hdr_t;
typedef struct load_command mach_lc_t;
typedef struct segment_command_64 mach_seg_t;
typedef struct symtab_command mach_stab_t;
typedef struct nlist_64 nlist_t;
typedef uint64_t kptr_t;

#define FOREACH_CMD(hdr, cmd) \
for( \
    mach_lc_t *cmd = (mach_lc_t*)(hdr + 1), *end = (mach_lc_t*)((uintptr_t)cmd + hdr->sizeofcmds - sizeof(mach_lc_t)); \
    cmd <= end; \
    cmd = (mach_lc_t*)((uintptr_t)cmd + cmd->cmdsize) \
)

#pragma pack(4)
typedef struct
{
    uint32_t Rd     : 5,
             immhi  : 19,
             op2    : 5,
             immlo  : 2,
             op1    : 1;
} adrp_t;

typedef struct
{
    uint32_t Rd     : 5,
             Rn     : 5,
             imm    : 12,
             shift  : 2,
             op     : 7,
             sf     : 1;
} add_imm_t;

typedef struct
{
    uint32_t Rt     : 5,
             Rn     : 5,
             imm    : 12,
             op     : 10;
} ldr_uoff_t;

typedef struct
{
    uint32_t op2    : 5,
             Rn     : 5,
             op1    : 22;
} br_t;

typedef struct
{
    uint32_t imm    : 26,
             op     : 5,
             mode   : 1;
} bl_t;
#pragma pack()

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

int main(int argc, const char **argv)
{
    if(argc < 2)
    {
        fprintf(stderr, "Usage:\n"
                        "    %s kernel\n"
                        , argv[0]);
        return 0;
    }

    int fd = open(argv[1], O_RDONLY);
    if(fd == -1)
    {
        ERRNO("open");
        return -1;
    }

    struct stat s;
    if(fstat(fd, &s) != 0)
    {
        ERRNO("fstat");
        return -1;
    }

    if(s.st_size < sizeof(mach_hdr_t))
    {
        ERR("File is too short to be a Mach-O.");
        return -1;
    }

    void *kernel = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(kernel == MAP_FAILED)
    {
        ERRNO("mmap");
        return -1;
    }

    mach_hdr_t *hdr = (mach_hdr_t*)kernel;
    if(hdr->magic != MACH_MAGIC)
    {
        ERR("Wrong magic: 0x%08x", hdr->magic);
        return -1;
    }

    struct
    {
        size_t size;
        size_t idx;
        kptr_t *val;
    } aliases =
    {
        .size = 0x100,
        .idx = 0,
    };
    aliases.val = malloc(aliases.size * sizeof(kptr_t));
    if(!aliases.val)
    {
        ERRNO("malloc");
        return -1;
    }
    struct
    {
        size_t size;
        size_t idx;
        kptr_t *val;
    } refs =
    {
        .size = 0x100,
        .idx = 0,
    };
    refs.val = malloc(refs.size * sizeof(kptr_t));
    if(!refs.val)
    {
        ERRNO("malloc");
        return -1;
    }
#define ADDVAL(thing, ptr) \
do \
{ \
    if((thing).size <= (thing).idx) \
    { \
        (thing).size *= 2; \
        (thing).val = realloc((thing).val, (thing).size * sizeof(*(thing).val)); \
        if(!(thing).val) \
        { \
            ERR("realloc(0x%lx): %s", (thing).size, strerror(errno)); \
        } \
    } \
    (thing).val[(thing).idx++] = (ptr); \
} while(0)

    kptr_t OSMetaClassConstructor = 0;
    FOREACH_CMD(hdr, cmd)
    {
        if(cmd->cmd == LC_SYMTAB)
        {
            mach_stab_t *stab = (mach_stab_t*)cmd;
            nlist_t *sym = (nlist_t*)((uintptr_t)kernel + stab->symoff);
            char *str = (char*)((uintptr_t)kernel + stab->stroff);
            for(size_t i = 0; i < stab->nsyms; ++i)
            {
                if(strcmp(&str[sym[i].n_un.n_strx], "__ZN11OSMetaClassC2EPKcPKS_j") == 0)
                {
                    OSMetaClassConstructor = sym[i].n_value;
                    DBG("OSMetaClass::OSMetaClass: " ADDR, OSMetaClassConstructor);
                }
            }
            break;
        }
    }
    if(OSMetaClassConstructor == 0)
    {
        ERR("Failed to find OSMetaClass::OSMetaClass.");
        return -1;
    }

    ADDVAL(aliases, OSMetaClassConstructor);

    for(kptr_t *mem = kernel, *end = (kptr_t*)((uintptr_t)kernel + s.st_size); mem < end; ++mem)
    {
        if(*mem == OSMetaClassConstructor)
        {
            kptr_t ref = off2addr(kernel, (uintptr_t)mem - (uintptr_t)kernel);
            DBG("ref: " ADDR, ref);
            ADDVAL(refs, ref);
        }
    }

    FOREACH_CMD(hdr, cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            for(uint32_t *mem = (uint32_t*)((uintptr_t)kernel + seg->fileoff), *end = (uint32_t*)((uintptr_t)kernel + seg->fileoff + seg->filesize - 3 * sizeof(uint32_t)); mem <= end; ++mem)
            {
                adrp_t *adrp = (adrp_t*)mem;
                ldr_uoff_t *ldr = (ldr_uoff_t*)(mem + 1);
                br_t *br = (br_t*)(mem + 2);
                if
                (
                    adrp->op1 == 1 && adrp->op2 == 0x10 && ldr->op == 0x3e5 && br->op1 == 0x3587c0 && br->op2 == 0 && // Types
                    adrp->Rd == ldr->Rn && ldr->Rt == br->Rn                                                          // Registers
                )
                {
                    kptr_t alias = seg->vmaddr + ((uintptr_t)adrp - ((uintptr_t)kernel + seg->fileoff));
                    kptr_t addr = alias & ~0xfff;
                    addr += (((int64_t)(adrp->immlo | (adrp->immhi << 2))) << (64 - 21)) >> (64 - 21 - 12);
                    addr += ldr->imm << 3;
                    for(size_t i = 0; i < refs.idx; ++i)
                    {
                        if(addr == refs.val[i])
                        {
                            DBG("alias: " ADDR, alias);
                            ADDVAL(aliases, alias);
                            break;
                        }
                    }
                }
            }
        }
    }

    FOREACH_CMD(hdr, cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            for(uint32_t *mem = (uint32_t*)((uintptr_t)kernel + seg->fileoff), *end = (uint32_t*)((uintptr_t)kernel + seg->fileoff + seg->filesize - 3 * sizeof(uint32_t)); mem <= end; ++mem)
            {
                bl_t *bl = (bl_t*)mem;
                if(bl->op == 0x5)
                {
                    kptr_t addr = seg->vmaddr + ((uintptr_t)bl - ((uintptr_t)kernel + seg->fileoff));
                    addr &= ~0xfff;
                    addr += (((int64_t)bl->imm) << (64 - 26)) >> (64 - 26 - 2);
                    for(size_t i = 0; i < aliases.idx; ++i)
                    {
                        if(addr == aliases.val[i])
                        {
                            DBG(ADDR, seg->vmaddr + ((uintptr_t)bl - ((uintptr_t)kernel + seg->fileoff)));
                        }
                    }
                }
            }
        }
    }

    return 0;
}
