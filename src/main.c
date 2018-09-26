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
#include <stdlib.h>             // malloc, realloc, qsort, exit
#include <string.h>             // strerror, strcmp, strstr, memmem
#include <sys/mman.h>           // mmap
#include <sys/stat.h>           // fstat
#include <mach/machine.h>       // CPU_TYPE_ARM64
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <CoreFoundation/CoreFoundation.h>

extern CFTypeRef IOCFUnserialize(const char *buffer, CFAllocatorRef allocator, CFOptionFlags options, CFStringRef *errorString);

#include "a64.h"
#include "cxx.h"

static bool debug = false;

#define LOG(str, args...)   do { fprintf(stderr, str "\n", ##args); } while(0)
#define DBG(str, args...)   do { if(debug) LOG("\x1b[1;95m[DBG] " str "\x1b[0m", ##args); } while(0)
#define WRN(str, args...)   LOG("\x1b[1;93m[WRN] " str "\x1b[0m", ##args)
#define ERR(str, args...)   LOG("\x1b[1;91m[ERR] " str "\x1b[0m", ##args)
#define ERRNO(str, args...) ERR(str ": %s", ##args, strerror(errno))

#define STRINGIFX(x) #x
#define STRINGIFY(x) STRINGIFX(x)

#define SWAP32(x) (((x & 0xff000000) >> 24) | ((x & 0xff0000) >> 8) | ((x & 0xff00) << 8) | ((x & 0xff) << 24))

#define ADDR                        "0x%016llx"
#define MACH_MAGIC                  MH_MAGIC_64
#define MACH_SEGMENT                LC_SEGMENT_64
typedef struct fat_header           fat_hdr_t;
typedef struct fat_arch             fat_arch_t;
typedef struct mach_header_64       mach_hdr_t;
typedef struct load_command         mach_lc_t;
typedef struct segment_command_64   mach_seg_t;
typedef struct section_64           mach_sec_t;
typedef struct symtab_command       mach_stab_t;
typedef struct dysymtab_command     mach_dstab_t;
typedef struct nlist_64             mach_nlist_t;
typedef struct relocation_info      mach_reloc_t;
typedef uint64_t                    kptr_t;

#define FOREACH_CMD(_hdr, _cmd) \
for( \
    mach_lc_t *_cmd = (mach_lc_t*)(_hdr + 1), *_end = (mach_lc_t*)((uintptr_t)_cmd + _hdr->sizeofcmds - sizeof(mach_lc_t)); \
    _cmd <= _end; \
    _cmd = (mach_lc_t*)((uintptr_t)_cmd + _cmd->cmdsize) \
)

#define STEP_MEM(_type, _mem, _addr, _size, _min) \
for(_type *_mem = (_type*)(_addr), *_end = (_type*)((uintptr_t)(_mem) + (_size)) - (_min); _mem <= _end; ++_mem)

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
    kptr_t addr;
    const char *name;
} sym_t;

typedef struct
{
    const char *class;
    const char *method;
} vtab_entry_name_t;

typedef struct
{
    kptr_t addr;
    vtab_entry_name_t name;
    uint16_t pac;
    uint16_t structor : 1,
             reserved : 15;
} vtab_entry_t;

typedef struct vtab_override
{
    struct vtab_override *next;
    vtab_entry_name_t name;
    kptr_t old;
    kptr_t new;
    uint32_t idx;
    uint16_t pac;
} vtab_override_t;

typedef struct metaclass
{
    kptr_t addr;
    kptr_t parent;
    kptr_t vtab;
    kptr_t callsite;
    struct metaclass *parentP;
    const char *name;
    const char *bundle;
    struct {
        vtab_override_t *head;
        vtab_override_t **nextP;
    } overrides;
    uint32_t objsize;
    uint32_t overrides_done : 1,
             overrides_err  : 1,
             reserved       : 30;
} metaclass_t;

typedef union
{
    kptr_t ptr;
    struct {
        int64_t lo : 48,
                hi : 16;
    };
    struct {
        kptr_t off : 32,
               pac : 16,
               nxt : 15,
               one :  1;
    };
} pacptr_t;

static kptr_t kuntag(kptr_t kbase, bool x1469, kptr_t ptr, uint16_t *pac)
{
    pacptr_t pp;
    pp.ptr = ptr;
    if(x1469)
    {
        if(pp.one)
        {
            if(pac) *pac = pp.pac;
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

static bool is_linear_inst(void *ptr)
{
    return is_adr(ptr) ||
           is_adrp(ptr) ||
           is_add_imm(ptr) ||
           is_sub_imm(ptr) ||
           is_ldr_imm_uoff(ptr) ||
           is_ldr_lit(ptr) ||
           is_bl(ptr) ||
           is_mov(ptr) ||
           is_movz(ptr) ||
           is_movk(ptr) ||
           is_movn(ptr) ||
           is_orr(ptr) ||
           is_str_uoff(ptr) ||
           is_stp_uoff(ptr) ||
           //is_stp_fp_uoff(ptr) ||
           is_nop(ptr);
}

typedef struct
{
    kptr_t x[32];
    uint32_t valid;
    uint32_t wide;
} a64_state_t;

// Best-effort emulation: halt on unknown instructions, keep track of which registers
// hold known values and only operate on those. Ignore non-static memory.
static bool a64_emulate(void *kernel, a64_state_t *state, uint32_t *from, uint32_t *to, bool init)
{
    if(init)
    {
        for(size_t i = 0; i < 32; ++i)
        {
            state->x[i] = 0;
        }
        state->valid = 0;
        state->wide = 0;
    }
    for(; from < to; ++from)
    {
        void *ptr = from;
        kptr_t addr = off2addr(kernel, (uintptr_t)from - (uintptr_t)kernel);
        if(is_nop(ptr) || is_str_uoff(ptr) || is_stp_uoff(ptr) /*|| is_stp_fp_uoff(ptr)*/)
        {
            // Ignore/no change
        }
        else if(is_stp_pre(ptr))
        {
            stp_t *stp = (stp_t*)ptr;
            if(state->valid & (1 << stp->Rn)) // Only if valid
            {
                state->x[stp->Rn] += get_stp_pre_off(stp);
            }
        }
        else if(is_adr(ptr) || is_adrp(ptr))
        {
            adr_t *adr = (adr_t*)ptr;
            state->x[adr->Rd] = (adr->op1 ? (addr & ~0xfff) : addr) + get_adr_off(adr);
            state->valid |= 1 << adr->Rd;
            state->wide  |= 1 << adr->Rd;
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
                state->x[add->Rd] = state->x[add->Rn] + (is_add_imm(add) ? 1 : -1) * get_add_sub_imm(add);
                state->valid |= 1 << add->Rd;
                state->wide = (state->wide & ~(1 << add->Rd)) | (add->sf << add->Rd);
            }
        }
        else if(is_ldr_imm_uoff(ptr))
        {
            ldr_imm_uoff_t *ldr = (ldr_imm_uoff_t*)ptr;
            if(!(state->valid & (1 << ldr->Rn))) // Unset validity
            {
                state->valid &= ~(1 << ldr->Rt);
            }
            else
            {
                void *ldr_addr = addr2ptr(kernel, state->x[ldr->Rn] + get_ldr_imm_uoff(ldr));
                if(!ldr_addr)
                {
                    return false;
                }
                state->x[ldr->Rt] = *(kptr_t*)ldr_addr;
                state->valid |= 1 << ldr->Rt;
                state->wide = (state->wide & ~(1 << ldr->Rt)) | (ldr->sf << ldr->Rt);
            }
        }
        else if(is_ldr_lit(ptr))
        {
            ldr_lit_t *ldr = (ldr_lit_t*)ptr;
            void *ldr_addr = addr2ptr(kernel, addr + get_ldr_lit_off(ldr));
            if(!ldr_addr)
            {
                return false;
            }
            state->x[ldr->Rt] = *(kptr_t*)ldr_addr;
            state->valid |= 1 << ldr->Rt;
            state->wide = (state->wide & ~(1 << ldr->Rt)) | (ldr->sf << ldr->Rt);
        }
        else if(is_bl(ptr))
        {
            state->valid &= ~0x3FFFF;
            // TODO: x30?
        }
        else if(is_mov(ptr))
        {
            mov_t *mov = (mov_t*)ptr;
            if(!(state->valid & (1 << mov->Rm))) // Unset validity
            {
                state->valid &= ~(1 << mov->Rd);
            }
            else
            {
                state->x[mov->Rd] = state->x[mov->Rm];
                state->valid |= 1 << mov->Rd;
                state->wide = (state->wide & ~(1 << mov->Rd)) | (mov->sf << mov->Rd);
            }
        }
        else if(is_movz(ptr))
        {
            movz_t *movz = (movz_t*)ptr;
            state->x[movz->Rd] = get_movzk_imm(movz);
            state->valid |= 1 << movz->Rd;
            state->wide = (state->wide & ~(1 << movz->Rd)) | (movz->sf << movz->Rd);
        }
        else if(is_movk(ptr))
        {
            movk_t *movk = (movk_t*)ptr;
            if(state->valid & (1 << movk->Rd)) // Only if valid
            {
                state->x[movk->Rd] = (state->x[movk->Rd] & ~(0xffff << (movk->hw << 4))) | get_movzk_imm(movk);
                state->valid |= 1 << movk->Rd;
                state->wide = (state->wide & ~(1 << movk->Rd)) | (movk->sf << movk->Rd);
            }
        }
        else if(is_movn(ptr))
        {
            movn_t *movn = (movn_t*)ptr;
            state->x[movn->Rd] = get_movn_imm(movn);
            state->valid |= 1 << movn->Rd;
            state->wide = (state->wide & ~(1 << movn->Rd)) | (movn->sf << movn->Rd);
        }
        else if(is_orr(ptr))
        {
            orr_t *orr = (orr_t*)ptr;
            if(orr->Rn == 31 || (state->valid & (1 << orr->Rn)))
            {
                state->x[orr->Rd] = (orr->Rd == 31 ? 0 : state->x[orr->Rd]) | get_orr_imm(orr);
                state->valid |= 1 << orr->Rd;
                state->wide = (state->wide & ~(1 << orr->Rd)) | (orr->sf << orr->Rd);
            }
            else
            {
                state->valid &= ~(1 << orr->Rd);
            }
        }
        else
        {
            WRN("Unexpected instruction at " ADDR, addr);
            return false;
        }
    }
    return true;
}

int compare_names(const void *a, const void *b)
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

int compare_bundles(const void *a, const void *b)
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

static void printMetaClass(metaclass_t *meta, bool opt_bundle, bool opt_meta, bool opt_size, bool opt_vtab, bool opt_overrides)
{
    if(opt_vtab)
    {
        if(meta->vtab == -1)
        {
            printf("vtab=?????????????????? ");
        }
        else
        {
            printf("vtab=" ADDR " ", meta->vtab);
        }
    }
    if(opt_size)
    {
        printf("size=0x%08x ", meta->objsize);
    }
    if(opt_meta)
    {
        printf("meta=" ADDR " parent=" ADDR " ", meta->addr, meta->parent);
    }
    printf("%s", meta->name);
    if(opt_bundle)
    {
        printf(" (%s)", meta->bundle ? meta->bundle : "???");
    }
    printf("\n");
    if(opt_overrides)
    {
        for(vtab_override_t *ovr = meta->overrides.head; ovr != NULL; ovr = ovr->next)
        {
            printf("    %#6lx func=" ADDR " overrides=" ADDR " pac=0x%04hx %s::%s\n", ovr->idx * sizeof(kptr_t), ovr->new, ovr->old, ovr->pac, ovr->name.class, ovr->name.method); // TODO: %#6lx will break if we ever show index 0
        }
    }
}

static void print_help(const char *self)
{
    fprintf(stderr, "Usage:\n"
                    "    %s [-abBCdeGmoOpsSv] [ClassName] [OverrideName] [BundleName] kernel\n"
                    "\n"
                    "Options:\n"
                    "    -a  Synonym for -bmsv\n"
                    "    -b  Print bundle identifier\n"
                    "    -B  Filter by bundle identifier\n"
                    "    -C  Filter by class name\n"
                    "    -d  Debug output\n"
                    "    -e  Filter extending ClassName (implies -C)\n"
                    "    -G  Sort (group) by bundle identifier\n"
                    "    -m  Print MetaClass addresses\n"
                    "    -o  Print overridden/new virtual methods\n"
                    "    -O  Filter by name of overridden method\n"
                    "    -p  Filter parents of ClassName (implies -C)\n"
                    "    -s  Print object sizes\n"
                    "    -S  Sort by class name\n"
                    "    -v  Print object vtabs\n"
                    , self);
}

int main(int argc, const char **argv)
{
    bool opt_bundle    = false,
         opt_bfilt     = false,
         opt_cfilt     = false,
         opt_bsort     = false,
         opt_csort     = false,
         opt_extend    = false,
         opt_meta      = false,
         opt_overrides = false,
         opt_ofilt     = false,
         opt_parent    = false,
         opt_size      = false,
         opt_vtab      = false;
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
                    opt_bundle = true;
                    opt_meta   = true;
                    opt_size   = true;
                    opt_vtab   = true;
                    break;
                }
                case 'b':
                {
                    opt_bundle = true;
                    break;
                }
                case 'B':
                {
                    opt_bfilt = true;
                    break;
                }
                case 'C':
                {
                    opt_cfilt = true;
                    break;
                }
                case 'e':
                {
                    opt_extend = true;
                    opt_cfilt  = true;
                    break;
                }
                case 'G':
                {
                    opt_bsort = true;
                    break;
                }
                case 'm':
                {
                    opt_meta = true;
                    break;
                }
                case 'o':
                {
                    opt_overrides = true;
                    break;
                }
                case 'O':
                {
                    opt_ofilt = true;
                    break;
                }
                case 'p':
                {
                    opt_parent = true;
                    opt_cfilt  = true;
                    break;
                }
                case 's':
                {
                    opt_size = true;
                    break;
                }
                case 'S':
                {
                    opt_csort = true;
                    break;
                }
                case 'v':
                {
                    opt_vtab = true;
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

    int wantargs = 1 + (opt_bfilt ? 1 : 0) + (opt_cfilt ? 1 : 0) + (opt_ofilt ? 1 : 0);
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

    if(opt_extend && opt_parent)
    {
        ERR("Only one of -e and -p may be given.");
        return -1;
    }

    if(opt_bsort && opt_csort)
    {
        ERR("Only one of -G and -S may be given.");
        return -1;
    }

    if(opt_cfilt)
    {
        filt_class = argv[aoff++];
    }
    if(opt_bfilt)
    {
        filt_bundle = argv[aoff++];
    }
    if(opt_ofilt)
    {
        filt_override = argv[aoff++];
    }

    int fd = open(argv[aoff], O_RDONLY);
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

    size_t kernelsize = s.st_size;
    if(kernelsize < sizeof(mach_hdr_t))
    {
        ERR("File is too short to be a Mach-O.");
        return -1;
    }

    void *kernel = mmap(NULL, kernelsize, PROT_READ, MAP_PRIVATE, fd, 0);
    if(kernel == MAP_FAILED)
    {
        ERRNO("mmap");
        return -1;
    }

    fat_hdr_t *fat = kernel;
    if(fat->magic == FAT_CIGAM)
    {
        bool found = false;
        fat_arch_t *arch = (fat_arch_t*)(fat + 1);
        for(size_t i = 0; i < SWAP32(fat->nfat_arch); ++i)
        {
            if(SWAP32(arch[i].cputype) == CPU_TYPE_ARM64)
            {
                kernel = (void*)((uintptr_t)kernel + SWAP32(arch[i].offset));
                kernelsize = SWAP32(arch[i].size);
                found = true;
                break;
            }
        }
        if(!found)
        {
            ERR("No arm64 slice in fat binary.");
            return -1;
        }
    }

    mach_hdr_t *hdr = (mach_hdr_t*)kernel;
    if(hdr->magic != MACH_MAGIC)
    {
        ERR("Wrong magic: 0x%08x", hdr->magic);
        return -1;
    }
    if(hdr->cputype != CPU_TYPE_ARM64)
    {
        ERR("Wrong architecture, only arm64 is supported.");
        return -1;
    }

    if(hdr->filetype != MH_EXECUTE && hdr->filetype != MH_KEXT_BUNDLE)
    {
        ERR("Wrong file type: 0x%x", hdr->filetype);
        return -1;
    }

    ARRDECL(kptr_t, aliases, 0x100);
    ARRDECL(kptr_t, refs, 0x100);

    kptr_t OSMetaClassConstructor = 0,
           OSMetaClassVtab = 0,
           OSObjectVtab = 0,
           OSObjectGetMetaClass = 0,
           kbase = 0,
           initcode = 0;
    bool x1469 = false;
    mach_stab_t *stab = NULL;
    mach_nlist_t *symtab = NULL;
    char *strtab = NULL;
    FOREACH_CMD(hdr, cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            if(seg->fileoff == 0 && seg->filesize > 0)
            {
                kbase = seg->vmaddr;
            }
            if(strcmp("__TEXT_EXEC", seg->segname) == 0)
            {
                mach_sec_t *secs = (mach_sec_t*)(seg + 1);
                for(size_t i = 0; i < seg->nsects; ++i)
                {
                    if(strcmp("initcode", secs[i].sectname) == 0)
                    {
                        initcode = secs[i].addr;
                        x1469 = true;
                        break;
                    }
                }
            }
        }
        else if(cmd->cmd == LC_SYMTAB)
        {
            stab = (mach_stab_t*)cmd;
            symtab = (mach_nlist_t*)((uintptr_t)kernel + stab->symoff);
            strtab = (char*)((uintptr_t)kernel + stab->stroff);
            for(size_t i = 0; i < stab->nsyms; ++i)
            {
                if((symtab[i].n_type & N_TYPE) == N_UNDF)
                {
                    continue;
                }
                char *s = &strtab[symtab[i].n_un.n_strx];
                if(hdr->filetype == MH_KEXT_BUNDLE)
                {
                    if(strcmp(s, "__ZN11OSMetaClassC2EPKcPKS_j.stub") == 0)
                    {
                        OSMetaClassConstructor = symtab[i].n_value;
                        DBG("OSMetaClass::OSMetaClass: " ADDR, OSMetaClassConstructor);
                    }
                }
                else
                {
                    if(strcmp(s, "__ZN11OSMetaClassC2EPKcPKS_j") == 0)
                    {
                        OSMetaClassConstructor = symtab[i].n_value;
                        DBG("OSMetaClass::OSMetaClass: " ADDR, OSMetaClassConstructor);
                    }
                    else if(strcmp(s, "__ZTV11OSMetaClass") == 0)
                    {
                        OSMetaClassVtab = symtab[i].n_value + 2 * sizeof(kptr_t);
                        DBG("OSMetaClassVtab: " ADDR, OSMetaClassVtab);
                    }
                    else if(strcmp(s, "__ZTV8OSObject") == 0)
                    {
                        OSObjectVtab = symtab[i].n_value + 2 * sizeof(kptr_t);
                        DBG("OSObjectVtab: " ADDR, OSObjectVtab);
                    }
                    else if(strcmp(s, "__ZNK8OSObject12getMetaClassEv") == 0)
                    {
                        OSObjectGetMetaClass = symtab[i].n_value;
                        DBG("OSObjectGetMetaClass: " ADDR, OSObjectGetMetaClass);
                    }
                }
            }
        }
    }
    if(!OSMetaClassConstructor)
    {
        if(hdr->filetype == MH_KEXT_BUNDLE)
        {
            ERR("Failed to find OSMetaClass::OSMetaClass.");
            return -1;
        }
        DBG("Failed to find OSMetaClass::OSMetaClass symbol, falling back to binary matching.");

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
            STEP_MEM(uint32_t, mem, kernel, kernelsize, 2)
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
                    STEP_MEM(uint32_t, m, mem + 2, kernelsize - ((uintptr_t)(mem + 2) - (uintptr_t)kernel), 1)
                    {
                        kptr_t bladdr = off2addr(kernel, (uintptr_t)m - (uintptr_t)kernel),
                               blref  = bladdr;
                        bl_t *bl = (bl_t*)m;
                        if(is_bl(bl))
                        {
                            a64_state_t state;
                            if(!a64_emulate(kernel, &state, mem, m, true))
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
        if(constrCandCurr.idx == 0)
        {
            ERR("Failed to find OSMetaClass::OSMetaClass.");
            return -1;
        }
        else if(constrCandCurr.idx > 1)
        {
            ERR("Found more than one possible OSMetaClass::OSMetaClass.");
            return -1;
        }
        OSMetaClassConstructor = constrCandCurr.val[0];
        DBG("OSMetaClass::OSMetaClass: " ADDR, OSMetaClassConstructor);
        free(constrCand[0].val);
        free(constrCand[1].val);
        for(size_t i = 0; i < NSTRREF; ++i)
        {
            free(strrefs[i].val);
        }
#undef constrCandPrev
#undef constrCandCurr
#undef NSTRREF
    }
    ARRPUSH(aliases, OSMetaClassConstructor);

    if(hdr->filetype != MH_KEXT_BUNDLE)
    {
        for(kptr_t *mem = kernel, *end = (kptr_t*)((uintptr_t)kernel + kernelsize); mem < end; ++mem)
        {
            if(kuntag(kbase, x1469, *mem, NULL) == OSMetaClassConstructor)
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
                                ARRPUSH(aliases, alias);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    ARRDECL(metaclass_t, metas, 0x1000);

    FOREACH_CMD(hdr, cmd)
    {
        if(cmd->cmd == MACH_SEGMENT)
        {
            mach_seg_t *seg = (mach_seg_t*)cmd;
            STEP_MEM(uint32_t, mem, (uintptr_t)kernel + seg->fileoff, seg->filesize, 1)
            {
                bl_t *bl = (bl_t*)mem;
                if(is_bl(bl))
                {
                    kptr_t bladdr = seg->vmaddr + ((uintptr_t)bl - ((uintptr_t)kernel + seg->fileoff));
                    kptr_t bltarg = bladdr + get_bl_off(bl);
                    for(size_t i = 0; i < aliases.idx; ++i)
                    {
                        if(bltarg == aliases.val[i])
                        {
                            uint32_t *fnstart = mem - 1;
                            bool unknown = false;
                            while(1)
                            {
                                if(fnstart < (uint32_t*)((uintptr_t)kernel + seg->fileoff))
                                {
                                    WRN("Hit start of segment at " ADDR " for " ADDR, seg->vmaddr + ((uintptr_t)fnstart - ((uintptr_t)kernel + seg->fileoff)), bladdr);
                                    goto next;
                                }
                                stp_t *stp = (stp_t*)fnstart;
                                if((is_stp_pre(stp) || is_stp_uoff(stp)) && stp->Rt == 29 && stp->Rt2 == 30)
                                {
                                    break;
                                }
                                if(!is_linear_inst(fnstart))
                                {
                                    unknown = true;
                                    ++fnstart;
                                    break;
                                }
                                --fnstart;
                            }
                            a64_state_t state;
                            if(a64_emulate(kernel, &state, fnstart, mem, true))
                            {
                                if((state.valid & 0x1) != 0x1)
                                {
                                    if(unknown)
                                    {
                                        WRN("Hit unknown instruction at " ADDR " for " ADDR, seg->vmaddr + ((uintptr_t)(fnstart - 1) - ((uintptr_t)kernel + seg->fileoff)), bladdr);
                                    }
                                    else
                                    {
                                        DBG("Skipping constructor call without x0 at " ADDR, bladdr);
                                    }
                                    goto next;
                                }
                                if((state.valid & 0xe) != 0xe)
                                {
                                    if(unknown)
                                    {
                                        WRN("Hit unknown instruction at " ADDR " for " ADDR, seg->vmaddr + ((uintptr_t)(fnstart - 1) - ((uintptr_t)kernel + seg->fileoff)), bladdr);
                                    }
                                    WRN("Skipping constructor call without x1-x3 (%x) at " ADDR, state.valid, bladdr);
                                    goto next;
                                }
                                if((state.wide & 0xf) != 0x7)
                                {
                                    WRN("Skipping constructor call with unexpected registers width (%x) at " ADDR, state.wide, bladdr);
                                    goto next;
                                }
                                DBG("Processing constructor call at " ADDR, bladdr);
                                metaclass_t *meta;
                                ARRNEXT(metas, meta);
                                meta->addr = state.x[0];
                                meta->parent = state.x[2];
                                meta->vtab = 0;
                                meta->callsite = off2addr(kernel, (uintptr_t)mem - (uintptr_t)kernel);
                                meta->parentP = NULL;
                                meta->name = addr2ptr(kernel, state.x[1]);
                                meta->bundle = NULL;
                                meta->overrides.head = NULL;
                                meta->overrides.nextP = &meta->overrides.head;
                                meta->objsize = state.x[3];
                                meta->overrides_done = 0;
                                meta->overrides_err = 0;
                                meta->reserved = 0;
                                if(!meta->name)
                                {
                                    DBG("meta->name: " ADDR " (untagged: " ADDR ")", state.x[1], kuntag(kbase, x1469, state.x[1], NULL));
                                    ERR("Name of MetaClass lies outside all segments at " ADDR, bladdr);
                                    return -1;
                                }
                            }
                            next:;
                            break;
                        }
                    }
                }
            }
        }
    }

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

    if(opt_vtab || opt_overrides || opt_ofilt)
    {
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
            for(size_t i = 0; i < stab->nsyms; ++i)
            {
                if((symtab[i].n_type & N_TYPE) == N_UNDF)
                {
                    continue;
                }
                char *s = &strtab[symtab[i].n_un.n_strx];
                size_t slen = strlen(s);
                if(slen >= 21 && strncmp(s, "__ZNK", 5) == 0 && strcmp(s + slen - 16, "12getMetaClassEv") == 0) // TODO: kinda ugly
                {
                    for(size_t j = 0; j < stab->nsyms; ++j)
                    {
                        if((symtab[j].n_type & N_TYPE) == N_UNDF)
                        {
                            continue;
                        }
                        char *t = &strtab[symtab[j].n_un.n_strx];
                        if(strncmp(t, "__ZTV", 5) == 0 && strncmp(t + 5, s + 5, slen - 21) == 0)
                        {
                            OSObjectVtab = symtab[j].n_value + 2 * sizeof(kptr_t);
                            OSObjectGetMetaClass = symtab[i].n_value;
                            DBG("%s: " ADDR, t, OSObjectVtab);
                            DBG("%s: " ADDR, s, OSObjectGetMetaClass);
                            goto after;
                        }
                    }
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
                                    }
                                    state.valid = 1;
                                    state.wide = 1;
                                    if(a64_emulate(kernel, &state, start, mem, false))
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
                STEP_MEM(uint32_t, mem, kernel, kernelsize, 3)
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
                if(OSObjectGetMetaClass == -1)
                {
                    OSObjectGetMetaClass = 0;
                }
            }
        }
        size_t VtabGetMetaClassOff = 0;
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
            if(kuntag(kbase, x1469, ovtab[i], NULL) == OSObjectGetMetaClass)
            {
                VtabGetMetaClassOff = i;
                DBG("VtabGetMetaClassOff: 0x%lx", VtabGetMetaClassOff);
                break;
            }
        }
        if(!VtabGetMetaClassOff)
        {
            ERR("Failed to find OSObjectGetMetaClass in OSObjectVtab.");
            return -1;
        }

        ARRDECL(kptr_t, candidates, 0x100);
        FOREACH_CMD(hdr, cmd)
        {
            if(cmd->cmd == MACH_SEGMENT)
            {
                mach_seg_t *seg = (mach_seg_t*)cmd;
                STEP_MEM(uint32_t, mem, (uintptr_t)kernel + seg->fileoff, seg->filesize, 3)
                {
                    adr_t *adr = (adr_t*)mem;
                    add_imm_t *add = (add_imm_t*)(mem + 1);
                    nop_t *nop = (nop_t*)(mem + 1);
                    ret_t *ret1 = (ret_t*)(mem + 1);
                    ret_t *ret2 = (ret_t*)(mem + 2);
                    bool iz_adrp = is_adrp(adr),
                         iz_add  = is_add_imm(add);
                    if
                    (
                        (iz_adrp && iz_add && is_ret(ret2) && adr->Rd == add->Rn && add->Rd == 0) ||
                        (is_adr(adr) && (is_ret(ret1) || (is_nop(nop) && is_ret(ret2))) && adr->Rd == 0)
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
                                    STEP_MEM(kptr_t, mem2, (kptr_t*)kernel + VtabGetMetaClassOff + 2, kernelsize - (VtabGetMetaClassOff + 2) * sizeof(kptr_t), 1)
                                    {
                                        if(kuntag(kbase, x1469, *mem2, NULL) == func && *(mem2 - VtabGetMetaClassOff - 1) == 0 && *(mem2 - VtabGetMetaClassOff - 2) == 0)
                                        {
                                            kptr_t ref = off2addr(kernel, (uintptr_t)(mem2 - VtabGetMetaClassOff) - (uintptr_t)kernel);
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
                                    if(candidates.idx > 0)
                                    {
                                        kptr_t cnd = 0;
                                        size_t numcnd = 0;
                                        STEP_MEM(uint32_t, mem2, kernel, kernelsize, 5)
                                        {
                                            adr_t *adrp = (adr_t*)mem2;
                                            add_imm_t *add1 = (add_imm_t*)(mem2 + 1);
                                            add_imm_t *add2 = (add_imm_t*)(mem2 + 2);
                                            str_uoff_t *str = (str_uoff_t*)(mem2 + 3);
                                            uint32_t *ldp = mem2 + 4;
                                            ret_t *ret1 = (ret_t*)(mem2 + 4);
                                            ret_t *ret2 = (ret_t*)(mem2 + 5);
                                            if
                                            (
                                                is_adrp(adrp) && is_add_imm(add1) && is_add_imm(add2) && is_str_uoff(str) && // TODO: adr + nop + add ?
                                                (is_ret(ret1) || (*ldp == 0xa8c17bfd /* ldp x29, x30, [sp], 0x10 */ && is_ret(ret2))) &&
                                                adrp->Rd == add1->Rn && add1->Rd == add2->Rn && add2->Rd == str->Rt &&
                                                get_str_uoff(str) == 0 && get_add_sub_imm(add2) == 2 * sizeof(kptr_t)
                                            )
                                            {
                                                kptr_t refloc = off2addr(kernel, (uintptr_t)adrp - (uintptr_t)kernel);
                                                kptr_t ref = refloc & ~0xfff;
                                                ref += get_adr_off(adrp);
                                                ref += get_add_sub_imm(add1) + get_add_sub_imm(add2);
                                                for(size_t j = 0; j < candidates.idx; ++j)
                                                {
                                                    if(candidates.val[j] == ref)
                                                    {
                                                        DBG("Location referencing vtab candidate " ADDR ": " ADDR, ref, refloc);
                                                        if(cnd != ref) // One vtab may be referenced multiple times
                                                        {
                                                            ++numcnd;
                                                        }
                                                        cnd = ref;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        if(numcnd == 1)
                                        {
                                            meta->vtab = cnd;
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
        free(candidates.val);

        for(size_t i = 0; i < metas.idx; ++i)
        {
            if(metas.val[i].vtab == -1)
            {
                WRN("Multiple vtab candidates for %s", metas.val[i].name);
            }
        }

        if(opt_overrides || opt_ofilt)
        {
            char **relocs = NULL;
            size_t reloc_min = ~0, reloc_max = 0;
            if(hdr->filetype == MH_KEXT_BUNDLE)
            {
                FOREACH_CMD(hdr, cmd)
                {
                    if(cmd->cmd == LC_DYSYMTAB)
                    {
                        mach_dstab_t *dstab = (mach_dstab_t*)cmd;
                        mach_reloc_t *reloc = (mach_reloc_t*)((uintptr_t)kernel + dstab->extreloff);
                        for(size_t i = 0; i < dstab->nextrel; ++i)
                        {
                            if(!reloc[i].r_extern)
                            {
                                ERR("External relocation entry %lu at 0x%x does not have external bit set.", i, reloc[i].r_address);
                                return -1;
                            }
                            DBG("Reloc %x: %s", reloc[i].r_address, &strtab[symtab[reloc[i].r_symbolnum].n_un.n_strx]);
                            if(reloc[i].r_address < reloc_min)
                            {
                                reloc_min = reloc[i].r_address;
                            }
                            if(reloc[i].r_address > reloc_max)
                            {
                                reloc_max = reloc[i].r_address;
                            }
                        }
                        if(reloc_min < reloc_max)
                        {
                            reloc_max += sizeof(kptr_t);
                            size_t relocsize = sizeof(char*) * (reloc_max - reloc_min) / sizeof(kptr_t);
                            relocs = malloc(relocsize);
                            if(!relocs)
                            {
                                ERRNO("malloc(relocs)");
                                return -1;
                            }
                            memset(relocs, 0, relocsize);
                            for(size_t i = 0; i < dstab->nextrel; ++i)
                            {
                                relocs[(reloc[i].r_address - reloc_min) / sizeof(kptr_t)] = &strtab[symtab[reloc[i].r_symbolnum].n_un.n_strx];
                            }
                        }
                        break;
                    }
                }
            }
            ARRDECL(vtab_entry_t, fncache, 0x200);
            for(size_t i = 0; i < metas.idx; ++i)
            {
                again:;
                bool do_again = false;
                metaclass_t *meta = &metas.val[i],
                            *parent = meta->parentP;
                if(meta->overrides_done || meta->overrides_err)
                {
                    goto done;
                }
                if(parent)
                {
                    while(!parent->overrides_err && !parent->overrides_done)
                    {
                        do_again = true;
                        meta = parent;
                        parent = meta->parentP;
                        if(!parent)
                        {
                            break;
                        }
                    }
                    if(parent && parent->overrides_err)
                    {
                        WRN("Skipping class %s because parent class was skipped.", meta->name);
                        meta->overrides_err = 1;
                        goto done;
                    }
                    while(parent && parent->vtab == 0) // Fall through on abstract classes
                    {
                        parent = parent->parentP;
                    }
                }
                if(meta->vtab == 0)
                {
                    meta->overrides_done = 1;
                    goto done;
                }
                if(meta->vtab == -1)
                {
                    WRN("Skipping class %s because vtable is missing.", meta->name);
                    meta->overrides_err = 1;
                    goto done;
                }
                // Parent is guaranteed to either be NULL or have a valid vtab here
                kptr_t *mvtab = addr2ptr(kernel, meta->vtab);
                if(!mvtab)
                {
                    WRN("%s vtab lies outside all segments.", meta->name);
                    meta->overrides_err = 1;
                    goto done;
                }
                kptr_t *pvtab = NULL;
                if(parent)
                {
                    pvtab = addr2ptr(kernel, parent->vtab);
                    if(!pvtab)
                    {
                        WRN("%s vtab lies outside all segments.", parent->name);
                        meta->overrides_err = 1;
                        goto done;
                    }
                }
#define KOFF(x) ((uintptr_t)&(x) - (uintptr_t)kernel)
                bool is_in_reloc = false;
                for(size_t idx = 1; // Skip delete function or smth
                    (is_in_reloc = (KOFF(mvtab[idx]) >= reloc_min && KOFF(mvtab[idx]) < reloc_max && relocs[(KOFF(mvtab[idx]) - reloc_min) / sizeof(kptr_t)] != NULL)) || mvtab[idx] != 0;
                    ++idx)
                {
                    if(!is_in_reloc && (!pvtab || kuntag(kbase, x1469, mvtab[idx], NULL) != kuntag(kbase, x1469, pvtab[idx], NULL)))
                    {
                        if(pvtab && pvtab[idx] == 0)
                        {
                            // Signal that we've reached end of the parent vtable
                            pvtab = NULL;
                        }
                        uint16_t pac;
                        kptr_t func = kuntag(kbase, x1469, mvtab[idx], &pac);
                        vtab_entry_t *entry = NULL;
                        // stab, symtab and strtab are guaranteed to be non-NULL here or we would've exited long ago
                        char *cxx_sym = NULL;
#if 0
                        if(is_in_reloc)
                        {
                            cxx_sym = relocs[(KOFF(mvtab[idx]) - reloc_min) / sizeof(kptr_t)];
                        }
                        else
#endif
                        {
                            for(size_t n = 0; n < stab->nsyms; ++n)
                            {
                                if((symtab[n].n_type & N_STAB) && !(symtab[n].n_type & N_EXT))
                                {
                                    continue;
                                }
                                if(symtab[n].n_value == func)
                                {
                                    cxx_sym = &strtab[symtab[n].n_un.n_strx];
                                    break;
                                }
                            }
                        }
                        if(cxx_sym)
                        {
                            DBG("Got symbol for virtual function " ADDR ": %s", func, cxx_sym);
                            if(strcmp(cxx_sym, "___cxa_pure_virtual") == 0)
                            {
                                func = 0;
                            }
                            else
                            {
                                char *class = NULL,
                                     *method = NULL;
                                bool structor = false;
                                if(!cxx_demangle(cxx_sym, &class, &method, &structor))
                                {
#if 0
                                    if(is_in_reloc)
                                    {
                                        WRN("Failed to demangle symbol: %s (from reloc)", cxx_sym);
                                    }
                                    else
#endif
                                    {
                                        WRN("Failed to demangle symbol: %s (from symtab, addr " ADDR ")", cxx_sym, func);
                                    }
                                }
                                else
                                {
                                    const char *cls = NULL;
#if 0
                                    if(is_in_reloc)
                                    {
                                        free(class);
                                        cls = meta->name;
                                    }
                                    else
#endif
                                    {
#if 0
                                        if(strcmp(class, meta->name) != 0 && (strcmp(class, "OSMetaClassBase")) != 0)
                                        {
                                            WRN("Symbol name doesn't match class name in %s: %s::%s vs %s", cxx_sym, class, method, meta->name);
                                        }
#endif
                                        cls = class;
                                    }
                                    ARRNEXT(fncache, entry);
                                    entry->addr = func;
                                    entry->name.class = cls;
                                    entry->name.method = method;
                                    entry->pac = pac;
                                    entry->structor = !!structor;
                                }
                            }
                        }
                        else
                        {
                            DBG("Found no symbol for virtual function " ADDR, func);
                        }
                        if(!entry && pvtab)
                        {
                            kptr_t pfunc = kuntag(kbase, x1469, pvtab[idx], NULL);
                            for(size_t n = 0; n < fncache.idx; ++n)
                            {
                                if(fncache.val[n].addr == pfunc)
                                {
                                    const char *method = fncache.val[n].name.method;
                                    if(fncache.val[n].structor)
                                    {
                                        const char *class = fncache.val[n].name.class;
                                        bool dest = method[0] == '~';
                                        if(dest)
                                        {
                                            ++method;
                                        }
                                        size_t clslen = strlen(class);
                                        if(strncmp(method, class, clslen) != 0)
                                        {
                                            WRN("Bad %sstructor: %s::%s", dest ? "de" : "con", class, method);
                                            continue;
                                        }
                                        method += clslen;
                                        char *m = NULL;
                                        asprintf(&m, "%s%s%s", dest ? "~" : "", meta->name, method);
                                        if(!m)
                                        {
                                            ERRNO("asprintf(structor)");
                                            return -1;
                                        }
                                        method = m;
                                    }
                                    ARRNEXT(fncache, entry);
                                    entry->addr = func;
                                    entry->name.class = meta->name;
                                    entry->name.method = method;
                                    entry->pac = pac;
                                    entry->structor = fncache.val[n].structor;
                                    break;
                                }
                            }
                        }
                        if(!entry)
                        {
                            char *method = NULL;
                            asprintf(&method, "fn_0x%lx()", idx * sizeof(kptr_t));
                            if(!method)
                            {
                                ERRNO("asprintf(method)");
                                return -1;
                            }
                            ARRNEXT(fncache, entry);
                            entry->addr = func;
                            entry->name.class = meta->name;
                            entry->name.method = method;
                            entry->pac = pac;
                            entry->structor = 0;
                        }
                        vtab_override_t *ovrd = malloc(sizeof(vtab_override_t));
                        if(!ovrd)
                        {
                            ERRNO("malloc(ovrd)");
                            return -1;
                        }
                        ovrd->next = NULL;
                        ovrd->name.class = entry->name.class;
                        ovrd->name.method = entry->name.method;
                        ovrd->old = pvtab ? kuntag(kbase, x1469, pvtab[idx], NULL) : 0;
                        ovrd->new = entry->addr;
                        ovrd->idx = idx;
                        ovrd->pac = entry->pac;
                        *(meta->overrides.nextP) = ovrd;
                        meta->overrides.nextP = &ovrd->next;
                    }
                }
                meta->overrides_done = 1;
                done:;
                if(do_again)
                {
                    goto again;
                }
            }
            free(fncache.val);
            if(relocs)
            {
                free(relocs);
            }
        }
    }

    const char *filter = NULL;
    const char *__kernel__ = "__kernel__"; // Single ref for pointer comparisons

    if(opt_bundle || opt_bfilt)
    {
        bool haveBundles = false;
        const char **bundleList = NULL;
        size_t bundleIdx = 0;
        if(hdr->filetype == MH_KEXT_BUNDLE)
        {
            kmod_info_t *kmod = NULL;
            for(size_t i = 0; i < stab->nsyms; ++i)
            {
                if((symtab[i].n_type & N_TYPE) == N_UNDF)
                {
                    continue;
                }
                char *s = &strtab[symtab[i].n_un.n_strx];
                if(strcmp(s, "_kmod_info") == 0)
                {
                    DBG("kmod: " ADDR, symtab[i].n_value);
                    kmod = addr2ptr(kernel, symtab[i].n_value);
                    break;
                }
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
                        mach_hdr_t *exhdr = addr2ptr(kernel, kuntag(kbase, x1469, start_ptr[kmod_num], NULL));
                        if(exhdr && exhdr->ncmds == 2)
                        {
                            mach_seg_t *exseg = (mach_seg_t*)(exhdr + 1);
                            mach_sec_t *exsec = (mach_sec_t*)(exseg + 1);
                            struct uuid_command *exuuid = (struct uuid_command*)((uintptr_t)exseg + exseg->cmdsize);
                            if
                            (
                                exseg->cmd == MACH_SEGMENT && exuuid->cmd == LC_UUID &&
                                strcmp("__TEXT_EXEC", exseg->segname) == 0 && exseg->nsects == 1 && strcmp("__text", exsec->sectname) == 0 && kuntag(kbase, x1469, exsec->addr, NULL) == initcode &&
                                exuuid->uuid[0x0] == 0 && exuuid->uuid[0x1] == 0 && exuuid->uuid[0x2] == 0 && exuuid->uuid[0x3] == 0 &&
                                exuuid->uuid[0x4] == 0 && exuuid->uuid[0x5] == 0 && exuuid->uuid[0x6] == 0 && exuuid->uuid[0x7] == 0 &&
                                exuuid->uuid[0x8] == 0 && exuuid->uuid[0x9] == 0 && exuuid->uuid[0xa] == 0 && exuuid->uuid[0xb] == 0 &&
                                exuuid->uuid[0xc] == 0 && exuuid->uuid[0xd] == 0 && exuuid->uuid[0xe] == 0 && exuuid->uuid[0xf] == 0
                            )
                            {
                                DBG("Found kmod_start for initcode, ignoring...");
                                goto false_alarm;
                            }
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
                    kptr_t iaddr = kuntag(kbase, x1469, info_ptr[i],  NULL);
                    kptr_t haddr = kuntag(kbase, x1469, start_ptr[i], NULL);
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
                                kptr_t vmaddr = kuntag(kbase, x1469, kseg->vmaddr, NULL);
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
                    }
                    else if(strcmp("__PRELINK_INFO", seg->segname) == 0)
                    {
                        if(seg->filesize == 0)
                        {
                            continue;
                        }
                        mach_sec_t *secs = (mach_sec_t*)(seg + 1);
                        for(size_t h = 0; h < seg->nsects; ++h)
                        {
                            if(strcmp("__info", secs[h].sectname) == 0)
                            {
                                const char *xml = (const char*)((uintptr_t)kernel + secs[h].offset);
                                CFStringRef err = NULL;
                                CFTypeRef plist = IOCFUnserialize(xml, NULL, 0, &err);
                                if(!plist)
                                {
                                    ERR("IOCFUnserialize: %s", CFStringGetCStringPtr(err, kCFStringEncodingUTF8));
                                    return -1;
                                }
                                CFArrayRef arr = CFDictionaryGetValue(plist, CFSTR("_PrelinkInfoDictionary"));
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
                                    kptr_t addr = 0;
                                    if(!CFNumberGetValue(cfnum, kCFNumberLongLongType, &addr))
                                    {
                                        WRN("Failed to get CFNumber contents for kext %s", str);
                                        continue;
                                    }
                                    DBG("Kext %s at " ADDR, str, addr);
                                    mach_hdr_t *hdr2 = addr2ptr(kernel, addr);
                                    if(!hdr2)
                                    {
                                        WRN("Failed to translate kext header address " ADDR, addr);
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
                                break;
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
            for(size_t i = 0; i < bundleIdx; ++i)
            {
                if(strcmp(bundleList[i], filt_bundle) == 0)
                {
                    filter = bundleList[i];
                    break;
                }
            }
            if(!filter)
            {
                bool ambiguousFilter = false;
                for(size_t i = 0; i < bundleIdx; ++i)
                {
                    if(strstr(bundleList[i], filt_bundle))
                    {
                        if(ambiguousFilter || filter)
                        {
                            if(filter)
                            {
                                ERR("More than one bundle matching filter: %s", filter);
                                ambiguousFilter = true;
                                filter = NULL;
                            }
                            ERR("More than one bundle matching filter: %s", bundleList[i]);
                            continue;
                        }
                        filter = bundleList[i];
                    }
                }
                if(ambiguousFilter)
                {
                    return -1;
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

    metaclass_t *target = NULL;
    if(filt_class)
    {
        for(size_t i = 0; i < metas.idx; ++i)
        {
            if(strcmp(metas.val[i].name, filt_class) == 0)
            {
                target = &metas.val[i];
                break;
            }
        }
        if(!target)
        {
            bool ambiguousClass = false;
            for(size_t i = 0; i < metas.idx; ++i)
            {
                if(strstr(metas.val[i].name, filt_class))
                {
                    if(ambiguousClass || target)
                    {
                        if(target)
                        {
                            ERR("More than one class matching filter: %s", target->name);
                            ambiguousClass = true;
                            target = NULL;
                        }
                        ERR("More than one class matching filter: %s", metas.val[i].name);
                        continue;
                    }
                    target = &metas.val[i];
                }
            }
            if(ambiguousClass)
            {
                return -1;
            }
            if(!target)
            {
                ERR("No class matching %s.", filt_class);
                return -1;
            }
        }
    }
    if(target && !(opt_parent || opt_extend))
    {
        printMetaClass(target, opt_bundle, opt_meta, opt_size, opt_vtab, opt_overrides);
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
        if(opt_parent)
        {
            for(metaclass_t *meta = target; meta; )
            {
                list[lsize++] = meta;
                meta = meta->parentP;
            }
        }
        else if(opt_extend)
        {
            list[0] = target;
            lsize = 1;
            for(size_t j = 0; j < lsize; ++j)
            {
                for(size_t i = 0; i < metas.idx; ++i)
                {
                    if(metas.val[i].parent == list[j]->addr)
                    {
                        list[lsize++] = &metas.val[i];
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
                if(list[i]->bundle == filter)
                {
                    list[nsize++] = list[i];
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
                for(vtab_override_t *ovr = m->overrides.head; ovr != NULL; ovr = ovr->next)
                {
                    if(strncmp(ovr->name.method, filt_override, slen) == 0 && ovr->name.method[slen] == '(') // TODO: fix dirty hack
                    {
                        list[nsize++] = m;
                        break;
                    }
                }
            }
            lsize = nsize;
        }
        if(opt_bsort || opt_csort)
        {
            qsort(list, lsize, sizeof(*list), opt_bsort ? &compare_bundles : &compare_names);
        }
        for(size_t i = 0; i < lsize; ++i)
        {
            printMetaClass(list[i], opt_bundle, opt_meta, opt_size, opt_vtab, opt_overrides);
        }
    }

    return 0;
}
