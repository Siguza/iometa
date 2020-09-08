#include <fcntl.h>              // open
#include <stdbool.h>
#include <unistd.h>             // close
#include <sys/mman.h>           // mmap
#include <sys/stat.h>           // fstat

#include "util.h"

bool debug = false;
const char *colorGray   = "\x1b[90m",
           *colorRed    = "\x1b[1;91m",
           *colorYellow = "\x1b[1;93m",
           *colorBlue   = "\x1b[1;94m",
           *colorPink   = "\x1b[1;95m",
           *colorCyan   = "\x1b[1;96m",
           *colorReset  = "\x1b[0m";

int map_file(const char *file, int prot, void **addrp, size_t *lenp)
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
