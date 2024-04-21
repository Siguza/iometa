/* Copyright (c) 2018-2024 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#include <fcntl.h>              // open
#include <stdbool.h>
#include <unistd.h>             // close
#include <sys/mman.h>           // mmap, MAP_FAILED
#include <sys/stat.h>           // fstat

#include "util.h"

uint8_t debug = 0;
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
