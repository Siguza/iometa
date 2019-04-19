/* Copyright (c) 2018-2019 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#include <stdint.h>
#include "a64.h"

static inline uint64_t Ones(uint8_t len)
{
    return (((1ULL << ((len & 0x40) >> 1)) - 1) << 32) | ((1ULL << (len & 0x3f)) - 1);
}

uint64_t DecodeBitMasks(uint8_t N, uint8_t imms, uint8_t immr, uint8_t bits)
{
    uint8_t len = (N << 6) | (~imms & 0x3f);
    len = (len & (1 << 6)) ? 6 : (len & (1 << 5)) ? 5 : (len & (1 << 4)) ? 4 : (len & (1 << 3)) ? 3 : (len & (1 << 2)) ? 2 : (len & (1 << 1)) ? 1 : (len & (1 << 0)) ? 0 : -1;
    uint64_t levels = Ones(len);
    uint64_t S = imms & levels;
    uint64_t R = immr & levels;
    uint8_t esize = 1 << len;
    uint64_t welem = Ones(S + 1);
    uint64_t wmask = (welem >> R) | ((welem & Ones(R % esize)) << (esize - (R % esize)));
    while(esize < bits)
    {
        wmask |= wmask << esize;
        esize <<= 1;
    }
    return wmask;
}
