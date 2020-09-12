/* Copyright (c) 2018-2020 Siguza
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

static inline uint64_t Replicate(uint64_t val, uint8_t times, uint64_t width)
{
    // Fast path
    switch(times)
    {
        case 64:
            val |= val << width;
            width <<= 1;
        case 32:
            val |= val << width;
            width <<= 1;
        case 16:
            val |= val << width;
            width <<= 1;
        case  8:
            val |= val << width;
            width <<= 1;
        case  4:
            val |= val << width;
            width <<= 1;
        case  2:
            val |= val << width;
        case  1:
            return val;
        case 0:
            return 0;
        default:
            break;
    }
    // Slow path
    uint64_t orig = val;
    for(size_t i = 0; i < times; ++i)
    {
        val <<= width;
        val |= orig;
    }
    return val;
}

uint64_t AdvSIMDExpandImm(uint8_t op, uint8_t cmode, uint64_t imm8)
{
    uint64_t imm64 = 0;
    switch((cmode >> 1) & 0b111)
    {
        case 0b000:
            imm64 = Replicate(imm8, 2, 32);
            break;
        case 0b001:
            imm64 = Replicate(imm8 << 8, 2, 32);
            break;
        case 0b010:
            imm64 = Replicate(imm8 << 16, 2, 32);
            break;
        case 0b011:
            imm64 = Replicate(imm8 << 24, 2, 32);
            break;
        case 0b100:
            imm64 = Replicate(imm8, 4, 16);
            break;
        case 0b101:
            imm64 = Replicate(imm8 << 8, 4, 16);
            break;
        case 0b110:
            imm64 = Replicate(imm8 << (8 << (cmode & 0b1)), 2, 32);
            break;
        case 0b111:
            switch(((cmode & 0b1) << 1) | op)
            {
                case 0b00:
                    imm64 = Replicate(imm8, 8, 8);
                    break;
                case 0b01:
#if 0
                    imm8a = Replicate((imm8 >> 7) & 0b1, 8, 1);
                    imm8b = Replicate((imm8 >> 6) & 0b1, 8, 1);
                    imm8c = Replicate((imm8 >> 5) & 0b1, 8, 1);
                    imm8d = Replicate((imm8 >> 4) & 0b1, 8, 1);
                    imm8e = Replicate((imm8 >> 3) & 0b1, 8, 1);
                    imm8f = Replicate((imm8 >> 2) & 0b1, 8, 1);
                    imm8g = Replicate((imm8 >> 1) & 0b1, 8, 1);
                    imm8h = Replicate((imm8     ) & 0b1, 8, 1);
                    imm64 = (imm8a << 0x38) | (imm8b << 0x30) | (imm8c << 0x28) | (imm8d << 0x20) | (imm8e << 0x18) | (imm8f << 0x10) | (imm8g << 0x08) | imm8h;
#else
                    imm64 = imm8 | (imm8 << (0x08-1)) | (imm8 << (0x10-2)) | (imm8 << (0x18-3)) | (imm8 << (0x20-4)) | (imm8 << (0x28-5)) | (imm8 << (0x30-6)) | (imm8 << (0x38-7));
                    imm64 &= 0x0101010101010101;
                    imm64 = Replicate(imm64, 8, 1);
#endif
                    break;
                case 0b10:
                    imm64 = Replicate((((imm8 & 0xc0) ^ 0x80) << 24) | (Replicate((imm8 >> 6) & 0b1, 5, 1) << 25) | ((imm8 & 0x3f) << 19), 2, 32);
                    break;
                case 0b11:
                    imm64 = (((imm8 & 0xc0) ^ 0x80) << 56) | (Replicate((imm8 >> 6) & 0b1, 8, 1) << 54) | ((imm8 & 0x3f) << 48);
                    break;
            }
            break;
    }
    return imm64;
}
