/* Copyright (c) 2018-2020 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#ifndef PRINT_H
#define PRINT_H

#include <stdbool.h>

#include "meta.h"
#include "util.h"

typedef bool (*print_sym_t)(const char *sym, kptr_t addr, void *arg);
typedef bool (*print_class_t)(metaclass_t *meta, opt_t opt, metaclass_t *OSMetaClass, print_sym_t print_sym, void *arg);

typedef struct
{
    bool (*init)(metaclass_t **list, size_t lsize, opt_t opt, void **argp);
    print_sym_t print_symbol;
    print_class_t print_class;
    bool (*finish)(void *arg);
} print_t;

extern print_t iometa_print;
extern print_t radare2_print;

bool print_all(void *classes, opt_t opt, metaclass_t *OSMetaClass, const char *filt_class, const char *filt_override, const char **filter, kptr_t pure_virtual, kptr_t OSMetaClassConstructor, kptr_t OSMetaClassAltConstructor, print_t *print);

#endif
