/* Copyright (c) 2018 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#ifndef CXX_H
#define CXX_H

#include <stdbool.h>

bool cxx_demangle(const char *sym, char **classptr, char **methodptr, bool *structorptr);

#endif
