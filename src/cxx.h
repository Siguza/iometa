#ifndef CXX_H
#define CXX_H

#include <stdbool.h>

bool cxx_demangle(const char *sym, const char **classptr, const char **methodptr);

#endif
