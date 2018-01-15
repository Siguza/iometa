#ifndef CXX_H
#define CXX_H

#include <stdbool.h>

bool cxx_demangle(const char *sym, char **classptr, char **methodptr, bool *structorptr);

#endif
