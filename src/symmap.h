#ifndef SYMMAP_H
#define SYMMAP_H

#include <stdint.h>

struct metaclass;

typedef struct
{
    const char *class;
    const char *method;
    uint32_t structor :  1,
             reserved : 31;
} symmap_method_t;

typedef struct symmap_class
{
    struct metaclass *metaclass;
    const char *name;
    symmap_method_t *methods;
    size_t num;
    uint32_t duplicate :  1,
             reserved  : 31;
} symmap_class_t;

int compare_symclass(const void *a, const void *b);
int compare_symclass_name(const void *a, const void *b);

int parse_symmap(char *mem, size_t len, size_t *num, symmap_class_t **entries);
void print_syment(const char *owner, const char *class, const char *method);
void print_symmap(metaclass_t *meta);

#endif
