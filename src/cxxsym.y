/* Copyright (c) 2018-2020 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

%{
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>              // snprintf
#include <stdlib.h>             // malloc, free
#include <string.h>             // strncmp, strstr

#include "cxx.h"
#include "util.h"

enum
{
    kBool,
    kChar,
    kSChar,
    kUChar,
    kShort,
    kUShort,
    kInt,
    kUInt,
    kLong,
    kULong,
    kLLong,
    kULLong,
    kFloat,
    kDouble,
    kLDouble,
    kVarargs,
    kVoid,
    kName,
    kTemplate,
    kFunc,
    kArray,
    kPtr,
    kRef,
    kVolatile,
    kConst,
    kBlock,
    kMember,
};

// To avoid tons of allocs
typedef struct
{
    const char *ptr;
    int len;
} str_t;

typedef struct type
{
    struct type *next;
    int kind;
    union
    {
        struct
        {
            str_t str;
            struct type *next;
        } name; // kName
        struct
        {
            struct type *name;
            struct type *types;
        } tpl; // kTemplate
        struct
        {
            struct type *ret;
            struct type *args;
        } func; // kFunc
        struct
        {
            str_t size;
            struct type *inner;
        } arr; // kArray
        struct
        {
            struct type *class;
            struct type *inner;
        } mem;
        struct type *inner; // kPtr, kRef, kVolatile, kConst, kBlock
    } val;
} type_t;

typedef struct
{
    // In
    const char *input;
    const char *moreinput;
    int pos;
    // Out
    type_t *class;
    str_t method;
    type_t *args;
    uint8_t cnst : 1,
            vltl : 1;
} state_t;
%}

%pure-parser

%token NAME_LITERAL
%token INT_LITERAL
%token CONST VOLATILE
%token SIGNED UNSIGNED BOOL CHAR SHORT INT LONG FLOAT DOUBLE
%token VARARGS DELIM CLASS_DELIM VOID BLOCK
%token ERROR

%lex-param   { state_t *state }
%parse-param { state_t *state }

%union
{
    str_t str;
    uint8_t val;
    type_t *type;
}

%type <str> NAME_LITERAL INT_LITERAL
%type <val> const.opt volatile.opt
%type <type> arglist typelist type complex array qual.opt qual flat ptr.opt ref.opt member.opt basic template.opt data name literal primitive varargs void block

%{
static void yyerror(state_t *state, const char *s);
static int yylex(YYSTYPE *lvalp, state_t *state);
static type_t* alloctype(int kind);
static void freetype(type_t *t);
static void list_set_last(type_t *t, type_t *last);
static void inner_set_base(type_t *t, type_t *base);
static void array_set_base(type_t *t, type_t *base);
static void complex_set_base(type_t *t, type_t *base);
%}

%destructor { freetype($$); } arglist typelist type complex array qual.opt qual flat ptr.opt ref.opt member.opt basic template.opt data name literal primitive varargs void block

%%

method: name DELIM NAME_LITERAL '(' arglist ')' const.opt volatile.opt {
          state->class = $1;
          state->method = $3;
          state->args = $5;
          state->cnst = $7;
          state->vltl = $8;
      }
      | name CLASS_DELIM NAME_LITERAL '(' arglist ')' const.opt volatile.opt {
          state->class = $1;
          state->method = $3;
          state->args = $5;
          state->cnst = $7;
          state->vltl = $8;
      }
      ;

arglist: /* empty */          { $$ = NULL; }
       | varargs              { $$ = $1; }
       | typelist             { $$ = $1; }
       | typelist ',' varargs { $$ = $1; list_set_last($$, $3); }
       ;

typelist: type              { $$ = $1; }
        | typelist ',' type { $$ = $1; list_set_last($$, $3); }
        ;

type: flat ref.opt {
        $$ = $1;
        if($2)
        {
            $2->val.inner = $$;
            $$ = $2;
        }
    }
    | flat complex {
        $$ = $2;
        complex_set_base($$, $1);
    }
    | void '(' qual ')' '(' arglist ')' {
        $$ = alloctype(kFunc);
        if(!$$) YYERROR;
        $$->val.func.ret = $1;
        $$->val.func.args = $6;
        complex_set_base($3, $$);
        $$ = $3;
    }
    | void '(' arglist ')' block qual.opt {
        $$ = alloctype(kFunc);
        if(!$$) YYERROR;
        $$->val.func.ret = $1;
        $$->val.func.args = $3;
        $5->val.inner = $$;
        $$ = $5;
        if($6)
        {
            complex_set_base($6, $$);
            $$ = $6;
        }
    }
    ;

complex: '(' qual ')' array {
           $$ = $2;
           complex_set_base($$, $4);
       }
       | '(' qual ')' '(' arglist ')' {
           $$ = alloctype(kFunc);
           if(!$$) YYERROR;
           $$->val.func.ret = NULL;
           $$->val.func.args = $5;
           complex_set_base($2, $$);
           $$ = $2;
       }
       | '(' arglist ')' block qual.opt {
           $$ = alloctype(kFunc);
           if(!$$) YYERROR;
           $$->val.func.ret = NULL;
           $$->val.func.args = $2;
           complex_set_base($4, $$);
           $$ = $4;
           if($5)
           {
               complex_set_base($5, $$);
               $$ = $5;
           }
       }
       ;

array: '[' ']'                   { $$ = alloctype(kArray); if(!$$) YYERROR; $$->val.arr.inner = NULL; $$->val.arr.size.ptr = NULL; }
     | '[' INT_LITERAL ']'       { $$ = alloctype(kArray); if(!$$) YYERROR; $$->val.arr.inner = NULL; $$->val.arr.size = $2; }
     | array '[' INT_LITERAL ']' { $$ = alloctype(kArray); if(!$$) YYERROR; $$->val.arr.inner = NULL; $$->val.arr.size = $3; array_set_base($1, $$); $$ = $1; }
     ;

qual.opt: /* empty */ { $$ = NULL; }
        | qual        { $$ = $1; }
        ;

qual: '&' { $$ = alloctype(kRef); if(!$$) YYERROR; $$->val.inner = NULL; }
    | member.opt '*' const.opt volatile.opt ptr.opt ref.opt {
        if($1)
        {
            $$ = $1;
        }
        else
        {
            $$ = alloctype(kPtr);
            if(!$$) YYERROR;
            $$->val.inner = NULL;
        }
        if($3)
        {
            type_t *tmp = alloctype(kConst);
            if(!tmp) YYERROR;
            tmp->val.inner = $$;
            $$ = tmp;
        }
        if($4)
        {
            type_t *tmp = alloctype(kVolatile);
            if(!tmp) YYERROR;
            tmp->val.inner = $$;
            $$ = tmp;
        }
        if($5)
        {
            inner_set_base($5, $$);
            $$ = $5;
        }
        if($6)
        {
            $6->val.inner = $$;
            $$ = $6;
        }
    }
    | member.opt '*' const.opt volatile.opt ptr.opt complex {
        if($1)
        {
            $$ = $1;
        }
        else
        {
            $$ = alloctype(kPtr);
            if(!$$) YYERROR;
            $$->val.inner = NULL;
        }
        if($3)
        {
            type_t *tmp = alloctype(kConst);
            if(!tmp) YYERROR;
            tmp->val.inner = $$;
            $$ = tmp;
        }
        if($4)
        {
            type_t *tmp = alloctype(kVolatile);
            if(!tmp) YYERROR;
            tmp->val.inner = $$;
            $$ = tmp;
        }
        if($5)
        {
            inner_set_base($5, $$);
            $$ = $5;
        }
        if($6)
        {
            complex_set_base($6, $$);
            $$ = $6;
        }
    }
    ;

flat: basic ptr.opt {
        $$ = $1;
        if($2)
        {
            inner_set_base($2, $$);
            $$ = $2;
        }
    }
    | void const.opt volatile.opt '*' const.opt volatile.opt ptr.opt {
        if($2)
        {
            type_t *tmp = alloctype(kConst);
            if(!tmp) YYERROR;
            tmp->val.inner = $1;
            $1 = tmp;
        }
        if($3)
        {
            type_t *tmp = alloctype(kVolatile);
            if(!tmp) YYERROR;
            tmp->val.inner = $1;
            $1 = tmp;
        }
        $$ = alloctype(kPtr);
        if(!$$) YYERROR;
        $$->val.inner = $1;
        if($5)
        {
            type_t *tmp = alloctype(kConst);
            if(!tmp) YYERROR;
            tmp->val.inner = $$;
            $$ = tmp;
        }
        if($6)
        {
            type_t *tmp = alloctype(kVolatile);
            if(!tmp) YYERROR;
            tmp->val.inner = $$;
            $$ = tmp;
        }
        if($7)
        {
            inner_set_base($7, $$);
            $$ = $7;
        }
    }
    ;

ptr.opt: /* empty */                        { $$ = NULL; }
       | ptr.opt member.opt '*' const.opt volatile.opt {
           if($2)
           {
               $$ = $2;
               $$->val.mem.inner = $1;
           }
           else
           {
               $$ = alloctype(kPtr);
               if(!$$) YYERROR;
               $$->val.inner = $1;
           }
           if($4)
           {
               type_t *tmp = alloctype(kConst);
               if(!tmp) YYERROR;
               tmp->val.inner = $$;
               $$ = tmp;
           }
           if($5)
           {
               type_t *tmp = alloctype(kVolatile);
               if(!tmp) YYERROR;
               tmp->val.inner = $$;
               $$ = tmp;
           }
       }
       ;

ref.opt: /* empty */ { $$ = NULL; }
       | '&'         { $$ = alloctype(kRef); if(!$$) YYERROR; $$->val.inner = NULL; }
       ;

member.opt: /* empty */ { $$ = NULL; }
          | name DELIM  { $$ = alloctype(kMember); if(!$$) YYERROR; $$->val.mem.class = $1; $$->val.mem.inner = NULL; }
          ;

basic: data const.opt volatile.opt {
        $$ = $1;
        if($2)
        {
            type_t *tmp = alloctype(kConst);
            if(!tmp) YYERROR;
            tmp->val.inner = $$;
            $$ = tmp;
        }
        if($3)
        {
            type_t *tmp = alloctype(kVolatile);
            if(!tmp) YYERROR;
            tmp->val.inner = $$;
            $$ = tmp;
        }
     }
     ;

const.opt: /* empty */ { $$ = 0; }
         | CONST       { $$ = 1; }
         ;

volatile.opt: /* empty */ { $$ = 0; }
            | VOLATILE    { $$ = 1; }
            ;

template.opt: /* empty */           { $$ = NULL; }
            /*| '<' template_args '>' { $$ = $2; }*/
            | '<' typelist '>'      { $$ = $2; }
            ;

/*template_args: type
             | template_args ',' type
             | integer
             | template_args ',' integer
             ;*/

data: primitive         { $$ = $1; }
    | name template.opt {
        if($2)
        {
            $$ = alloctype(kTemplate);
            if(!$$) YYERROR;
            $$->val.tpl.name = $1;
            $$->val.tpl.types = $2;
        }
        else
        {
            $$ = $1;
        }
    }
    ;

name: literal            { $$ = $1; }
    | name DELIM literal { $$ = $3; $$->val.name.next = $1; }
    ;

literal: NAME_LITERAL {
            $$ = alloctype(kName);
            if(!$$) YYERROR;
            $$->val.name.str = $1;
            $$->val.name.next = NULL;
       }
       ;

primitive: BOOL                 { $$ = alloctype(kBool);    if(!$$) YYERROR; }
         | CHAR                 { $$ = alloctype(kChar);    if(!$$) YYERROR; }
         | SIGNED CHAR          { $$ = alloctype(kSChar);   if(!$$) YYERROR; }
         | UNSIGNED CHAR        { $$ = alloctype(kUChar);   if(!$$) YYERROR; }
         | SHORT                { $$ = alloctype(kShort);   if(!$$) YYERROR; }
         | UNSIGNED SHORT       { $$ = alloctype(kUShort);  if(!$$) YYERROR; }
         | INT                  { $$ = alloctype(kInt);     if(!$$) YYERROR; }
         | UNSIGNED INT         { $$ = alloctype(kUInt);    if(!$$) YYERROR; }
         | LONG                 { $$ = alloctype(kLong);    if(!$$) YYERROR; }
         | UNSIGNED LONG        { $$ = alloctype(kULong);   if(!$$) YYERROR; }
         | LONG LONG            { $$ = alloctype(kLLong);   if(!$$) YYERROR; }
         | UNSIGNED LONG LONG   { $$ = alloctype(kULLong);  if(!$$) YYERROR; }
         | FLOAT                { $$ = alloctype(kFloat);   if(!$$) YYERROR; }
         | DOUBLE               { $$ = alloctype(kDouble);  if(!$$) YYERROR; }
         | LONG DOUBLE          { $$ = alloctype(kLDouble); if(!$$) YYERROR; }
         ;

varargs: VARARGS { $$ = alloctype(kVarargs); if(!$$) YYERROR; };

void: VOID { $$ = alloctype(kVoid); if(!$$) YYERROR; };

block: BLOCK { $$ = alloctype(kBlock); if(!$$) YYERROR; $$->val.inner = NULL; };

%%

// ------------------------------ Parsing ------------------------------

static type_t* alloctype(int kind)
{
    type_t *t = malloc(sizeof(type_t));
    if(t)
    {
        t->next = NULL;
        t->kind = kind;
    }
    return t;
}

static void freetype(type_t *t)
{
    if(!t) return;
    if(t->next) freetype(t->next);
    switch(t->kind)
    {
        case kPtr:
        case kRef:
        case kVolatile:
        case kConst:
        case kBlock:
            if(t->val.inner) freetype(t->val.inner);
            break;
        case kName:
            if(t->val.name.next) freetype(t->val.name.next);
            break;
        case kTemplate:
            if(t->val.tpl.name) freetype(t->val.tpl.name);
            if(t->val.tpl.types) freetype(t->val.tpl.types);
            break;
        case kFunc:
            if(t->val.func.ret) freetype(t->val.func.ret);
            if(t->val.func.args) freetype(t->val.func.args);
            break;
        case kArray:
            if(t->val.arr.inner) freetype(t->val.arr.inner);
            break;
        case kMember:
            if(t->val.mem.class) freetype(t->val.mem.class);
            if(t->val.mem.inner) freetype(t->val.mem.inner);
            break;
    }
    free(t);
}

static void list_set_last(type_t *t, type_t *last)
{
    while(1)
    {
        if(!t->next)
        {
            t->next = last;
            break;
        }
        t = t->next;
    }
}

static void inner_set_base(type_t *t, type_t *base)
{
    while(1)
    {
        if(!t->val.inner)
        {
            t->val.inner = base;
            break;
        }
        t = t->val.inner;
    }
}

static void array_set_base(type_t *t, type_t *base)
{
    while(1)
    {
        if(!t->val.arr.inner)
        {
            t->val.arr.inner = base;
            break;
        }
        t = t->val.arr.inner;
    }
}

static void complex_set_base(type_t *t, type_t *base)
{
    if(t->kind == kRef)
    {
        if(!t->val.inner)
        {
            t->val.inner = base;
            return;
        }
        t = t->val.inner;
    }
    while(1)
    {
        switch(t->kind)
        {
            case kPtr:
            case kVolatile:
            case kConst:
            case kBlock:
                if(!t->val.inner)
                {
                    t->val.inner = base;
                    return;
                }
                t = t->val.inner;
                break;
            case kFunc:
                if(!t->val.func.ret)
                {
                    t->val.func.ret = base;
                    return;
                }
                t = t->val.func.ret;
                break;
            case kArray:
                if(!t->val.arr.inner)
                {
                    t->val.arr.inner = base;
                    return;
                }
                t = t->val.arr.inner;
                break;
            case kMember:
                if(!t->val.mem.inner)
                {
                    t->val.mem.inner = base;
                    return;
                }
                t = t->val.mem.inner;
                break;
        }
    }
}

static void yyerror(state_t *state, const char *s)
{
    WRN("cxx_mangle: %s at \"%s\"", s, &state->input[state->pos]);
}

static int yylex(YYSTYPE *lvalp, state_t *state)
{
    char c;
    int pos;
    do
    {
        c = state->input[pos = state->pos++];
    } while(c == ' ');
    switch(c)
    {
        case '\0':
            if(state->moreinput)
            {
                state->input = state->moreinput;
                state->moreinput = NULL;
                state->pos = 0;
                //return CLASS_DELIM;
                return DELIM;
            }
            return YYEOF;
        case ',':
        case '*':
        case '&':
        case '(':
        case ')':
        case '[':
        case ']':
        case '<':
        case '>':
            return c;
        case ':':
            if(state->input[pos = state->pos++] != ':') return ERROR;
            return DELIM;
        case '.':
            if(state->input[pos = state->pos++] != '.') return ERROR;
            if(state->input[pos = state->pos++] != '.') return ERROR;
            return VARARGS;
    }
    if(c >= '0' && c <= '9')
    {
        // Don't allow leading zeroes
        if(c == '0' && state->input[state->pos] >= '0' && state->input[state->pos] <= '9')
        {
            return ERROR;
        }
        // If we supported full C++ declarations, we'd have to allow things like 3ull here.
        // But these are only used in template literals, which we currently don't support.
        while(1)
        {
            c = state->input[state->pos];
            if(!(c >= '0' && c <= '9'))
            {
                // Don't consume
                break;
            }
            // Consume
            ++state->pos;
        }
        // If the first non-digit is alphanumeric, then syntax error
        if(c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
        {
            return ERROR;
        }
        lvalp->str = (str_t){ .ptr = state->input + pos, .len = state->pos - pos };
        return INT_LITERAL;
    }
    if(c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
    {
        while(1)
        {
            c = state->input[state->pos];
            if(!(c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')))
            {
                // Don't consume
                break;
            }
            // Consume
            ++state->pos;
        }
        const char *ptr = state->input + pos;
        int len = state->pos - pos;
        switch(len)
        {
            case 3:
                if(strncmp(ptr, "int", 3) == 0) return INT;
                break;
            case 4:
                if(strncmp(ptr, "bool", 4) == 0) return BOOL;
                if(strncmp(ptr, "char", 4) == 0) return CHAR;
                if(strncmp(ptr, "long", 4) == 0) return LONG;
                if(strncmp(ptr, "void", 4) == 0) return VOID;
                break;
            case 5:
                if(strncmp(ptr, "const", 5) == 0) return CONST;
                if(strncmp(ptr, "short", 5) == 0) return SHORT;
                if(strncmp(ptr, "float", 5) == 0) return FLOAT;
                break;
            case 6:
                if(strncmp(ptr, "signed", 6) == 0) return SIGNED;
                if(strncmp(ptr, "double", 6) == 0) return DOUBLE;
                break;
            case 8:
                if(strncmp(ptr, "unsigned", 8) == 0) return UNSIGNED;
                if(strncmp(ptr, "volatile", 8) == 0) return VOLATILE;
                break;
            case 13:
                if(strncmp(ptr, "block_pointer", 13) == 0) return BLOCK;
                break;
        }
        lvalp->str = (str_t){ .ptr = ptr, .len = len };
        return NAME_LITERAL;
    }
    return ERROR;
}

// ------------------------------ Parsing End ------------------------------

bool compare_types(type_t *a, type_t *b)
{
    if(a->kind != b->kind) return false;
    switch(a->kind)
    {
        case kPtr:
        case kRef:
        case kVolatile:
        case kConst:
        case kBlock:
            return compare_types(a->val.inner, b->val.inner);
        case kMember:
            return compare_types(a->val.mem.class, b->val.mem.class) && compare_types(a->val.mem.inner, b->val.mem.inner);
        case kName:
            if(a->val.name.str.len != b->val.name.str.len || strncmp(a->val.name.str.ptr, b->val.name.str.ptr, a->val.name.str.len) != 0) return false;
            if(a->val.name.next == NULL && b->val.name.next == NULL) return true;
            if(a->val.name.next == NULL || b->val.name.next == NULL) return false;
            return compare_types(a->val.name.next, b->val.name.next);
        case kArray:
            return a->val.arr.size.len == b->val.arr.size.len
                && strncmp(a->val.arr.size.ptr, b->val.arr.size.ptr, a->val.arr.size.len) == 0
                && compare_types(a->val.arr.inner, b->val.arr.inner);
        case kTemplate:
            for(type_t *t1 = a->val.tpl.types, *t2 = b->val.tpl.types; t1 || t2; )
            {
                if(!t1 || !t2) return false;
                if(!compare_types(t1, t2)) return false;
                t1 = t1->next;
                t2 = t2->next;
            }
            return compare_types(a->val.tpl.name, b->val.tpl.name);
        case kFunc:
            for(type_t *t1 = a->val.func.args, *t2 = b->val.func.args; t1 || t2; )
            {
                if(!t1 || !t2) return false;
                if(!compare_types(t1, t2)) return false;
                t1 = t1->next;
                t2 = t2->next;
            }
            return compare_types(a->val.func.ret, b->val.func.ret);
    }
    // For all the primitives
    return true;
}

static bool cxx_mangle_compress(char *buf, size_t sz, int *i, void *arr, char *str, type_t *type)
{
    ARRCAST(type_t*, stack, arr);
    for(size_t j = 0; j < stack->idx; ++j)
    {
        if(compare_types(stack->val[j], type))
        {
            // We're guaranteed to have two characters because everything single-char is a primitive
            *str++ = 'S';
            if(j > 0)
            {
                --j;
                size_t log36 = 0;
                for(size_t tmp = j; tmp >= 36; tmp /= 36)
                {
                    ++log36;
                }
                // One for the log0 digit, one for the underscore
                if(log36 + 2 > (size_t)(buf + sz - str))
                {
                    return false;
                }
                for(size_t k = 0; k <= log36; ++k)
                {
                    int tmp = j % 36;
                    str[log36 - k] = tmp < 10 ? '0' + tmp : 'A' + (tmp - 10);
                    j /= 36;
                }
                str += log36 + 1;
            }
            *str++ = '_';
            *str = '\0';
            *i = str - buf;
            return true;
        }
    }
    // Not found, add it
    ARRPUSH(*stack, type);
    return true;
}

static bool cxx_mangle_type(char *buf, size_t sz, int *i, void *arr, type_t *type)
{
#define P(fmt, ...) \
do \
{ \
    *i += snprintf(buf + *i, sz - *i, (fmt), ##__VA_ARGS__); \
    if(*i >= sz) return false; \
} while(0)
    for(type_t *t = type; t != NULL; t = t->next)
    {
        bool compress = false;
        int pos = *i;
        switch(t->kind)
        {
            case kBool:     P("b"); break;
            case kChar:     P("c"); break;
            case kSChar:    P("a"); break;
            case kUChar:    P("h"); break;
            case kShort:    P("s"); break;
            case kUShort:   P("t"); break;
            case kInt:      P("i"); break;
            case kUInt:     P("j"); break;
            case kLong:     P("l"); break;
            case kULong:    P("m"); break;
            case kLLong:    P("x"); break;
            case kULLong:   P("y"); break;
            case kFloat:    P("f"); break;
            case kDouble:   P("d"); break;
            case kLDouble:  P("e"); break;
            case kVarargs:  P("z"); break;
            case kVoid:     P("v"); break;
            case kName:
            {
                compress = true;
                if(t->val.name.next)
                {
                    if(!cxx_mangle_type(buf, sz, i, arr, t->val.name.next))
                    {
                        return false;
                    }
                    // This is a bit weird, but we need to slip into the previous N..E group
                    if(buf[*i - 1] == 'E')
                    {
                        --*i;
                    }
                    // ...or create one, if none exists yet.
                    else
                    {
                        if((size_t)*i + 1 >= sz) return false;
                        for(int j = *i; j > pos; --j)
                        {
                            buf[j] = buf[j-1];
                        }
                        ++*i;
                        buf[pos] = 'N';
                    }
                    // Now append our own name to the group and close it
                    P("%u%.*sE", t->val.name.str.len, t->val.name.str.len, t->val.name.str.ptr);
                }
                else
                {
                    P("%u%.*s", t->val.name.str.len, t->val.name.str.len, t->val.name.str.ptr);
                }
                break;
            }
            case kTemplate:
            {
                compress = true;
                if(!cxx_mangle_type(buf, sz, i, arr, t->val.tpl.name))
                {
                    return false;
                }
                // Same deal as for kName
                bool inGroup = buf[*i - 1] == 'E';
                if(inGroup)
                {
                    --*i;
                }
                // Now emit the type list
                P("I");
                if(!cxx_mangle_type(buf, sz, i, arr, t->val.tpl.types))
                {
                    return false;
                }
                // And both the type list and the group
                if(inGroup) P("EE");
                else        P("E");
                break;
            }
            case kFunc:
                compress = true;
                P("F");
                if(!cxx_mangle_type(buf, sz, i, arr, t->val.func.ret))
                {
                    return false;
                }
                if(!t->val.func.args)
                {
                    P("v");
                }
                else if(!cxx_mangle_type(buf, sz, i, arr, t->val.func.args))
                {
                    return false;
                }
                P("E");
                break;
            case kArray:
                compress = true;
                if(!t->val.arr.size.ptr) P("A_");
                else P("A%.*s_", t->val.arr.size.len, t->val.arr.size.ptr);
                if(!cxx_mangle_type(buf, sz, i, arr, t->val.arr.inner))
                {
                    return false;
                }
                break;
            case kPtr:
                compress = true;
                P("P");
                if(!cxx_mangle_type(buf, sz, i, arr, t->val.inner))
                {
                    return false;
                }
                break;
            case kRef:
                compress = true;
                P("R");
                if(!cxx_mangle_type(buf, sz, i, arr, t->val.inner))
                {
                    return false;
                }
                break;
            case kVolatile:
                compress = true;
                P("V");
                if(!cxx_mangle_type(buf, sz, i, arr, t->val.inner))
                {
                    return false;
                }
                break;
            case kConst:
                compress = true;
                P("K");
                if(!cxx_mangle_type(buf, sz, i, arr, t->val.inner))
                {
                    return false;
                }
                break;
            case kBlock:
                compress = true;
                P("U13block_pointer");
                if(!cxx_mangle_type(buf, sz, i, arr, t->val.inner))
                {
                    return false;
                }
                break;
            case kMember:
                compress = true;
                P("M");
                if(!cxx_mangle_type(buf, sz, i, arr, t->val.mem.class))
                {
                    return false;
                }
                if(!cxx_mangle_type(buf, sz, i, arr, t->val.mem.inner))
                {
                    return false;
                }
                break;
        }
        if(compress)
        {
            if(!cxx_mangle_compress(buf, sz, i, arr, buf + pos, t))
            {
                return false;
            }
        }
    }
    return true;
#undef P
}

char* cxx_mangle(const char *class, const char *method)
{
    char *ret = NULL;
    state_t state =
    {
        .input = class ? class : method,
        .moreinput = class ? method : NULL,
        .pos = 0,
    };
    int r = yyparse(&state);
    if(r != 0)
    {
        goto out;
    }

    int i = 0;
    char buf[512];
    buf[0] = '\0';
#define P(fmt, ...) \
do \
{ \
    i += snprintf(buf + i, sizeof(buf) - i, (fmt), ##__VA_ARGS__); \
    if(i >= sizeof(buf)) goto out; \
} while(0)

    P("__ZN%s%s", state.vltl ? "V" : "",  state.cnst ? "K" : "");
    ARRDEF(type_t*, stack, 32);
    int prev = i;
    bool ok = cxx_mangle_type(buf, sizeof(buf), &i, &stack, state.class);
    if(ok)
    {
        if(buf[prev] == 'N')
        {
            i -= 2; // N and E
            for(; prev < i; ++prev)
            {
                buf[prev] = buf[prev+1];
            }
        }
        P("%u%.*sE", state.method.len, state.method.len, state.method.ptr);
        if(!state.args)
        {
            P("v");
        }
        else
        {
            ok = cxx_mangle_type(buf, sizeof(buf), &i, &stack, state.args);
        }
    }
    ARRFREE(stack);
    if(!ok)
    {
        goto out;
    }
#undef P
    ret = strdup(buf);

out:;
    if(state.args) freetype(state.args);
    return ret;
}

#ifdef CXXSYM_DEBUG
int main(int argc, const char **argv)
{
    if(argc != 2)
    {
        fprintf(stderr, "Usage: %s 'Class::method(...)'\n", argv[0]);
        return -1;
    }
    char *str = cxx_mangle(NULL, argv[1]);
    if(!str)
    {
        fprintf(stderr, "Mangling error\n");
        return -1;
    }
    printf("%s\n", str);
    return 0;
}
#endif
