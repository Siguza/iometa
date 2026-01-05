VERSION := 1.7.1
TARGET  := iometa
SRCDIR  := src
GENDIR  := gen
DEPDIR  := IOCFBootleg
FLAGS   := -Wall -Wshadow-all -std=gnu17 -D_GNU_SOURCE=1 -O3 -flto -DVERSION=$(VERSION) -DTIMESTAMP="`date +'%d. %B %Y %H:%M:%S'`" -I$(SRCDIR) $(CFLAGS)
DEP_C   :=
DEP_H   :=

ifndef HOST_OS
    ifeq ($(OS),Windows_NT)
        HOST_OS	:= Windows
    else
        HOST_OS	:= $(shell uname -s)
    endif
endif

ifeq ($(HOST_OS),Darwin)
    FLAGS += -framework CoreFoundation -framework IOKit -lc++abi
else
    FLAGS += -Wno-unused-but-set-variable -isystem $(DEPDIR)/include -isystem $(DEPDIR)/src -lstdc++
    DEP_C += $(DEPDIR)/src/CoreFoundation/*.c $(DEPDIR)/src/IOKit/*.c
    DEP_H += $(DEPDIR)/src/CoreFoundation/*.h $(DEPDIR)/src/device/*.h $(DEPDIR)/src/*.h $(DEPDIR)/include/CoreFoundation/*.h $(DEPDIR)/include/IOKit/*.h $(DEPDIR)/include/System/libkern/*.h
endif


.PHONY: all aux clean

all: $(TARGET)

$(TARGET): $(SRCDIR)/*.h $(SRCDIR)/*.c $(GENDIR)/cxxsym.c $(DEP_H) $(DEP_C) Makefile
	$(CC) -o $@ $(FLAGS) $(SRCDIR)/*.c $(GENDIR)/cxxsym.c $(DEP_C)

$(GENDIR)/cxxsym.c: $(SRCDIR)/cxxsym.y Makefile | $(GENDIR)
	bison -o $@ $<

$(GENDIR):
	mkdir -p $@

aux: mangle pac

mangle: $(SRCDIR)/util.h $(SRCDIR)/cxx.h $(SRCDIR)/util.c $(GENDIR)/cxxsym.c Makefile
	$(CC) -o $@ $(FLAGS) -DCXXSYM_DEBUG $(SRCDIR)/util.c $(GENDIR)/cxxsym.c

pac: $(SRCDIR)/util.h $(SRCDIR)/cxx.h $(SRCDIR)/util.c $(SRCDIR)/cxx.c Makefile
	$(CC) -o $@ $(FLAGS) -DCXXPAC_DEBUG $(SRCDIR)/util.c $(SRCDIR)/cxx.c

clean:
	rm -rf $(TARGET) $(GENDIR) mangle pac
