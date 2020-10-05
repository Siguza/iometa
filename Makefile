VERSION = 1.6.3
TARGET  = iometa
SRCDIR  = src
GENDIR  = gen
FLAGS   = -Wall -O3 -flto -DVERSION=$(VERSION) -DTIMESTAMP="`date +'%d. %B %Y %H:%M:%S'`" -framework CoreFoundation -framework IOKit -lc++abi -I$(SRCDIR) $(CFLAGS)

.PHONY: all aux clean

all: $(TARGET)

$(TARGET): $(SRCDIR)/*.h $(SRCDIR)/*.c $(GENDIR)/cxxsym.c
	$(CC) -o $@ $(FLAGS) $(SRCDIR)/*.c $(GENDIR)/cxxsym.c

$(GENDIR)/cxxsym.c: $(SRCDIR)/cxxsym.y | $(GENDIR)
	bison -o $@ $<

$(GENDIR):
	mkdir -p $@

aux: mangle pac

mangle: $(SRCDIR)/util.h $(SRCDIR)/cxx.h $(SRCDIR)/util.c $(GENDIR)/cxxsym.c
	$(CC) -o $@ $(FLAGS) -DCXXSYM_DEBUG $(SRCDIR)/util.c $(GENDIR)/cxxsym.c

pac: $(SRCDIR)/util.h $(SRCDIR)/cxx.h $(SRCDIR)/util.c $(SRCDIR)/cxx.c
	$(CC) -o $@ $(FLAGS) -DCXXPAC_DEBUG $(SRCDIR)/util.c $(SRCDIR)/cxx.c

clean:
	rm -rf $(TARGET) $(GENDIR) mangle pac
