VERSION = 1.6.0
TARGET  = iometa
SRCDIR  = src
GENDIR  = gen
FLAGS   = -Wall -O3 -flto -DVERSION=$(VERSION) -DTIMESTAMP="`date +'%d. %B %Y %H:%M:%S'`" -framework CoreFoundation -framework IOKit -lc++abi -I$(SRCDIR) $(CFLAGS)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCDIR)/*.h $(SRCDIR)/*.c $(GENDIR)/cxxsym.c
	$(CC) -o $@ $(FLAGS) $(SRCDIR)/*.c $(GENDIR)/cxxsym.c

$(GENDIR)/cxxsym.c: $(SRCDIR)/cxxsym.y | $(GENDIR)
	bison -o $@ $<

$(GENDIR):
	mkdir -p $@

clean:
	rm -rf $(TARGET) $(GENDIR)
