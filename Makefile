VERSION = 1.5.0
TARGET  = iometa
SRCDIR  = src
FLAGS   = -Wall -O3 -flto -DVERSION=$(VERSION) -DTIMESTAMP="`date +'%d. %B %Y %H:%M:%S'`" -framework CoreFoundation -framework IOKit -lc++abi $(CFLAGS)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCDIR)/*.c
	$(CC) -o $@ $(FLAGS) $^

clean:
	rm -rf $(TARGET)
