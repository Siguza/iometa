VERSION = 1.2.0
TARGET  = iometa
SRC     = src

.PHONY: all clean

all: $(TARGET)

$(TARGET): src/*.c
	$(CC) -o $@ $^ -Wall -O3 -DVERSION=$(VERSION) -framework CoreFoundation -framework IOKit $(CFLAGS)

clean:
	rm -rf $(TARGET)
