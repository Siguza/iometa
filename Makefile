TARGET = iometa
SRC = src

.PHONY: all clean

all: $(TARGET)

$(TARGET): src/*.c
	$(CC) -o $@ $^ -Wall -O3 -framework CoreFoundation -framework IOKit $(CFLAGS)

clean:
	rm -rf $(TARGET)
