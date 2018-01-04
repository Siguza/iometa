TARGET = iometa
SRC = src

.PHONY: all clean

all: $(TARGET)

$(TARGET): src/*.c
	$(CC) -o $@ $^ -Wall -O3 $(CFLAGS)

clean:
	rm -rf $(TARGET)
