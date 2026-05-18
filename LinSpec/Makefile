CC=gcc
CFLAGS=-Isrc -Wall -Wextra
TARGET=linspec
SRC=src/main.c src/memory_audit.c src/system_audit.c

$(TARGET): $(SRC)
	@$(CC) $(CFLAGS) -o $(TARGET) $(SRC)
	@echo " ✅ Build complete: $(TARGET)"

clean:
	@rm -f $(TARGET)
	@echo " 🧹 Cleaned up binary"

.PHONY: clean
