# Variables
TARGET = writer
OBJ = writer.o
RM = rm -f
CC = gcc

# Flags
CFLAGS = -Wall -c

# Build
.PHONY: all

all: $(TARGET)

$(TARGET) : $(OBJ)
	@$(CROSS_COMPILE)$(CC) $^ -o $@

$(OBJ) : $(TARGET).c
	@$(CROSS_COMPILE)$(CC) $(CFLAGS) -o $@ $<


# Clean
.PHONY: clean

clean:
	@$(RM) $(OBJ) $(TARGET)
