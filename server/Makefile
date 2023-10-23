# Variables
TARGET = aesdsocket
OBJ = aesdsocket.o
RM = rm -f
CC ?= gcc

# Flags
CFLAGS ?= -Wall -c
LDFLAGS ?= -Wall -g

# Build
.PHONY: all

all: $(TARGET)

$(TARGET) : $(TARGET).c
	@$(CROSS_COMPILE)$(CC) $(LDFLAGS) $^ -o $@

# $(TARGET) : $(OBJ)
# 	@$(CROSS_COMPILE)$(CC) $(LDFLAGS) $^ -o $@

# $(OBJ) : $(TARGET).c
# 	@$(CROSS_COMPILE)$(CC) $(CFLAGS) $^ -o $@
# 	@chmod 664 $@


# Clean
.PHONY: clean

clean:
	@$(RM) $(OBJ) $(TARGET)
