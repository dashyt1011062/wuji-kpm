KP_DIR ?= ../kpatch-next

ifeq ($(origin CC),default)
CC := gcc
endif
ifneq ($(strip $(TARGET_COMPILE)),)
CC := $(TARGET_COMPILE)gcc
endif

TARGET := wuji-hwbp.kpm
OBJS := src/wuji_hwbp.o

INCLUDE_DIRS := \
	kernel \
	kernel/include \
	kernel/patch/include \
	kernel/linux/include \
	kernel/linux/arch/arm64/include \
	kernel/linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/$(dir))

CFLAGS += -Wall -Wextra -fno-builtin -fno-stack-protector -ffreestanding
CFLAGS += -nostdinc -mgeneral-regs-only -std=gnu11

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -r -o $@ $^

src/%.o: src/%.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -O2 -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)
