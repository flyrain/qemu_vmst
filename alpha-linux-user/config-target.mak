# Automatically generated by configure - do not modify
CONFIG_QEMU_INTERP_PREFIX="/usr/gnemul/qemu-alpha"
TARGET_SHORT_ALIGNMENT=2
TARGET_INT_ALIGNMENT=4
TARGET_LONG_ALIGNMENT=8
TARGET_LLONG_ALIGNMENT=8
TARGET_ARCH=alpha
TARGET_ALPHA=y
TARGET_ARCH2=alpha
TARGET_BASE_ARCH=alpha
TARGET_ABI_DIR=alpha
CONFIG_NO_XEN=y
CONFIG_USER_ONLY=y
CONFIG_LINUX_USER=y
CONFIG_USE_NPTL=y
CONFIG_USE_GUEST_BASE=y
CONFIG_I386_DIS=y
CONFIG_ALPHA_DIS=y
LDFLAGS+=-Wl,-T../config-host.ld -Wl,-T,$(SRC_PATH)/$(ARCH).ld 
QEMU_CFLAGS+=
QEMU_INCLUDES+=-I$(SRC_PATH)/linux-headers -I$(SRC_PATH)/tcg -I$(SRC_PATH)/tcg/$(ARCH) 
