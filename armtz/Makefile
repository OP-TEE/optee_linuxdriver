ccflags-y+=-Werror

obj-$(CONFIG_OPTEE) += optee_armtz.o

optee_armtz-objs:=   \
		tee_tz_drv.o \
		tee_mem.o \
		handle.o


ifeq ($(CONFIG_ARM),y)
# "smc" assembly instruction requires dedicated "ARMv7 secure extension"
secext := $(call as-instr,.arch_extension sec,+sec)
AFLAGS_tee_smc-arm.o := -Wa,-march=armv7-a$(secext)
optee_armtz-objs += \
	tee_smc-arm.o
endif

ifeq ($(CONFIG_ARM64),y)
optee_armtz-objs += \
	tee_smc-arm64.o
endif
