CFG_TEE_DRV_DEBUGFS?=0

ccflags-y+=-Werror
ccflags-y+=-I$(M)/include/linux -iquote$(M)/generic
ccflags-y+=-I$(src)/include

ccflags-y+=-DCFG_TEE_DRV_DEBUGFS=${CFG_TEE_DRV_DEBUGFS}

obj-m += optee.o

optee-objs:=   \
		generic/tee_service.o \
		generic/tee_driver.o \
		generic/tee_kernel_api.o \
		generic/tee_supp_com.o \
		generic/tee_mem.o \
		generic/tee_op.o

ccflags-y+=-iquote$(M)/core/armv7
optee-objs += core/armv7/tee_tz.o
optee-objs += core/armv7/stm-smc.o
# "smc" assembly intruction requires dedicated "armv7 secure extension"
secext := $(call as-instr,.arch_extension sec,+sec)
AFLAGS_stm-smc.o := -Wa,-march=armv7-a$(secext)
ifeq ($(CFG_TEE_DRV_DEBUGFS),1)
optee-objs += core/armv7/tee_tz_debug.o
optee-objs += generic/tee_debug.o
endif # CFG_TEE_DRV_DEBUGFS
