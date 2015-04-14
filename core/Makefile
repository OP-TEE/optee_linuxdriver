cflags-y += -Werror

obj-$(CONFIG_OPTEE) += optee.o

optee-objs:=   \
		tee_core.o  \
		tee_context.o  \
		tee_session.o  \
		tee_shm.o  \
		tee_supp_com.o  \
		tee_sysfs.o \
		tee_mutex_wait.o
