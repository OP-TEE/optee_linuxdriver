/*
 * Copyright (C) ST-Microelectronics 2013. All rights reserved.
 */
#ifndef _TEE_IOC_H
#define _TEE_IOC_H

#include <linux/tee_client_api.h>

#ifndef __KERNEL__
#define __user
#endif

/**
 * struct tee_cmd_io - The command sent to an open TEE device.
 * @err: Error code (as in Global Platform TEE Client API spec)
 * @origin: Origin for the error code (also from spec).
 * @cmd: The command to be executed in the trusted application.
 * @uuid: The uuid for the trusted application.
 * @data: The trusted application or memory block.
 * @data_size: The size of the trusted application or memory block.
 * @op: The cmd payload operation for the trusted application.
 * @fd_sess: The fd of TEE session
 *
 * This structure is mainly used in the Linux kernel for communication
 * with the user space.
 */
struct tee_cmd_io {
	uint32_t err;
	uint32_t origin;
	uint32_t cmd;
	struct teec_uuid __user *uuid;
	void __user *data;
	uint32_t data_size;
	struct teec_op_desc __user *op;
	int fd_sess;
};

struct tee_shm_io {
	void __user *buffer;
	size_t size;
	uint32_t flags;
	int fd_shm;
	uint8_t registered;
};

#define TEE_OPEN_SESSION_IOC		_IOWR('t', 161, struct tee_cmd_io)
#define TEE_INVOKE_COMMAND_IOC		_IOWR('t', 163, struct tee_cmd_io)
#define TEE_REQUEST_CANCELLATION_IOC	_IOWR('t', 164, struct tee_cmd_io)
#define TEE_ALLOC_SHM_IOC		_IOWR('t', 165, struct tee_shm_io)
#define TEE_GET_FD_FOR_RPC_SHM_IOC	_IOWR('t', 167, struct tee_shm_io)

#endif /* _TEE_IOC_H */
