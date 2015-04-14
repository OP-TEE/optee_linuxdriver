/*
* Copyright (C) STMicroelectronics 2014. All rights reserved.
*
* This code is STMicroelectronics proprietary and confidential.
* Any use of the code for whatever purpose is subject to
* specific written permission of STMicroelectronics SA.
*/
#include <linux/semaphore.h>

#ifndef TEE_SUPP_COMM_H
#define TEE_SUPP_COMM_H

#define TEE_RPC_ICMD_ALLOCATE 0x1001
#define TEE_RPC_ICMD_FREE     0x1002
#define TEE_RPC_ICMD_INVOKE   0x1003

#define TEE_RPC_NBR_BUFF 1
#define TEE_RPC_DATA_SIZE 64
#define TEE_RPC_BUFFER_NUMBER 5

#define TEE_RPC_STATE_IDLE    0x00
#define TEE_RPC_STATE_ACTIVE  0x01

/* Keep aligned with optee_client (user space) */
#define TEE_RPC_BUFFER		0x00000001
#define TEE_RPC_VALUE		0x00000002
#define TEE_RPC_LOAD_TA		0x10000001
#define TEE_RPC_FREE_TA_WITH_FD	0x10000012
/*
 * Handled within the driver only
 * Keep aligned with optee_os (secure space)
 */
#define TEE_RPC_MUTEX_WAIT	0x20000000
#define TEE_RPC_WAIT		0x30000000

/* Parameters for TEE_RPC_WAIT_MUTEX above */
#define TEE_MUTEX_WAIT_SLEEP	0
#define TEE_MUTEX_WAIT_WAKEUP	1
#define TEE_MUTEX_WAIT_DELETE	2

/**
 * struct tee_rpc_bf - Contains definition of the tee com buffer
 * @state: Buffer state
 * @data: Command data
 */
struct tee_rpc_bf {
	uint32_t state;
	uint8_t data[TEE_RPC_DATA_SIZE];
};

struct tee_rpc_alloc {
	uint32_t size;	/* size of block */
	void *data;	/* pointer to data */
	void *shm;	/* pointer to an opaque data, being shm structure */
};

struct tee_rpc_free {
	void *shm;	/* pointer to an opaque data, being shm structure */
};

struct tee_rpc_cmd {
	void *buffer;
	uint32_t size;
	uint32_t type;
	int fd;
};

struct tee_rpc_invoke {
	uint32_t cmd;
	uint32_t ret;
	uint32_t num_params;
	struct tee_rpc_cmd cmds[TEE_RPC_BUFFER_NUMBER];
};

struct tee_rpc {
	struct tee_rpc_invoke comm_to_user;
	struct tee_rpc_invoke comm_from_user;
	struct semaphore data_to_user;
	struct semaphore data_from_user;
	struct mutex out_sync; /* Out sync mutex */
	struct mutex in_sync; /* In sync mutex */
	struct mutex req_sync; /* Request sync mutex */
	atomic_t  used;
};

enum teec_rpc_result {
	TEEC_RPC_OK,
	TEEC_RPC_FAIL
};

struct tee;

int tee_supp_init(struct tee *tee);
void tee_supp_deinit(struct tee *tee);

enum teec_rpc_result tee_supp_cmd(struct tee *tee,
				  uint32_t id, void *data, size_t datalen);

ssize_t tee_supp_read(struct file *filp, char __user *buffer,
		  size_t length, loff_t *offset);

ssize_t tee_supp_write(struct file *filp, const char __user *buffer,
		   size_t length, loff_t *offset);

#endif
