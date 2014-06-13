/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
#ifndef TEE_OP_H
#define TEE_OP_H

#include <linux/mutex.h>

#include "tee_client_api.h"
#include "tee_ioctl.h"
#include "tee_mem.h"

#define TEE_TZ_NAME "teetz"

/*
 * Target virtualization
 */
struct tee_session;

enum t_cmd_service_id {
	/* For TEE Client API 1.0 */
	CMD_TEEC_OPEN_SESSION = 0x11000008,
	CMD_TEEC_CLOSE_SESSION = 0x11000009,
	CMD_TEEC_INVOKE_COMMAND = 0x1100000a,
	CMD_REGISTER_RPC = 0x1100000b,	/* this is NOT a GP TEE API ! */
	CMD_SET_SEC_DDR = 0x1100000c,	/* this is NOT a GP TEE API ! */
	CMD_TEEC_CANCEL_COMMAND = 0x1100000d,
	CMD_TEEC_REGISTER_MEMORY = 0x1100000e,
	CMD_TEEC_UNREGISTER_MEMORY = 0x1100000f,

	/* Internal command */
	CMD_TEE_DEINIT_CPU = 0x11000010,
	CMD_TEE_SET_CORE_TRACE_LEVEL = 0x11000012,
	CMD_TEE_GET_CORE_TRACE_LEVEL = 0x11000013,
	CMD_TEE_SET_TA_TRACE_LEVEL = 0x11000014,
	CMD_TEE_GET_TA_TRACE_LEVEL = 0x11000015,

	CMD_REGISTER_DEF_SHM = 0x11000020,
	CMD_UNREGISTER_DEF_SHM = 0x11000021
};

struct tee_targetop {
	struct miscdevice *miscdev;
	TEEC_Result(*call_sec_world) (struct tee_session *ts,
				      enum t_cmd_service_id sec_cmd,
				      uint32_t ta_cmd,
				      uint32_t param_type,
				      TEEC_Value
				      params[TEEC_CONFIG_PAYLOAD_REF_COUNT],
				      uint32_t *origin);
	TEEC_Result(*register_shm) (unsigned long paddr, unsigned long size,
				    void **handle);
	TEEC_Result(*unregister_shm) (void *handle);
	uint32_t page_size;

	struct shm_pool *Allocator;
};

enum TEED_State {
	TEED_STATE_OPEN_DEV = 0,
	TEED_STATE_OPEN_SESSION = 1
};

/**
 * struct tee_session - The session data of an open tee device.
 * @uc: The command struct
 * @id: The session ID returned and managed by the secure world
 * @state: The current state of the session in the linux kernel.
 * @vaddr: Virtual address for the operation memrefs currently in use.
 */
struct tee_session {
	__u32 id;
	enum TEED_State state;
	struct mutex syncstate; /* Sync state mutex */

	TEEC_UUID *uuid;	/* !< The uuid for the trusted application */
	int tafd;               /* !< Trusted App SHM file */
	void *ta;		/* !< Trusted App allocated memory (in SHM) */
	__u32 tasize;		/* !< Trusted App allocated memory size */

	__u32 login;
	bool userApi;

	struct tee_targetop *op;
};

/**
 * struct tee_identity - Represents the identity of the client
 * @login: Login id
 * @uuid: UUID as defined above
 */
struct tee_identity {
	uint32_t login;
	TEEC_UUID uuid;
};

/*
 * tee_cmd_str() - return the string corresponding to this command
 * @cmd: id of the command
 * @return null if error
 */
const char *tee_cmd_str(enum t_cmd_service_id cmd);

/*
 * Definitions of messages to communicate with TEE
 * TODO: clean
 * 1st attribute of send msg must be the service
 * 1st attribute of rcv msg must be the duration
 */

/*
 * tee_msg_recv - default strcutre of TEE service output message
 */
struct tee_msg_recv {
	int duration;
	uint32_t res;
	uint32_t origin;
};

/*
 * tee_msg_send - generic part of the msg sent to the TEE
 */
struct tee_msg_send {
	unsigned int service;
};

/*
 * tee_open_session_data - input arg structure for TEE open session service
 */
struct tee_open_session_data {
	struct ta_signed_header_t *ta;
	TEEC_UUID *uuid;
	uint32_t param_types;
	TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
	struct tee_identity client_id;
	uint32_t params_flags[TEEC_CONFIG_PAYLOAD_REF_COUNT];
};

/*
 * tee_open_session_send - input arg msg for TEE open session service
 */
struct tee_open_session_send {
	struct tee_msg_send header;
	struct tee_open_session_data data;
};

/*
 * tee_open_session_recv - output arg structure for TEE open session service
 */
struct tee_open_session_recv {
	struct tee_msg_recv header;
	uint32_t sess;
	TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
};

/*
 * tee_invoke_command_data - input arg structure for TEE invoke cmd service
 */
struct tee_invoke_command_data {
	uint32_t sess;
	uint32_t cmd;
	uint32_t param_types;
	TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
	struct tee_identity client_id;
	uint32_t params_flags[TEEC_CONFIG_PAYLOAD_REF_COUNT];
};

struct tee_invoke_command_send {
	struct tee_msg_send header;
	struct tee_invoke_command_data data;
};

/*
 * tee_invoke_command_recv - output arg structure for TEE invoke cmd service
 */
struct tee_invoke_command_recv {
	struct tee_msg_recv header;
	TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
};

/*
 * tee_close_session_data - input arg structure for TEE close session service
 */
struct tee_close_session_data {
	uint32_t sess;
};

/*
 * tee_close_session_send - input arg msg for TEE close session service
 */
struct tee_close_session_send {
	struct tee_msg_send header;
	struct tee_close_session_data data;
};

/*
 * tee_cancel_command_data - input arg structure for TEE cancel service
 */
struct tee_cancel_command_data {
	uint32_t sess;
	struct tee_identity client_id;
};

/*
 * tee_cancel_command_send - input msg structure for TEE cancel service
 */
struct tee_cancel_command_send {
	struct tee_msg_send header;
	struct tee_cancel_command_data data;
};

/*
 * tee_register_rpc_send_data - input arg structure for TEE register rpc service
 */
struct tee_register_rpc_send_data {
	uint32_t fnk;
	uint32_t bf;
	uint32_t nbr_bf;
};

/*
 * tee_register_rpc_send - input msg structure for TEE register rpc service
 */
struct tee_register_rpc_send {
	struct tee_msg_send header;
	struct tee_register_rpc_send_data data;
};

/*
 * tee_register_rpc_recv_data - ouput arg structure for TEE register rpc service
 */
struct tee_register_rpc_recv_data {
	uint32_t fnk;
	uint32_t bf;
	uint32_t nbr_bf;
};

/*
 * tee_register_rpc_recv - ouput msg structure for TEE register rpc service
 */
struct tee_register_rpc_recv {
	struct tee_msg_recv header;
	struct tee_register_rpc_recv_data data;
};

/*
 * tee_register_irqfwd_xxx - (un)register callback for interrupt forwarding
 */
struct tee_register_irqfwd_send {
	struct tee_msg_send header;
	struct {
		unsigned long cb;
	} data;
};
struct tee_register_irqfwd_recv {
	struct tee_msg_recv header;
};

/*
 * tee_trace_level_data - input arg structure for TEE trace level service
 */
struct tee_trace_level_data {
	int trace_level;
};

/*
 * tee_trace_level_send - input msg structure for TEE trace level service
 */
struct tee_trace_level_send {
	struct tee_msg_send header;
	struct tee_trace_level_data data;
};

/*
 * tee_trace_level_recv - output arg structure for TEE trace level service
 */
struct tee_trace_level_recv {
	struct tee_msg_recv header;
	int trace_level;
};

/*
 * tee_core_status_out - output arg structure for TEE status service
 */
#define TEEC_STATUS_MSG_SIZE 80

struct tee_core_status_out {
	struct tee_msg_recv header;
	char raw[TEEC_STATUS_MSG_SIZE];
};

/*
 * tee_get_l2cc_mutex - input/output argument structures
 */
struct tee_get_l2cc_mutex_send {
	struct tee_msg_send header;
};
struct tee_get_l2cc_mutex_recv {
	struct tee_msg_recv header;
	struct {
		unsigned long paddr;
	} data;
};

#endif
