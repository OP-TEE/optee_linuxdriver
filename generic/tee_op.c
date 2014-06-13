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
#include "tee-op.h"

static const char CMD_TEEC_OPEN_SESSION_STR[] = "OPEN_SESSION   ";

static const char CMD_TEEC_CLOSE_SESSION_STR[] = "CLOSE_SESSION  ";
static const char CMD_TEEC_INVOKE_COMMAND_STR[] = "INVOKE_COMMAND ";
static const char CMD_REGISTER_RPC_STR[] = "REGISTER_RPC   ";
static const char CMD_SET_SEC_DDR_STR[] = "SET_SEC_DDR    ";
static const char CMD_TEEC_CANCEL_COMMAND_STR[] = "CANCEL_COMMAND ";

static const char CMD_TEE_DEINIT_CPU_STR[] = "DEINIT_CPU     ";
static const char CMD_TEE_SET_CORE_TRACE_LEVEL_STR[] =
							"SET_CORE_TRACE_LEVEL";
static const char CMD_TEE_GET_CORE_TRACE_LEVEL_STR[] =
							"GET_CORE_TRACE_LEVEL";
static const char CMD_TEE_SET_TA_TRACE_LEVEL_STR[] = "SET_TA_TRACE_LEVEL";
static const char CMD_TEE_GET_TA_TRACE_LEVEL_STR[] = "GET_TA_TRACE_LEVEL";

static const char CMD_REGISTER_DEF_SHM_STR[] = "REGISTER_DEF_SHM";
static const char CMD_UNREGISTER_DEF_SHM_STR[] = "UNREGISTER_DEF_SHM";

const char *tee_cmd_str(enum t_cmd_service_id cmd)
{
	switch (cmd) {
	case CMD_TEEC_OPEN_SESSION:
		return CMD_TEEC_OPEN_SESSION_STR;

	case CMD_TEEC_CLOSE_SESSION:
		return CMD_TEEC_CLOSE_SESSION_STR;

	case CMD_TEEC_INVOKE_COMMAND:
		return CMD_TEEC_INVOKE_COMMAND_STR;

	case CMD_REGISTER_RPC:
		return CMD_REGISTER_RPC_STR;

	case CMD_SET_SEC_DDR:
		return CMD_SET_SEC_DDR_STR;

	case CMD_TEEC_CANCEL_COMMAND:
		return CMD_TEEC_CANCEL_COMMAND_STR;

	case CMD_TEE_DEINIT_CPU:
		return CMD_TEE_DEINIT_CPU_STR;

	case CMD_TEE_SET_CORE_TRACE_LEVEL:
		return CMD_TEE_SET_CORE_TRACE_LEVEL_STR;

	case CMD_TEE_GET_CORE_TRACE_LEVEL:
		return CMD_TEE_GET_CORE_TRACE_LEVEL_STR;

	case CMD_TEE_SET_TA_TRACE_LEVEL:
		return CMD_TEE_SET_TA_TRACE_LEVEL_STR;

	case CMD_TEE_GET_TA_TRACE_LEVEL:
		return CMD_TEE_GET_TA_TRACE_LEVEL_STR;

	case CMD_REGISTER_DEF_SHM:
		return CMD_REGISTER_DEF_SHM_STR;
	case CMD_UNREGISTER_DEF_SHM:
		return CMD_UNREGISTER_DEF_SHM_STR;

	default:
		return NULL;
	}
}
