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
#ifndef TEE_H
#define TEE_H

/**
 * struct tee_cmd - The command sent to an open tee device.
 * @err: Error code (as in Global Platform TEE Client API spec)
 * @origin: Origin for the error code (also from spec).
 * @cmd: The command to be executed in the trusted application.
 * @uuid: The uuid for the trusted application.
 * @data: The trusted application or memory block.
 * @data_size: The size of the trusted application or memory block.
 * @op: The payload for the trusted application.
 *
 * This structure is mainly used in the Linux kernel for communication
 * with the user space.
 */
struct tee_cmd {
	TEEC_Result     err;
	uint32_t        origin;
	uint32_t        cmd;
	TEEC_UUID       *uuid;
	void            *data;
	uint32_t        data_size;
	TEEC_Operation  *op;
};

#define TEE_OPEN_SESSION_IOC		_IOWR('t', 161, struct tee_cmd)
#define TEE_CLOSE_SESSION_IOC		_IOWR('t', 162, unsigned long)
#define TEE_INVOKE_COMMAND_IOC		_IOWR('t', 163, struct tee_cmd)
#define TEE_REQUEST_CANCELLATION_IOC	_IOWR('t', 164, struct tee_cmd)
#define TEE_ALLOC_SHM_IOC		_IOWR('t', 165, TEEC_SharedMemory)

#endif
