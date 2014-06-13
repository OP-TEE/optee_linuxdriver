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
#ifndef TEE_SERVICE_H
#define TEE_SERVICE_H

#include <linux/types.h>

#define SHM_ALLOCATE_FROM_PHYSICAL 0x100

struct tee_shm {
	struct tee_targetop *op;
	unsigned long paddr;
};

struct tee_targetop *tee_get_target(const char *devname);

struct tee_session *tee_create_session(const char *devname, bool userApi);
void tee_delete_session(struct tee_session *ts);

struct tee_shm *tee_shm_allocate(struct tee_targetop *op,
				 void *vaddr, int size, uint32_t flags);
void tee_shm_unallocate(struct tee_shm *shm);

TEEC_Result allocate_uuid(struct tee_session *ts);

TEEC_Result copy_op(struct tee_session *ts, TEEC_Operation *op,
		    unsigned long
		    tmp_allocated_memories[TEEC_CONFIG_PAYLOAD_REF_COUNT],
		    uint32_t *param_type,
		    TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT]);
TEEC_Result uncopy_op(struct tee_session *ts, TEEC_Operation *op,
		      unsigned long
		      tmp_allocated_memories[TEEC_CONFIG_PAYLOAD_REF_COUNT],
		      TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT]);
void free_temp_op(struct tee_session *ts,
		  unsigned long
		  tmp_allocated_memories[TEEC_CONFIG_PAYLOAD_REF_COUNT]);

#endif
