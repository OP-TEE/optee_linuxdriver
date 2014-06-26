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
#include <linux/module.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/io.h>
#include <linux/vmalloc.h>

#include "linux/tee_kernel_api.h"

#include "tee-op.h"
#include "tee_supp_com.h"
#include "tee_service.h"

struct tee_supp_arg {
	uint32_t            res;
	uint32_t            id;
	uint32_t            datasize;
	uint32_t            reserved;
	/* uint32_t instead of uint8_t in order to ensure it is 4 aligned */
	uint32_t             data[TEE_RPC_DATA_SIZE / sizeof(uint32_t)];
};


struct tee_uuid {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t  clockSeqAndNode[8];
};


struct tee_rpc_load_ta_cmd {
	struct tee_uuid uuid;
	void *va;
};

static int alloc_ta_bin(struct tee_session *ts)
{
	struct tee_supp_arg supp_arg;
	struct tee_rpc_invoke *head;
	struct tee_rpc_load_ta_cmd *supp_cmd;
	struct tee_shm *tee_shm;
	struct device *dev = ts->op->miscdev->this_device;

	dev_dbg(dev, ">\n");
	head = (struct tee_rpc_invoke *)&supp_arg.data;
	head->cmd = TEE_RPC_LOAD_TA;
	head->res = 0;
	head->nbr_bf = 2;

	tee_shm = tee_shm_allocate(
			ts->op, NULL, sizeof(struct tee_rpc_load_ta_cmd), 0);
	if (!tee_shm)
		return -ENOMEM;

	head->cmds[0].buffer = (void *)tee_shm->paddr;

	supp_cmd = (struct tee_rpc_load_ta_cmd *)tee_shm_pool_p2v(
		dev, ts->op->Allocator, (unsigned long)head->cmds[0].buffer);
	memcpy(&supp_cmd->uuid, ts->uuid, sizeof(struct tee_uuid));
	head->cmds[0].size = sizeof(struct tee_rpc_load_ta_cmd);
	head->cmds[0].type = TEE_RPC_BUFFER;

	head->cmds[1].buffer = NULL;
	head->cmds[1].size = 0;
	head->cmds[1].type = TEE_RPC_BUFFER;

	supp_arg.datasize = sizeof(*head) - sizeof(head->cmds) +
		sizeof(head->cmds[0]) * head->nbr_bf;
	supp_arg.id = TEE_RPC_ICMD_INVOKE;
	supp_arg.res = tee_supp_cmd(
			ts->op, supp_arg.id, supp_arg.data, supp_arg.datasize);
	ts->ta = (void *)tee_shm_pool_p2v(
		dev, ts->op->Allocator, (unsigned long)head->cmds[1].buffer);
	ts->tasize = head->cmds[1].size;
	ts->tafd = head->cmds[1].fd;
	dev_dbg(dev, "ta loaded pa %p va %p fd %d\n",
		head->cmds[1].buffer, ts->ta, ts->tafd);
	dev_dbg(dev, "Going to free %p\n", head->cmds[0].buffer);
	tee_shm_unallocate(tee_shm);
	if (supp_arg.res != TEEC_SUCCESS) {
		dev_err(dev, "can't load ta\n");
		return -ENOENT;
	}

	dev_dbg(dev, "<\n");
	return 0;
}

static int free_ta_bin(struct tee_session *ts)
{
	struct tee_supp_arg supp_arg;
	struct tee_rpc_invoke *head;
	struct tee_shm *tee_shm;
	struct device *dev = ts->op->miscdev->this_device;

	dev_dbg(dev, ">\n");
	head = (struct tee_rpc_invoke *)&supp_arg.data;
	head->cmd = TEE_RPC_FREE_TA_WITH_FD;
	head->res = 0;
	head->nbr_bf = 1;

	tee_shm = tee_shm_allocate(
			ts->op, NULL, sizeof(struct tee_rpc_load_ta_cmd), 0);
	if (!tee_shm)
		return -ENOMEM;

	dev_dbg(dev, "free ta va %p fd %d\n", ts->ta, ts->tafd);
	head->cmds[0].size = ts->tasize;
	head->cmds[0].type = TEE_RPC_BUFFER;
	head->cmds[0].fd = ts->tafd;

	supp_arg.datasize = sizeof(*head) - sizeof(head->cmds) +
		sizeof(head->cmds[0]) * head->nbr_bf;
	supp_arg.id = TEE_RPC_ICMD_INVOKE;
	supp_arg.res = tee_supp_cmd(
			ts->op, supp_arg.id, supp_arg.data, supp_arg.datasize);
	tee_shm_unallocate(tee_shm);
	if (supp_arg.res != TEEC_SUCCESS) {
		dev_err(dev, "can't unload ta\n");
		return -ENOENT;
	}
	ts->ta = NULL;
	dev_dbg(dev, "<\n");
	return 0;
}


TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
	if (name == NULL)
		strcpy(context->devname, TEE_TZ_NAME);
	else
		strcpy(context->devname, name);

	return TEEC_SUCCESS;
}
EXPORT_SYMBOL(TEEC_InitializeContext);

TEEC_Result TEEC_FinalizeContext(TEEC_Context *context)
{
	return TEEC_SUCCESS;
}
EXPORT_SYMBOL(TEEC_FinalizeContext);

TEEC_Result TEEC_OpenSession(TEEC_Context *context,
			     TEEC_Session *session,
			     const TEEC_UUID *destination,
			     uint32_t connectionMethod,
			     const void *connectionData,
			     TEEC_Operation *operation,
			     uint32_t *returnOrigin)
{
	struct tee_session *ts;
	uint32_t param_type = 0x0;
	TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
	unsigned long tmp_allocated_memories[TEEC_CONFIG_PAYLOAD_REF_COUNT] = {
		0, };
	TEEC_Result ret;
	TEEC_Operation dummy_op;
	struct device *dev = NULL;

	if (operation == NULL) {
		/*
		* The code here exist because Global Platform API states that
		* it is allowed to give operation as a NULL pointer.
		* In kernel and secure world we in most cases don't want
		* this to be NULL, hence we use this dummy operation when
		* a client doesn't provide any operation.
		*/
	    memset(&dummy_op, 0, sizeof(TEEC_Operation));
	    operation = &dummy_op;
	}


	if (context == NULL || session == NULL || destination == NULL ||
	    operation == NULL || returnOrigin == NULL ||
	    connectionData != NULL)
		return TEEC_ERROR_BAD_PARAMETERS;

	*returnOrigin = TEEC_ORIGIN_API;

	ts = tee_create_session(context->devname, false);
	if (ts == NULL)
		return TEEC_ERROR_OUT_OF_MEMORY;

	dev = ts->op->miscdev->this_device;

	ret = allocate_uuid(ts);
	if (ret != TEEC_SUCCESS)
		goto error;

	*ts->uuid = *destination;

	ret = copy_op(ts, operation, tmp_allocated_memories,
			&param_type, params);
	if (ret != TEEC_SUCCESS)
		goto error;

	dev_dbg(dev, "uuid=%08x-%04x-%04x\n",
		((ts->uuid) ? ts->uuid->timeLow : 0xDEAD),
		((ts->uuid) ? ts->uuid->timeMid : 0xDEAD),
		((ts->uuid) ? ts->uuid->
		 timeHiAndVersion : 0xDEAD));

	alloc_ta_bin(ts);

	ret = ts->op->call_sec_world(ts, CMD_TEEC_OPEN_SESSION, 0,
			param_type, params, returnOrigin);

	(void)uncopy_op(ts, operation, tmp_allocated_memories, params);

	if (ret != TEEC_SUCCESS) {
		dev_err(dev,
			"TEEC_OpenSession: call_sec_world , err [%x], org [%x]\n",
			ret, *returnOrigin);
		goto error;
	}

	ts->state = TEED_STATE_OPEN_SESSION;
	session->session = ts;

	return TEEC_SUCCESS;
error:
	tee_delete_session(ts);
	return ret;
}
EXPORT_SYMBOL(TEEC_OpenSession);

void TEEC_CloseSession(TEEC_Session *session)
{
	if (session != NULL && session->session != NULL) {
		struct tee_session *ts = (struct tee_session *)session->session;

		free_ta_bin(ts);

		tee_delete_session(ts);
	}
}
EXPORT_SYMBOL(TEEC_CloseSession);

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session,
			       uint32_t commandID,
			       TEEC_Operation *operation,
			       uint32_t *returnOrigin)
{
	struct tee_session *ts;
	uint32_t param_type = 0x0;
	TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
	unsigned long tmp_allocated_memories[TEEC_CONFIG_PAYLOAD_REF_COUNT] = {
		0, };
	TEEC_Result ret;
	struct device *dev = NULL;

	if (session == NULL || operation == NULL || returnOrigin == NULL ||
	    session->session == NULL)
		return TEEC_ERROR_BAD_PARAMETERS;

	*returnOrigin = TEEC_ORIGIN_API;
	ts = (struct tee_session *)session->session;
	dev = ts->op->miscdev->this_device;

	if (ts->state != TEED_STATE_OPEN_SESSION)
		return TEEC_ERROR_BAD_PARAMETERS;

	ret = copy_op(ts, operation, tmp_allocated_memories,
			&param_type, params);
	if (ret != TEEC_SUCCESS)
		return ret;

	ret = ts->op->call_sec_world(ts, CMD_TEEC_INVOKE_COMMAND, commandID,
					param_type, params, returnOrigin);

	(void)uncopy_op(ts, operation, tmp_allocated_memories, params);

	if (ret != TEEC_SUCCESS)
		dev_err(dev,
			"TEEC_InvokeCommand: call_sec_world , err [%x], org [%x]\n",
			ret, *returnOrigin);

	return ret;
}
EXPORT_SYMBOL(TEEC_InvokeCommand);

TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *context,
		TEEC_SharedMemory *sharedMem)
{
	pr_info("TEEC_RegisterSharedMemory (vaddr=%p, size=%d)\n",
		sharedMem->buffer, (int)sharedMem->size);

	if (sharedMem == NULL || sharedMem->buffer == NULL ||
	    sharedMem->size == 0)
		return TEEC_ERROR_BAD_PARAMETERS;

	sharedMem->d.shm = NULL;
	sharedMem->registered = 1;

	/*
	 * Note: memory register in this context and allocate by previous
	 * TEEC_AllocateSharedMemory
	 * in another context will be consider as continuous by infrastructure.
	 * Elsewhere, it will be always uncontinuous.
	 *
	 * A potential optimization could be to pass flags to indicate
	 * continuity !!!!
	 */
	return 0;
}
EXPORT_SYMBOL(TEEC_RegisterSharedMemory);

TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context,
		TEEC_SharedMemory *sharedMem)
{
	struct tee_targetop *op;

	if (context == NULL)
		return TEEC_ERROR_BAD_PARAMETERS;

	op = tee_get_target(context->devname);
	if (op == NULL)
		return TEEC_ERROR_BAD_PARAMETERS;

	sharedMem->d.shm =
		tee_shm_allocate(op, NULL, sharedMem->size, sharedMem->flags);
	if (sharedMem->d.shm == NULL) {
		pr_err("TEEC_AllocateSharedMemory: tee_shm_allocate(%zu) failed\n",
		       sharedMem->size);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	pr_info("TEEC_AllocateSharedMemory (%zu) => paddr = %lx\n",
		sharedMem->size, sharedMem->d.shm->paddr);

	sharedMem->buffer =
		ioremap_nocache(sharedMem->d.shm->paddr, sharedMem->size);
	if (sharedMem->buffer == NULL) {
		pr_err("TEEC_AllocateSharedMemory: ioremap_nocache(%lx, %zu) failed\n",
		       sharedMem->d.shm->paddr, sharedMem->size);
		tee_shm_unallocate(sharedMem->d.shm);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	sharedMem->registered = 0;

	return TEEC_SUCCESS;
}
EXPORT_SYMBOL(TEEC_AllocateSharedMemory);

void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *sharedMemory)
{
	pr_info("TEEC_ReleaseSharedMemory (vaddr = %p)\n",
		sharedMemory->buffer);

	if (sharedMemory->registered == 0) {
		iounmap(sharedMemory->buffer);
		sharedMemory->buffer = NULL;
		tee_shm_unallocate(sharedMemory->d.shm);
	}
}
EXPORT_SYMBOL(TEEC_ReleaseSharedMemory);
