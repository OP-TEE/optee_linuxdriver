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
 */
#include <linux/module.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/io.h>
#include <linux/vmalloc.h>

#include "linux/tee_kernel_api.h"
#include "linux/tee_core.h"
#include "linux/tee_ioc.h"

#include "tee_core_priv.h"
#include "tee_shm.h"
#include "tee_supp_com.h"

#define TEE_TZ_DEVICE_NAME	"opteearm3200"

static void reset_tee_cmd(struct tee_cmd_io *cmd)
{
	cmd->fd_sess = -1;
	cmd->cmd = 0;
	cmd->uuid = NULL;
	cmd->origin = TEEC_ORIGIN_API;
	cmd->err = TEEC_SUCCESS;
	cmd->data = NULL;
	cmd->data_size = 0;
	cmd->op = NULL;
}

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
	struct tee *tee;
	struct tee_context *ctx;
	pr_cont("%s: > name=\"%s\"\n", __func__, name);

	if (!context)
		return TEEC_ERROR_BAD_PARAMETERS;

	context->fd = 0;

	if (name == NULL)
		strncpy(context->devname, TEE_TZ_DEVICE_NAME,
			sizeof(context->devname));
	else
		strncpy(context->devname, name, sizeof(context->devname));

	tee = tee_get_tee(context->devname);
	if (!tee) {
		pr_err("%s - can't get device [%s]\n", __func__, name);
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	ctx = tee_context_create(tee);
	if (IS_ERR_OR_NULL(ctx))
		return TEEC_ERROR_BAD_PARAMETERS;

	ctx->usr_client = 0;

	/* TODO fixme will not work on 64-bit platform */
	context->fd = (int)(uintptr_t)ctx;
	BUG_ON(ctx != (struct tee_context *)(uintptr_t)context->fd);

	pr_cont("%s: < ctx=%p is created\n", __func__, (void *)ctx);
	return TEEC_SUCCESS;
}
EXPORT_SYMBOL(TEEC_InitializeContext);

void TEEC_FinalizeContext(TEEC_Context *context)
{
	if (!context || !context->fd) {
		pr_err("%s - can't release context %p:[%s]\n", __func__,
		       context, (context
				 && context->devname) ? context->devname : "");
		return;
	}
	/* TODO fixme will not work on 64-bit platform */
	tee_context_destroy((struct tee_context *)(uintptr_t)context->fd);
	return;
}
EXPORT_SYMBOL(TEEC_FinalizeContext);

TEEC_Result TEEC_OpenSession(TEEC_Context *context,
			     TEEC_Session *session,
			     const TEEC_UUID *destination,
			     uint32_t connectionMethod,
			     const void *connectionData,
			     TEEC_Operation *operation,
			     uint32_t *return_origin)
{
	TEEC_Operation dummy_op;
	struct tee_cmd_io cmd;
	struct tee_session *sess;
	struct tee_context *ctx;

	if (!operation) {
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

	if (!context || !session || !destination || !operation
	    || !return_origin)
		return TEEC_ERROR_BAD_PARAMETERS;

	session->fd = 0;

	/* TODO fixme will not work on 64-bit platform */
	ctx = (struct tee_context *)(uintptr_t)context->fd;
	reset_tee_cmd(&cmd);
	cmd.op = operation;
	cmd.uuid = (TEEC_UUID *) destination;

	sess = tee_session_create_and_open(ctx, &cmd);
	if (IS_ERR_OR_NULL(sess)) {
		if (cmd.origin)
			*return_origin = cmd.origin;
		else
			*return_origin = TEEC_ORIGIN_COMMS;
		if (cmd.err)
			return cmd.err;
		else
			return TEEC_ERROR_COMMUNICATION;
	} else {
		*return_origin = cmd.origin;
		/* TODO fixme will not work on 64-bit platform */
		session->fd = (int)(uintptr_t)sess;
		BUG_ON(sess != (struct tee_session *)(uintptr_t)session->fd);
		return cmd.err;
	}
}
EXPORT_SYMBOL(TEEC_OpenSession);

void TEEC_CloseSession(TEEC_Session *session)
{
	if (session && session->fd) {
		/* TODO fixme will not work on 64-bit platform */
		struct tee_session *sess =
			(struct tee_session *)(uintptr_t)session->fd;
		tee_session_close_and_destroy(sess);
	}
}
EXPORT_SYMBOL(TEEC_CloseSession);

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session,
			       uint32_t commandID,
			       TEEC_Operation *operation,
			       uint32_t *return_origin)
{
	int ret = 0;
	struct tee_cmd_io cmd;
	struct tee_session *sess;

	if (!session || !operation || !return_origin || !session->fd)
		return TEEC_ERROR_BAD_PARAMETERS;

	/* TODO fixme will not work on 64-bit platform */
	sess = (struct tee_session *)(uintptr_t)session->fd;
	reset_tee_cmd(&cmd);
	cmd.cmd = commandID;
	cmd.op = operation;

	ret = tee_session_invoke_be(sess, &cmd);
	if (ret) {
		if (cmd.origin)
			*return_origin = cmd.origin;
		else
			*return_origin = TEEC_ORIGIN_COMMS;
		if (cmd.err)
			return cmd.err;
		else
			return TEEC_ERROR_COMMUNICATION;
	} else {
		*return_origin = cmd.origin;
		return cmd.err;
	}
}
EXPORT_SYMBOL(TEEC_InvokeCommand);

TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *context,
				      TEEC_SharedMemory *sharedMem)
{
	if (!sharedMem)
		return TEEC_ERROR_BAD_PARAMETERS;

	sharedMem->registered = 1;
	return TEEC_SUCCESS;
}
EXPORT_SYMBOL(TEEC_RegisterSharedMemory);

TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context,
				      TEEC_SharedMemory *sharedMem)
{
	struct tee_shm *tee_shm;
	struct tee_context *ctx;

	if (!context || !sharedMem)
		return TEEC_ERROR_BAD_PARAMETERS;

	/* TODO fixme will not work on 64-bit platform */
	ctx = (struct tee_context *)(uintptr_t)context->fd;

	tee_shm = tee_shm_alloc(ctx, sharedMem->size, sharedMem->flags);
	if (IS_ERR_OR_NULL(tee_shm)) {
		pr_err
		    ("TEEC_AllocateSharedMemory: tee_shm_allocate(%zu) failed\n",
		     sharedMem->size);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	pr_info("TEEC_AllocateSharedMemory (%zu) => paddr = %p, flags %x\n",
		sharedMem->size, (void *)tee_shm->paddr, tee_shm->flags);

	sharedMem->buffer = ioremap_nocache(tee_shm->paddr, sharedMem->size);
	if (!sharedMem->buffer) {
		pr_err("TEEC_AllocateSharedMemory: ioremap_nocache(%p, %zu) failed\n",
		     (void *)tee_shm->paddr, sharedMem->size);
		tee_shm_free(tee_shm);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	sharedMem->registered = 0;
	sharedMem->flags |= tee_shm->flags;
	/* TODO fixme will not work on 64-bit platform */
	sharedMem->d.fd = (int)(uintptr_t)tee_shm;
	BUG_ON(tee_shm != (struct tee_shm *)(uintptr_t)sharedMem->d.fd);

	return TEEC_SUCCESS;
}
EXPORT_SYMBOL(TEEC_AllocateSharedMemory);

void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *sharedMemory)
{
	struct tee_shm *shm;

	if (!sharedMemory)
		return;

	if (sharedMemory->registered)
		return;

	/* TODO fixme will not work on 64-bit platform */
	shm = (struct tee_shm *)(uintptr_t)sharedMemory->d.fd;

	pr_info("TEEC_ReleaseSharedMemory (vaddr = %p)\n",
		sharedMemory->buffer);

	iounmap(sharedMemory->buffer);
	sharedMemory->buffer = NULL;
	tee_shm_free(shm);
}
EXPORT_SYMBOL(TEEC_ReleaseSharedMemory);
