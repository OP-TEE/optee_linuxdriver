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
/* #define DEBUG */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/uuid.h>

#include <linux/tee_core.h>
#include <linux/tee_ioc.h>

#include <tee_shm.h>
#include <tee_supp_com.h>
#include <tee_mutex_wait.h>
#include <tee_wait_queue.h>

#include <arm_common/optee_msg.h>
#include <arm_common/optee_smc.h>

#include "tee_mem.h"
#include "tee_tz_op.h"
#include "tee_tz_priv.h"
#include "handle.h"

#define _TEE_TZ_NAME "armtz"
#define DEV (ptee->tee->dev)

/* #define TEE_STRESS_OUTERCACHE_FLUSH */

/* magic config: bit 1 is set, Secure TEE shall handler NSec IRQs */
#define SEC_ROM_NO_FLAG_MASK	0x0000
#define SEC_ROM_IRQ_ENABLE_MASK	0x0001
#define SEC_ROM_DEFAULT		SEC_ROM_IRQ_ENABLE_MASK
#define TEE_RETURN_BUSY		0x3
#define ALLOC_ALIGN		SZ_4K

#define CAPABLE(tee) !(tee->conf & TEE_CONF_FW_NOT_CAPABLE)

static struct tee_tz *tee_tz;

/* Temporary workaround until we're only using post 3.13 kernels */
#ifdef ioremap_cached
#define ioremap_cache	ioremap_cached
#endif


/*******************************************************************
 * Calling TEE
 *******************************************************************/

static void e_lock_teez(struct tee_tz *ptee)
{
	mutex_lock(&ptee->mutex);
}

static void e_lock_wait_completion_teez(struct tee_tz *ptee)
{
	/*
	 * Release the lock until "something happens" and then reacquire it
	 * again.
	 *
	 * This is needed when TEE returns "busy" and we need to try again
	 * later.
	 */
	ptee->c_waiters++;
	mutex_unlock(&ptee->mutex);
	/*
	 * Wait at most one second. Secure world is normally never busy
	 * more than that so we should normally never timeout.
	 */
	wait_for_completion_timeout(&ptee->c, HZ);
	mutex_lock(&ptee->mutex);
	ptee->c_waiters--;
}

static void e_unlock_teez(struct tee_tz *ptee)
{
	/*
	 * If at least one thread is waiting for "something to happen" let
	 * one thread know that "something has happened".
	 */
	if (ptee->c_waiters)
		complete(&ptee->c);
	mutex_unlock(&ptee->mutex);
}

static struct tee_shm *handle_rpc_alloc(struct tee_tz *ptee, size_t size)
{
	struct tee_rpc_alloc rpc_alloc;

	rpc_alloc.size = size;
	tee_supp_cmd(ptee->tee, TEE_RPC_ICMD_ALLOCATE,
		     &rpc_alloc, sizeof(rpc_alloc));
	return rpc_alloc.shm;
}

static void handle_rpc_free(struct tee_tz *ptee, struct tee_shm *shm)
{
	struct tee_rpc_free rpc_free;

	if (!shm)
		return;
	rpc_free.shm = shm;
	tee_supp_cmd(ptee->tee, TEE_RPC_ICMD_FREE, &rpc_free, sizeof(rpc_free));
}

static void handle_rpc_func_cmd_wait_queue(struct tee_tz *ptee,
						struct optee_msg_arg *arg)
{
	struct optee_msg_param *params;

	if (arg->num_params != 1)
		goto bad;

	params = OPTEE_MSG_GET_PARAMS(arg);

	if ((params->attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
			OPTEE_MSG_ATTR_TYPE_VALUE_INPUT)
		goto bad;

	switch (params->u.value.a) {
	case OPTEE_MSG_RPC_WAIT_QUEUE_SLEEP:
		tee_wait_queue_sleep(DEV, &ptee->wait_queue, params->u.value.b);
		break;
	case OPTEE_MSG_RPC_WAIT_QUEUE_WAKEUP:
		tee_wait_queue_wakeup(DEV, &ptee->wait_queue,
				      params->u.value.b);
		break;
	default:
		goto bad;
	}

	arg->ret = TEEC_SUCCESS;
	return;
bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}



static void handle_rpc_func_cmd_wait(struct optee_msg_arg *arg)
{
	struct optee_msg_param *params;
	u32 msec_to_wait;

	if (arg->num_params != 1)
		goto bad;

	params = OPTEE_MSG_GET_PARAMS(arg);
	msec_to_wait = params[0].u.value.a;

	/* set task's state to interruptible sleep */
	set_current_state(TASK_INTERRUPTIBLE);

	/* take a nap */
	schedule_timeout(msecs_to_jiffies(msec_to_wait));

	arg->ret = TEEC_SUCCESS;
	return;
bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_rpc_func_cmd_load_ta(struct tee_tz *ptee,
			struct optee_msg_arg *arg)
{
	struct optee_msg_param *params;
	struct tee_rpc_invoke inv;
	struct tee_shm *shm;

	params = OPTEE_MSG_GET_PARAMS(arg);
	if (arg->num_params != 2)
		goto bad_args;
	if ((params[0].attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
			OPTEE_MSG_ATTR_TYPE_VALUE_INPUT)
		goto bad_args;
	if ((params[1].attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
			OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT)
		goto bad_args;


	shm = handle_rpc_alloc(ptee, sizeof(uuid_le));
	if (!shm) {
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;
		return;
	}

	memset(&inv, 0, sizeof(inv));
	memcpy(shm->kaddr, &params[0].u.value, sizeof(uuid_le));
	inv.cmds[0].buffer = (void *)(uintptr_t)shm->paddr;
	inv.cmds[0].size = sizeof(uuid_le);
	inv.cmds[0].type = TEE_RPC_BUFFER;
	inv.cmds[1].buffer = (void *)(uintptr_t)params[1].u.tmem.buf_ptr;
	inv.cmds[1].size = params[1].u.tmem.size;
	inv.cmds[1].type = TEE_RPC_BUFFER;
	inv.cmd = TEE_RPC_LOAD_TA2;
	inv.res = TEEC_ERROR_NOT_IMPLEMENTED;
	inv.nbr_bf = 2;

	tee_supp_cmd(ptee->tee, TEE_RPC_ICMD_INVOKE, &inv, sizeof(inv));
	arg->ret = inv.res;

	handle_rpc_free(ptee, shm);

	params[1].u.tmem.size = inv.cmds[1].size;
	return;
bad_args:
	arg->ret = TEEC_ERROR_GENERIC;
}

static void handle_rpc_func_cmd_fs(struct tee_tz *ptee,
			struct optee_msg_arg *arg)
{
	struct optee_msg_param *params;
	struct tee_rpc_invoke inv;

	params = OPTEE_MSG_GET_PARAMS(arg);
	if (arg->num_params != 1)
		goto bad_args;
	if ((params[0].attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
			OPTEE_MSG_ATTR_TYPE_TMEM_INOUT)
		goto bad_args;

	memset(&inv, 0, sizeof(inv));
	inv.cmds[0].buffer = (void *)(uintptr_t)params[0].u.tmem.buf_ptr;
	inv.cmds[0].size = params[0].u.tmem.size;
	inv.cmds[0].type = TEE_RPC_BUFFER;
	inv.cmd = TEE_RPC_FS;
	inv.res = TEEC_ERROR_NOT_IMPLEMENTED;
	inv.nbr_bf = 1;

	tee_supp_cmd(ptee->tee, TEE_RPC_ICMD_INVOKE, &inv, sizeof(inv));
	arg->ret = inv.res;

	params[0].u.tmem.size = inv.cmds[0].size;
	return;
bad_args:
	arg->ret = TEEC_ERROR_GENERIC;
}

static void handle_rpc_func_cmd_get_time(struct optee_msg_arg *arg)
{
	struct optee_msg_param *params;
	struct timespec ts;

	if (arg->num_params != 1)
		goto bad;
	params = OPTEE_MSG_GET_PARAMS(arg);
	if ((params->attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
			OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT)
		goto bad;

	getnstimeofday(&ts);
	params->u.value.a = ts.tv_sec;
	params->u.value.b = ts.tv_nsec;

	arg->ret = TEEC_SUCCESS;
	return;
bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_rpc_func_cmd_shm_alloc(struct tee_tz *ptee,
                        struct optee_msg_arg *arg)
{
	struct optee_msg_param *params = OPTEE_MSG_GET_PARAMS(arg);
	struct tee_shm *shm;
	size_t sz;
	size_t n;

	arg->ret_origin = TEEC_ORIGIN_COMMS;

	if (!arg->num_params ||
	    params->attr != OPTEE_MSG_ATTR_TYPE_VALUE_INPUT) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	for (n = 1; n < arg->num_params; n++) {
		if (params[n].attr != OPTEE_MSG_ATTR_TYPE_NONE) {
			arg->ret = TEEC_ERROR_BAD_PARAMETERS;
			return;
		}
	}

	switch (params->u.value.a) {
	case OPTEE_MSG_RPC_SHM_TYPE_APPL:
	case OPTEE_MSG_RPC_SHM_TYPE_KERNEL:
		break;
	default:
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}
	sz = params->u.value.b;
	shm = handle_rpc_alloc(ptee, sz);
	if (IS_ERR_OR_NULL(shm)) {
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;
		return;
	}

	params[0].attr = OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT;
	params[0].u.tmem.buf_ptr = shm->paddr;
	params[0].u.tmem.size = sz;
	params[0].u.tmem.shm_ref = (unsigned long)shm;
	arg->ret = TEEC_SUCCESS;
}


static void handle_rpc_func_cmd(struct tee_tz *ptee, struct optee_msg_arg *arg)
{
	switch (arg->cmd) {
	case OPTEE_MSG_RPC_CMD_GET_TIME:
		handle_rpc_func_cmd_get_time(arg);
		break;
	case OPTEE_MSG_RPC_CMD_WAIT_QUEUE:
		handle_rpc_func_cmd_wait_queue(ptee, arg);
		break;
	case OPTEE_MSG_RPC_CMD_SUSPEND:
		handle_rpc_func_cmd_wait(arg);
		break;
	case OPTEE_MSG_RPC_CMD_SHM_ALLOC:
		handle_rpc_func_cmd_shm_alloc(ptee, arg);
		break;
	case OPTEE_MSG_RPC_CMD_LOAD_TA:
		handle_rpc_func_cmd_load_ta(ptee, arg);
		break;
	case OPTEE_MSG_RPC_CMD_FS:
		handle_rpc_func_cmd_fs(ptee, arg);
		break;
	default:
		arg->ret = TEEC_ERROR_NOT_IMPLEMENTED;
	}
}

static void reg_pair_from_64(u32 *reg0, u32 *reg1, u64 val)
{
	*reg0 = val >> 32;
	*reg1 = val;
}

static void *reg_pair_to_ptr(u32 reg0, u32 reg1)
{
	return (void *)(unsigned long)(((u64)reg0 << 32) | reg1);
}


static u32 handle_rpc(struct tee_tz *ptee, struct smc_param *param)
{
	struct tee_shm *shm;

	switch (OPTEE_SMC_RETURN_GET_RPC_FUNC(param->a0)) {
	case OPTEE_SMC_RPC_FUNC_ALLOC:
		shm = handle_rpc_alloc(ptee, param->a1);
		if (!IS_ERR_OR_NULL(shm)) {
			reg_pair_from_64(&param->a1, &param->a2, shm->paddr);
			reg_pair_from_64(&param->a4, &param->a5,
					 (unsigned long)shm);
		} else {
			param->a1 = 0;
			param->a2 = 0;
			param->a4 = 0;
			param->a5 = 0;
		}
		break;
	case OPTEE_SMC_RPC_FUNC_FREE:
		shm = reg_pair_to_ptr(param->a1, param->a2);
		handle_rpc_free(ptee, shm);
		break;
	case OPTEE_SMC_RPC_FUNC_IRQ:
		break;
	case OPTEE_SMC_RPC_FUNC_CMD:
		shm = reg_pair_to_ptr(param->a1, param->a2);
		handle_rpc_func_cmd(ptee, shm->kaddr);
		break;
	default:
		dev_warn(DEV, "Unknown RPC func 0x%x\n",
			 (u32)OPTEE_SMC_RETURN_GET_RPC_FUNC(param->a0));
		break;
	}

	return OPTEE_SMC_CALL_RETURN_FROM_RPC;
}

static void call_tee(struct tee_tz *ptee,
			uintptr_t parg, struct optee_msg_arg *arg)
{
	u32 ret;
	u32 funcid;
	struct smc_param param = { 0 };

	funcid = OPTEE_SMC_CALL_WITH_ARG;
	reg_pair_from_64(&param.a1, &param.a2, parg);

	e_lock_teez(ptee);
	while (true) {
		param.a0 = funcid;

		tee_smc_call(&param);
		ret = param.a0;

		if (ret == OPTEE_SMC_RETURN_ETHREAD_LIMIT) {
			/*
			 * Since secure world is out of threads, release the
			 * lock we had when entering this function and wait
			 * for "something to happen" (something else to
			 * exit from secure world and needed resources may
			 * have become available).
			 */
			e_lock_wait_completion_teez(ptee);
		} else if (OPTEE_SMC_RETURN_IS_RPC(ret)) {
			/* Process the RPC. */
			e_unlock_teez(ptee);
			funcid = handle_rpc(ptee, &param);
			e_lock_teez(ptee);
		} else {
			break;
		}
	}
	e_unlock_teez(ptee);

	switch (ret) {
	case OPTEE_SMC_RETURN_UNKNOWN_FUNCTION:
		break;
	case OPTEE_SMC_RETURN_OK:
		/* arg->ret set by secure world */
		break;
	default:
		/* Should not happen */
		arg->ret = TEEC_ERROR_COMMUNICATION;
		arg->ret_origin = TEEC_ORIGIN_COMMS;
		break;
	}
}

/*******************************************************************
 * TEE service invoke formating
 *******************************************************************/

/* allocate tee service argument buffer and return virtual address */
static void *alloc_tee_arg(struct tee_tz *ptee, unsigned long *p, size_t l)
{
	void *vaddr;
	dev_dbg(DEV, ">\n");
	BUG_ON(!CAPABLE(ptee->tee));

	if ((p == NULL) || (l == 0))
		return NULL;

	/* assume a 4 bytes aligned is sufficient */
	*p = tee_shm_pool_alloc(DEV, ptee->shm_pool, l, ALLOC_ALIGN);
	if (*p == 0)
		return NULL;

	vaddr = tee_shm_pool_p2v(DEV, ptee->shm_pool, *p);

	dev_dbg(DEV, "< %p\n", vaddr);

	return vaddr;
}

/* free tee service argument buffer (from its physical address) */
static void free_tee_arg(struct tee_tz *ptee, unsigned long p)
{
	dev_dbg(DEV, ">\n");
	BUG_ON(!CAPABLE(ptee->tee));

	if (p)
		tee_shm_pool_free(DEV, ptee->shm_pool, p, 0);

	dev_dbg(DEV, "<\n");
}

static uint32_t get_cache_attrs(struct tee_tz *ptee)
{
	return OPTEE_MSG_ATTR_CACHE_PREDEFINED << OPTEE_MSG_ATTR_CACHE_SHIFT;
}

static uint32_t param_type_teec2teesmc(uint8_t type)
{
	switch (type) {
	case TEEC_NONE:
		return OPTEE_MSG_ATTR_TYPE_NONE;
	case TEEC_VALUE_INPUT:
		return OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	case TEEC_VALUE_OUTPUT:
		return OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT;
	case TEEC_VALUE_INOUT:
		return OPTEE_MSG_ATTR_TYPE_VALUE_INOUT;
	case TEEC_MEMREF_TEMP_INPUT:
	case TEEC_MEMREF_PARTIAL_INPUT:
		return OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
	case TEEC_MEMREF_TEMP_OUTPUT:
	case TEEC_MEMREF_PARTIAL_OUTPUT:
		return OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT;
	case TEEC_MEMREF_WHOLE:
	case TEEC_MEMREF_TEMP_INOUT:
	case TEEC_MEMREF_PARTIAL_INOUT:
		return OPTEE_MSG_ATTR_TYPE_TMEM_INOUT;
	default:
		WARN_ON(true);
		return 0;
	}
}

static void set_params(struct tee_tz *ptee,
		struct optee_msg_param params[TEEC_CONFIG_PAYLOAD_REF_COUNT],
		uint32_t param_types,
		struct tee_data *data)
{
	size_t n;
	struct tee_shm *shm;
	TEEC_Value *value;

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		uint32_t type = TEEC_PARAM_TYPE_GET(param_types, n);

		params[n].attr = param_type_teec2teesmc(type);
		if (params[n].attr == OPTEE_MSG_ATTR_TYPE_NONE)
			continue;
		if (params[n].attr <= OPTEE_MSG_ATTR_TYPE_VALUE_INOUT) {
			value = (TEEC_Value *)&data->params[n];
			params[n].u.value.a = value->a;
			params[n].u.value.b = value->b;
			continue;
		}
		shm = data->params[n].shm;
		params[n].attr |= get_cache_attrs(ptee);
		params[n].u.tmem.buf_ptr = shm->paddr;
		params[n].u.tmem.size = shm->size_req;
		params[n].u.tmem.shm_ref = (unsigned long)shm;
	}
}

static void get_params(struct tee_data *data,
		struct optee_msg_param params[TEEC_CONFIG_PAYLOAD_REF_COUNT])
{
	size_t n;
	struct tee_shm *shm;
	TEEC_Value *value;

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		if (params[n].attr == OPTEE_MSG_ATTR_TYPE_NONE)
			continue;
		if (params[n].attr <= OPTEE_MSG_ATTR_TYPE_VALUE_INOUT) {
			value = &data->params[n].value;
			value->a = params[n].u.value.a;
			value->b = params[n].u.value.b;
			continue;
		}
		shm = data->params[n].shm;
		shm->size_req = params[n].u.tmem.size;
	}
}


/*
 * tee_open_session - invoke TEE to open a GP TEE session
 */
static int tz_open(struct tee_session *sess, struct tee_cmd *cmd)
{
	struct tee *tee;
	struct tee_tz *ptee;
	int ret = 0;

	struct optee_msg_arg *arg;
	struct optee_msg_param *params;
	uintptr_t parg;
	TEEC_UUID *uuid;

	BUG_ON(!sess->ctx->tee);
	BUG_ON(!sess->ctx->tee->priv);
	tee = sess->ctx->tee;
	ptee = tee->priv;

	if (cmd->uuid)
		uuid = cmd->uuid->kaddr;
	else
		uuid = NULL;

	dev_dbg(tee->dev, "> ta kaddr %p, uuid=%08x-%04x-%04x\n",
		(cmd->ta) ? cmd->ta->kaddr : NULL,
		((uuid) ? uuid->timeLow : 0xDEAD),
		((uuid) ? uuid->timeMid : 0xDEAD),
		((uuid) ? uuid->timeHiAndVersion : 0xDEAD));

	if (!CAPABLE(ptee->tee)) {
		dev_dbg(tee->dev, "< not capable\n");
		return -EBUSY;
	}

	arg = alloc_tee_arg(ptee, &parg, OPTEE_MSG_GET_ARG_SIZE(
				TEEC_CONFIG_PAYLOAD_REF_COUNT + 2));

	if ((arg == NULL)) {
		free_tee_arg(ptee, parg);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	memset(arg, 0, sizeof(*arg));
	arg->num_params = TEEC_CONFIG_PAYLOAD_REF_COUNT + 2;
	params = OPTEE_MSG_GET_PARAMS(arg);

	arg->cmd = OPTEE_MSG_CMD_OPEN_SESSION;
	arg->cancel_id = 0;

	params[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT |
			 OPTEE_MSG_ATTR_META;
	params[1].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT |
			 OPTEE_MSG_ATTR_META;

	memset(&params[0].u.value, 0, sizeof(params[0].u.value));
	memset(&params[1].u.value, 0, sizeof(params[1].u.value));
	if (uuid)
		memcpy(&params[0].u.value, uuid, sizeof(*uuid));
	params[1].u.value.c = TEEC_LOGIN_PUBLIC;

	set_params(ptee, params + 2, cmd->param.type, &cmd->param);

	call_tee(ptee, parg, arg);

	get_params(&cmd->param, params + 2);

	if (arg->ret != TEEC_ERROR_COMMUNICATION) {
		sess->sessid = arg->session;
		cmd->err = arg->ret;
		cmd->origin = arg->ret_origin;
	} else
		ret = -EBUSY;

	free_tee_arg(ptee, parg);

	dev_dbg(DEV, "< %x:%d\n", arg->ret, ret);
	return ret;
}

/*
 * tee_invoke_command - invoke TEE to invoke a GP TEE command
 */
static int tz_invoke(struct tee_session *sess, struct tee_cmd *cmd)
{
	struct tee *tee;
	struct tee_tz *ptee;
	int ret = 0;

	struct optee_msg_arg *arg;
	uintptr_t parg;
	struct optee_msg_param *params;

	BUG_ON(!sess->ctx->tee);
	BUG_ON(!sess->ctx->tee->priv);
	tee = sess->ctx->tee;
	ptee = tee->priv;

	dev_dbg(DEV, "> sessid %x cmd %x type %x\n",
		sess->sessid, cmd->cmd, cmd->param.type);

	if (!CAPABLE(tee)) {
		dev_dbg(tee->dev, "< not capable\n");
		return -EBUSY;
	}

	arg = (typeof(arg))alloc_tee_arg(ptee, &parg,
			OPTEE_MSG_GET_ARG_SIZE(TEEC_CONFIG_PAYLOAD_REF_COUNT));
	if (!arg) {
		free_tee_arg(ptee, parg);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	memset(arg, 0, sizeof(*arg));
	arg->num_params = TEEC_CONFIG_PAYLOAD_REF_COUNT;
	params = OPTEE_MSG_GET_PARAMS(arg);

	arg->cmd = OPTEE_MSG_CMD_INVOKE_COMMAND;
	arg->session = sess->sessid;
	arg->cancel_id = 0;
	arg->func = cmd->cmd;

	set_params(ptee, params, cmd->param.type, &cmd->param);

	call_tee(ptee, parg, arg);

	get_params(&cmd->param, params);

	if (arg->ret != TEEC_ERROR_COMMUNICATION) {
		cmd->err = arg->ret;
		cmd->origin = arg->ret_origin;
	} else
		ret = -EBUSY;

	free_tee_arg(ptee, parg);

	dev_dbg(DEV, "< %x:%d\n", arg->ret, ret);
	return ret;
}

/*
 * tee_cancel_command - invoke TEE to cancel a GP TEE command
 */
static int tz_cancel(struct tee_session *sess, struct tee_cmd *cmd)
{
	struct tee *tee;
	struct tee_tz *ptee;
	int ret = 0;

	struct optee_msg_arg *arg;
	uintptr_t parg;

	BUG_ON(!sess->ctx->tee);
	BUG_ON(!sess->ctx->tee->priv);
	tee = sess->ctx->tee;
	ptee = tee->priv;

	dev_dbg(DEV, "cancel on sessid=%08x\n", sess->sessid);

	arg = alloc_tee_arg(ptee, &parg, OPTEE_MSG_GET_ARG_SIZE(0));
	if (arg == NULL) {
		free_tee_arg(ptee, parg);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	memset(arg, 0, sizeof(*arg));
	arg->cmd = OPTEE_MSG_CMD_CANCEL;
	arg->session = sess->sessid;
	arg->cancel_id = 0;

	call_tee(ptee, parg, arg);

	if (arg->ret == TEEC_ERROR_COMMUNICATION)
		ret = -EBUSY;

	free_tee_arg(ptee, parg);

	dev_dbg(DEV, "< %x:%d\n", arg->ret, ret);
	return ret;
}

/*
 * tee_close_session - invoke TEE to close a GP TEE session
 */
static int tz_close(struct tee_session *sess)
{
	struct tee *tee;
	struct tee_tz *ptee;
	int ret = 0;

	struct optee_msg_arg *arg;
	uintptr_t parg;

	BUG_ON(!sess->ctx->tee);
	BUG_ON(!sess->ctx->tee->priv);
	tee = sess->ctx->tee;
	ptee = tee->priv;

	dev_dbg(DEV, "close on sessid=%08x\n", sess->sessid);

	if (!CAPABLE(tee)) {
		dev_dbg(tee->dev, "< not capable\n");
		return -EBUSY;
	}

	arg = alloc_tee_arg(ptee, &parg, OPTEE_MSG_GET_ARG_SIZE(0));
	if (arg == NULL) {
		free_tee_arg(ptee, parg);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	dev_dbg(DEV, "> [%x]\n", sess->sessid);

	memset(arg, 0, sizeof(*arg));
	arg->cmd = OPTEE_MSG_CMD_CLOSE_SESSION;
	arg->session = sess->sessid;

	call_tee(ptee, parg, arg);

	if (arg->ret == TEEC_ERROR_COMMUNICATION)
		ret = -EBUSY;

	free_tee_arg(ptee, parg);

	dev_dbg(DEV, "< %x:%d\n", arg->ret, ret);
	return ret;
}

static struct tee_shm *tz_alloc(struct tee *tee, size_t size, uint32_t flags)
{
	struct tee_shm *shm = NULL;
	struct tee_tz *ptee;
	size_t size_aligned;
	BUG_ON(!tee->priv);
	ptee = tee->priv;

	dev_dbg(DEV, "%s: s=%d,flags=0x%08x\n", __func__, (int)size, flags);

/*	comment due to #6357
 *	if ( (flags & ~(tee->shm_flags | TEE_SHM_MAPPED
 *	| TEE_SHM_TEMP | TEE_SHM_FROM_RPC)) != 0 ) {
		dev_err(tee->dev, "%s: flag parameter is invalid\n", __func__);
		return ERR_PTR(-EINVAL);
	}*/

	size_aligned = ((size / SZ_4K) + 1) * SZ_4K;
	if (unlikely(size_aligned == 0)) {
		dev_err(DEV, "[%s] requested size too big\n", __func__);
		return NULL;
	}

	shm = devm_kzalloc(tee->dev, sizeof(struct tee_shm), GFP_KERNEL);
	if (!shm) {
		dev_err(tee->dev, "%s: kzalloc failed\n", __func__);
		return ERR_PTR(-ENOMEM);
	}

	shm->size_alloc = ((size / SZ_4K) + 1) * SZ_4K;
	shm->size_req = size;
	shm->paddr = tee_shm_pool_alloc(tee->dev, ptee->shm_pool,
					shm->size_alloc, ALLOC_ALIGN);
	if (!shm->paddr) {
		dev_err(tee->dev, "%s: cannot alloc memory, size 0x%lx\n",
			__func__, (unsigned long)shm->size_alloc);
		devm_kfree(tee->dev, shm);
		return ERR_PTR(-ENOMEM);
	}
	shm->kaddr = tee_shm_pool_p2v(tee->dev, ptee->shm_pool, shm->paddr);
	if (!shm->kaddr) {
		dev_err(tee->dev, "%s: p2v(%p)=0\n", __func__,
			(void *)shm->paddr);
		tee_shm_pool_free(tee->dev, ptee->shm_pool, shm->paddr, NULL);
		devm_kfree(tee->dev, shm);
		return ERR_PTR(-EFAULT);
	}
	shm->flags = flags;
	if (ptee->shm_cached)
		shm->flags |= TEE_SHM_CACHED;

	dev_dbg(tee->dev, "%s: kaddr=%p, paddr=%p, shm=%p, size %x:%x\n",
		__func__, shm->kaddr, (void *)shm->paddr, shm,
		(unsigned int)shm->size_req, (unsigned int)shm->size_alloc);

	return shm;
}

static void tz_free(struct tee_shm *shm)
{
	size_t size;
	int ret;
	struct tee *tee;
	struct tee_tz *ptee;

	BUG_ON(!shm->tee);
	BUG_ON(!shm->tee->priv);
	tee = shm->tee;
	ptee = tee->priv;

	dev_dbg(tee->dev, "%s: shm=%p\n", __func__, shm);

	ret = tee_shm_pool_free(tee->dev, ptee->shm_pool, shm->paddr, &size);
	if (!ret) {
		devm_kfree(tee->dev, shm);
		shm = NULL;
	}
}

static int tz_shm_inc_ref(struct tee_shm *shm)
{
	struct tee *tee;
	struct tee_tz *ptee;

	BUG_ON(!shm->tee);
	BUG_ON(!shm->tee->priv);
	tee = shm->tee;
	ptee = tee->priv;

	return tee_shm_pool_incref(tee->dev, ptee->shm_pool, shm->paddr);
}

/******************************************************************************/
/*
static void tee_get_status(struct tee_tz *ptee)
{
	TEEC_Result ret;
	struct tee_msg_send *arg;
	struct tee_core_status_out *res;
	unsigned long parg, pres;

	if (!CAPABLE(ptee->tee))
		return;

	arg = (typeof(arg))alloc_tee_arg(ptee, &parg, sizeof(*arg));
	res = (typeof(res))alloc_tee_arg(ptee, &pres, sizeof(*res));

	if ((arg == NULL) || (res == NULL)) {
		dev_err(DEV, "TZ outercache mutex error: alloc shm failed\n");
		goto out;
	}

	memset(arg, 0, sizeof(*arg));
	memset(res, 0, sizeof(*res));
	arg->service = ISSWAPI_TEE_GET_CORE_STATUS;
	ret = send_and_wait(ptee, ISSWAPI_TEE_GET_CORE_STATUS, SEC_ROM_DEFAULT,
				parg, pres);
	if (ret != TEEC_SUCCESS) {
		dev_warn(DEV, "get statuc failed\n");
		goto out;
	}

	pr_info("TEETZ Firmware status:\n");
	pr_info("%s", res->raw);

out:
	free_tee_arg(ptee, parg);
	free_tee_arg(ptee, pres);
}*/

#ifdef CONFIG_OUTER_CACHE
/*
 * Synchronised outer cache maintenance support
 */
#ifndef CONFIG_ARM_TZ_SUPPORT
/* weak outer_tz_mutex in case not supported by kernel */
bool __weak outer_tz_mutex(unsigned long *p)
{
	pr_err("weak outer_tz_mutex");
	if (p != NULL)
		return false;
	return true;
}
#endif

/* register_outercache_mutex - Negotiate/Disable outer cache shared mutex */
static int register_outercache_mutex(struct tee_tz *ptee, bool reg)
{
	unsigned long *vaddr = NULL;
	int ret = 0;
	struct smc_param param;
	uintptr_t paddr = 0;

	dev_dbg(ptee->tee->dev, ">\n");
	BUG_ON(!CAPABLE(ptee->tee));

	if ((reg == true) && (ptee->tz_outer_cache_mutex != NULL)) {
		dev_err(DEV, "outer cache shared mutex already registered\n");
		return -EINVAL;
	}
	if ((reg == false) && (ptee->tz_outer_cache_mutex == NULL))
		return 0;

	mutex_lock(&ptee->mutex);

	if (reg == false) {
		vaddr = ptee->tz_outer_cache_mutex;
		ptee->tz_outer_cache_mutex = NULL;
		goto out;
	}

	memset(&param, 0, sizeof(param));
	param.a0 = OPTEE_SMC_L2CC_MUTEX;
	param.a1 = OPTEE_SMC_L2CC_MUTEX_GET_ADDR;
	tee_smc_call(&param);

	if (param.a0 != OPTEE_SMC_RETURN_OK) {
		dev_warn(DEV, "no TZ l2cc mutex service supported\n");
		goto out;
	}
	paddr = (unsigned long)reg_pair_to_ptr(param.a2, param.a3);
	dev_dbg(DEV, "outer cache shared mutex paddr 0x%lx\n", paddr);

	vaddr = ioremap_cache(paddr, sizeof(u32));
	if (vaddr == NULL) {
		dev_warn(DEV, "TZ l2cc mutex disabled: ioremap failed\n");
		ret = -ENOMEM;
		goto out;
	}

	dev_dbg(DEV, "outer cache shared mutex vaddr %p\n", vaddr);
	if (outer_tz_mutex(vaddr) == false) {
		dev_warn(DEV, "TZ l2cc mutex disabled: outer cache refused\n");
		goto out;
	}

	memset(&param, 0, sizeof(param));
	param.a0 = OPTEE_SMC_L2CC_MUTEX;
	param.a1 = OPTEE_SMC_L2CC_MUTEX_ENABLE;
	tee_smc_call(&param);

	if (param.a0 != OPTEE_SMC_RETURN_OK) {

		dev_warn(DEV, "TZ l2cc mutex disabled: TZ enable failed\n");
		goto out;
	}
	ptee->tz_outer_cache_mutex = vaddr;

out:
	if (ptee->tz_outer_cache_mutex == NULL) {
		memset(&param, 0, sizeof(param));
		param.a0 = OPTEE_SMC_L2CC_MUTEX;
		param.a1 = OPTEE_SMC_L2CC_MUTEX_DISABLE;
		tee_smc_call(&param);
		outer_tz_mutex(NULL);
		if (vaddr)
			iounmap(vaddr);
		dev_dbg(DEV, "outer cache shared mutex disabled\n");
	}

	mutex_unlock(&ptee->mutex);
	dev_dbg(DEV, "< teetz outer mutex: ret=%d pa=0x%lX va=0x%p %sabled\n",
		ret, paddr, vaddr, ptee->tz_outer_cache_mutex ? "en" : "dis");
	return ret;
}
#endif

/* configure_shm - Negotiate Shared Memory configuration with teetz. */
static int configure_shm(struct tee_tz *ptee)
{
	struct smc_param param = { 0 };
	size_t shm_size = -1;
	int ret = 0;

	dev_dbg(DEV, ">\n");
	BUG_ON(!CAPABLE(ptee->tee));

	mutex_lock(&ptee->mutex);
	param.a0 = OPTEE_SMC_GET_SHM_CONFIG;
	tee_smc_call(&param);
	mutex_unlock(&ptee->mutex);

	if (param.a0 != OPTEE_SMC_RETURN_OK) {
		dev_err(DEV, "shm service not available: %X", (uint)param.a0);
		ret = -EINVAL;
		goto out;
	}

	ptee->shm_paddr = param.a1;
	shm_size = param.a2;
	ptee->shm_cached = (param.a3 == OPTEE_SMC_SHM_CACHED);

	if (ptee->shm_cached)
		ptee->shm_vaddr = ioremap_cache(ptee->shm_paddr, shm_size);
	else
		ptee->shm_vaddr = ioremap_nocache(ptee->shm_paddr, shm_size);

	if (ptee->shm_vaddr == NULL) {
		dev_err(DEV, "shm ioremap failed\n");
		ret = -ENOMEM;
		goto out;
	}

	ptee->shm_pool = tee_shm_pool_create(DEV, shm_size,
					     ptee->shm_vaddr, ptee->shm_paddr);

	if (!ptee->shm_pool) {
		dev_err(DEV, "shm pool creation failed (%zu)", shm_size);
		ret = -EINVAL;
		goto out;
	}

	if (ptee->shm_cached)
		tee_shm_pool_set_cached(ptee->shm_pool);
out:
	dev_dbg(DEV, "< ret=%d pa=0x%lX va=0x%p size=%zu, %scached",
		ret, ptee->shm_paddr, ptee->shm_vaddr, shm_size,
		(ptee->shm_cached == 1) ? "" : "un");
	return ret;
}


/******************************************************************************/

static int tz_start(struct tee *tee)
{
	struct tee_tz *ptee;
	int ret;

	BUG_ON(!tee || !tee->priv);
	dev_dbg(tee->dev, ">\n");
	if (!CAPABLE(tee)) {
		dev_dbg(tee->dev, "< not capable\n");
		return -EBUSY;
	}

	ptee = tee->priv;
	BUG_ON(ptee->started);
	ptee->started = true;

	ret = configure_shm(ptee);
	if (ret)
		goto exit;


#ifdef CONFIG_OUTER_CACHE
	ret = register_outercache_mutex(ptee, true);
	if (ret)
		goto exit;
#endif

exit:
	if (ret)
		ptee->started = false;

	dev_dbg(tee->dev, "< ret=%d dev=%s\n", ret, tee->name);
	return ret;
}

static int tz_stop(struct tee *tee)
{
	struct tee_tz *ptee;

	BUG_ON(!tee || !tee->priv);

	ptee = tee->priv;

	dev_dbg(tee->dev, "> dev=%s\n", tee->name);
	if (!CAPABLE(tee)) {
		dev_dbg(tee->dev, "< not capable\n");
		return -EBUSY;
	}

#ifdef CONFIG_OUTER_CACHE
	register_outercache_mutex(ptee, false);
#endif
	tee_shm_pool_destroy(tee->dev, ptee->shm_pool);
	iounmap(ptee->shm_vaddr);
	ptee->started = false;

	dev_dbg(tee->dev, "< ret=0 dev=%s\n", tee->name);
	return 0;
}

/******************************************************************************/

const struct tee_ops tee_fops = {
	.type = "tz",
	.owner = THIS_MODULE,
	.start = tz_start,
	.stop = tz_stop,
	.invoke = tz_invoke,
	.cancel = tz_cancel,
	.open = tz_open,
	.close = tz_close,
	.alloc = tz_alloc,
	.free = tz_free,
	.shm_inc_ref = tz_shm_inc_ref,
};

static int tz_tee_init(struct platform_device *pdev)
{
	int ret = 0;

	struct tee *tee = platform_get_drvdata(pdev);
	struct tee_tz *ptee = tee->priv;

	tee_tz = ptee;

#if 0
	/* To replace by a syscall */
#ifndef CONFIG_ARM_TZ_SUPPORT
	dev_err(tee->dev,
		"%s: dev=%s, TZ fw is not loaded: TEE TZ is not supported.\n",
		__func__, tee->name);
	tee->conf = TEE_CONF_FW_NOT_CAPABLE;
	return 0;
#endif
#endif

	ptee->started = false;
	ptee->sess_id = 0xAB000000;
	mutex_init(&ptee->mutex);
	init_completion(&ptee->c);
	ptee->c_waiters = 0;

	tee_wait_queue_init(&ptee->wait_queue);
	ret = tee_mutex_wait_init(&ptee->mutex_wait);

	if (ret)
		dev_err(tee->dev, "%s: dev=%s, Secure armv7 failed (%d)\n",
				__func__, tee->name, ret);
	else
		dev_dbg(tee->dev, "%s: dev=%s, Secure armv7\n",
				__func__, tee->name);
	return ret;
}

static void tz_tee_deinit(struct platform_device *pdev)
{
	struct tee *tee = platform_get_drvdata(pdev);
	struct tee_tz *ptee = tee->priv;

	if (!CAPABLE(tee))
		return;

	tee_mutex_wait_exit(&ptee->mutex_wait);
	tee_wait_queue_exit(&ptee->wait_queue);

	dev_dbg(tee->dev, "%s: dev=%s, Secure armv7 started=%d\n", __func__,
		 tee->name, ptee->started);
}

static int tz_tee_probe(struct platform_device *pdev)
{
	int ret = 0;
	struct device *dev = &pdev->dev;
	struct tee *tee;
	struct tee_tz *ptee;

	pr_info("%s: name=\"%s\", id=%d, pdev_name=\"%s\"\n", __func__,
		pdev->name, pdev->id, dev_name(dev));
#ifdef _TEE_DEBUG
	pr_debug("- dev=%p\n", dev);
	pr_debug("- dev->parent=%p\n", dev->parent);
	pr_debug("- dev->driver=%p\n", dev->driver);
#endif

	tee = tee_core_alloc(dev, _TEE_TZ_NAME, pdev->id, &tee_fops,
			     sizeof(struct tee_tz));
	if (!tee)
		return -ENOMEM;

	ptee = tee->priv;
	ptee->tee = tee;

	platform_set_drvdata(pdev, tee);

	ret = tz_tee_init(pdev);
	if (ret)
		goto bail0;

	ret = tee_core_add(tee);
	if (ret)
		goto bail1;

#ifdef _TEE_DEBUG
	pr_debug("- tee=%p, id=%d, iminor=%d\n", tee, tee->id,
		 tee->miscdev.minor);
#endif
	return 0;

bail1:
	tz_tee_deinit(pdev);
bail0:
	tee_core_free(tee);
	return ret;
}

static int tz_tee_remove(struct platform_device *pdev)
{
	struct tee *tee = platform_get_drvdata(pdev);
	struct device *dev = &pdev->dev;
	/*struct tee_tz *ptee;*/

	pr_info("%s: name=\"%s\", id=%d, pdev_name=\"%s\"\n", __func__,
		pdev->name, pdev->id, dev_name(dev));
#ifdef _TEE_DEBUG
	pr_debug("- tee=%p, id=%d, iminor=%d, name=%s\n",
		 tee, tee->id, tee->miscdev.minor, tee->name);
#endif

/*	ptee = tee->priv;
	tee_get_status(ptee);*/

	tz_tee_deinit(pdev);
	tee_core_del(tee);
	return 0;
}

static struct of_device_id tz_tee_match[] = {
	{
	 .compatible = "stm,armv7sec",
	 },
	{},
};

static struct platform_driver tz_tee_driver = {
	.probe = tz_tee_probe,
	.remove = tz_tee_remove,
	.driver = {
		   .name = "armv7sec",
		   .owner = THIS_MODULE,
		   .of_match_table = tz_tee_match,
		   },
};

static struct platform_device tz_0_plt_device = {
	.name = "armv7sec",
	.id = 0,
	.dev = {
/*                              .platform_data = tz_0_tee_data,*/
		},
};

static int __init tee_tz_init(void)
{
	int rc;

	pr_info("TEE armv7 Driver initialization\n");

#ifdef _TEE_DEBUG
	pr_debug("- Register the platform_driver \"%s\" %p\n",
		 tz_tee_driver.driver.name, &tz_tee_driver.driver);
#endif

	rc = platform_driver_register(&tz_tee_driver);
	if (rc != 0) {
		pr_err("failed to register the platform driver (rc=%d)\n", rc);
		goto bail0;
	}

	rc = platform_device_register(&tz_0_plt_device);
	if (rc != 0) {
		pr_err("failed to register the platform devices 0 (rc=%d)\n",
		       rc);
		goto bail1;
	}

	return rc;

bail1:
	platform_driver_unregister(&tz_tee_driver);
bail0:
	return rc;
}

static void __exit tee_tz_exit(void)
{
	pr_info("TEE ARMV7 Driver de-initialization\n");

	platform_device_unregister(&tz_0_plt_device);
	platform_driver_unregister(&tz_tee_driver);
}

module_init(tee_tz_init);
module_exit(tee_tz_exit);

MODULE_AUTHOR("STMicroelectronics");
MODULE_DESCRIPTION("STM Secure TEE ARMV7 TZ driver");
MODULE_SUPPORTED_DEVICE("");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
