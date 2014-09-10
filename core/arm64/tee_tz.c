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
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/jiffies.h>

#include <asm/pgtable.h>

#include "tee-op.h"
#include "tee_supp_com.h"
#include "tee_mem.h"
#include "tee_service.h"
#include "tee_driver.h"
#include "tee_debug.h"
#include "tee_tz.h"
#include <arm_common/teesmc.h>
#include <arm_common/teesmc_st.h>
#include "handle.h"

#define DEV	(tee_tz_miscdev.this_device)

/* Shared Memory data (config loaded from secure world) */
static unsigned long shm_paddr;
static size_t shm_size;
static bool shm_cached;
static void *shm_vaddr;

/* TZ shared mutex service */
static void *tz_outer_cache_mutex;

/* protect concurrent access to the tee-tz: inits, entry */
static DEFINE_MUTEX(g_mutex_teez);

static DEFINE_MUTEX(e_mutex_teez);
static DECLARE_COMPLETION(e_comp_teez);
static int e_num_waiters;

/* device data */
struct tee_driver tee_tz_data;
static struct miscdevice tee_tz_miscdev;

static bool tee_tz_ready;

static struct handle_db shm_handle_db = HANDLE_DB_INITIALIZER;


/*******************************************************************
 * Calling TEE
 *******************************************************************/

static void e_lock_teez(void)
{
	mutex_lock(&e_mutex_teez);
}

static void e_lock_wait_completion_teez(void)
{
	/*
	 * Release the lock until "something happens" and then reacquire it
	 * again.
	 *
	 * This is needed when TEE returns "busy" and we need to try again
	 * later.
	 */
	e_num_waiters++;
	mutex_unlock(&e_mutex_teez);
	/*
	 * Wait at most one second. Secure world is normally never busy
	 * more than that so we should normally never timeout.
	 */
	wait_for_completion_timeout(&e_comp_teez, HZ);
	mutex_lock(&e_mutex_teez);
	e_num_waiters--;
}

static void e_unlock_teez(void)
{
	/*
	 * If at least one thread is waiting for "something to happen" let
	 * one thread know that "something has happened".
	 */
	if (e_num_waiters)
		complete(&e_comp_teez);
	mutex_unlock(&e_mutex_teez);
}

static void handle_rpc_func_cmd_mutex_wait(struct teesmc32_arg *arg32)
{
	struct teesmc32_param *params;

	if (arg32->num_params != 2)
		goto bad;

	params = TEESMC32_GET_PARAMS(arg32);

	if ((params[0].attr & TEESMC_ATTR_TYPE_MASK) !=
			TEESMC_ATTR_TYPE_VALUE_INPUT)
		goto bad;
	if ((params[1].attr & TEESMC_ATTR_TYPE_MASK) !=
			TEESMC_ATTR_TYPE_VALUE_INPUT)
		goto bad;

	switch (params[0].u.value.a) {
	case TEE_MUTEX_WAIT_SLEEP:
		tee_mutex_wait_sleep(DEV, params[1].u.value.a,
				     params[1].u.value.b);
		break;
	case TEE_MUTEX_WAIT_WAKEUP:
		tee_mutex_wait_wakeup(DEV, params[1].u.value.a,
				      params[1].u.value.b);
		break;
	case TEE_MUTEX_WAIT_DELETE:
		tee_mutex_wait_delete(DEV, params[1].u.value.a);
		break;
	default:
		goto bad;
	}

	arg32->ret = TEEC_SUCCESS;;
	return;
bad:
	arg32->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_rpc_func_cmd_wait(struct teesmc32_arg *arg32)
{
	struct teesmc32_param *params;
	u32 msec_to_wait;

	if (arg32->num_params != 1)
		goto bad;

	params = TEESMC32_GET_PARAMS(arg32);
	msec_to_wait = params[0].u.value.a;

	/* set task's state to interruptible sleep */
	set_current_state(TASK_INTERRUPTIBLE);

	/* take a nap */
	schedule_timeout(msecs_to_jiffies(msec_to_wait));

	arg32->ret = TEEC_SUCCESS;;
	return;
bad:
	arg32->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_rpc_func_cmd_to_supplicant(struct teesmc32_arg *arg32)
{
	struct teesmc32_param *params;
	struct tee_rpc_invoke inv;
	size_t n;
	uint32_t ret;

	if (arg32->num_params > TEE_RPC_BUFFER_NUMBER) {
		arg32->ret = TEEC_ERROR_GENERIC;
		return;
	}

	params = TEESMC32_GET_PARAMS(arg32);

	memset(&inv, 0, sizeof(inv));
	inv.cmd = arg32->cmd;
	/*
	 * Set a suitable error code in case tee-supplicant
	 * ignores the request.
	 */
	inv.res = TEEC_ERROR_NOT_IMPLEMENTED;
	inv.nbr_bf = arg32->num_params;
	for (n = 0; n < arg32->num_params; n++) {
		inv.cmds[n].buffer =
			(void *)(uintptr_t)params[n].u.memref.buf_ptr;
		inv.cmds[n].size = params[n].u.memref.size;
		switch (params[n].attr & TEESMC_ATTR_TYPE_MASK) {
		case TEESMC_ATTR_TYPE_VALUE_INPUT:
		case TEESMC_ATTR_TYPE_VALUE_OUTPUT:
		case TEESMC_ATTR_TYPE_VALUE_INOUT:
			inv.cmds[n].type = TEE_RPC_VALUE;
			break;
		case TEESMC_ATTR_TYPE_MEMREF_INPUT:
		case TEESMC_ATTR_TYPE_MEMREF_OUTPUT:
		case TEESMC_ATTR_TYPE_MEMREF_INOUT:
			inv.cmds[n].type = TEE_RPC_BUFFER;
			break;
		default:
			arg32->ret = TEEC_ERROR_GENERIC;
			return;
		}
	}

	ret = tee_supp_cmd(&TZop, TEE_RPC_ICMD_INVOKE,
				  &inv, sizeof(inv));
	if (ret == TEEC_RPC_OK)
		arg32->ret = inv.res;

	for (n = 0; n < arg32->num_params; n++) {
		switch (params[n].attr & TEESMC_ATTR_TYPE_MASK) {
		case TEESMC_ATTR_TYPE_VALUE_INPUT:
		case TEESMC_ATTR_TYPE_VALUE_OUTPUT:
		case TEESMC_ATTR_TYPE_VALUE_INOUT:
		case TEESMC_ATTR_TYPE_MEMREF_OUTPUT:
		case TEESMC_ATTR_TYPE_MEMREF_INOUT:
			/*
			 * Allow supplicant to assign a new pointer
			 * to an out-buffer. Needed when the
			 * supplicant allocates a new buffer, for
			 * instance when loading a TA.
			 */
			params[n].u.memref.buf_ptr =
					(uint32_t)(uintptr_t)inv.cmds[n].buffer;
			params[n].u.memref.size = inv.cmds[n].size;
			break;
		default:
			break;
		}
	}
}

static void handle_rpc_func_cmd(u32 parg32)
{
	struct teesmc32_arg *arg32;

	arg32 = tee_shm_pool_p2v(DEV, TZop.Allocator, parg32);

	switch (arg32->cmd) {
		case TEE_RPC_MUTEX_WAIT:
			handle_rpc_func_cmd_mutex_wait(arg32);
			break;
		case TEE_RPC_WAIT:
			handle_rpc_func_cmd_wait(arg32);
			break;
		default:
			handle_rpc_func_cmd_to_supplicant(arg32);
	}
}

static u32 handle_rpc(struct smc_param64 *param)
{
	switch (TEESMC_RETURN_GET_RPC_FUNC(param->a0)) {
	case TEESMC_RPC_FUNC_ALLOC_ARG:
		param->a1 = tee_shm_pool_alloc(DEV, TZop.Allocator,
					param->a1, 4);
		break;
	case TEESMC_RPC_FUNC_ALLOC_PAYLOAD:
		/* Can't support payload shared memory with this interface */
		param->a2 = 0;
		break;
	case TEESMC_RPC_FUNC_FREE_ARG:
		tee_shm_pool_free(DEV, TZop.Allocator, param->a1, 0);
		break;
	case TEESMC_RPC_FUNC_FREE_PAYLOAD:
		/* Can't support payload shared memory with this interface */
		break;
	case TEESMC_ST_RPC_FUNC_ALLOC_PAYLOAD:
	{
		struct tee_shm *shm;
		int cookie;

		shm = tee_shm_allocate(&TZop, 0, param->a1, 0);
		if (!shm) {
			param->a1 = 0;
			break;
		}

		cookie = handle_get(&shm_handle_db, shm);
		if (cookie < 0) {
			tee_shm_unallocate(shm);
			param->a1 = 0;
			break;
		}
		param->a1 = shm->paddr;
		param->a2 = cookie;
		break;
	}
	case TEESMC_ST_RPC_FUNC_FREE_PAYLOAD:
		if (param->a1) {
			struct tee_shm *shm;

			shm = handle_put(&shm_handle_db, param->a1);
			if (shm)
				tee_shm_unallocate(shm);
		}
		break;
	case TEESMC_RPC_FUNC_IRQ:
		break;
	case TEESMC_RPC_FUNC_CMD:
		handle_rpc_func_cmd(param->a1);
		break;
	default:
		dev_warn(DEV, "Unknown RPC func 0x%x\n",
			 (u32)TEESMC_RETURN_GET_RPC_FUNC(param->a0));
		break;
	}

	if (irqs_disabled())
		return TEESMC32_FASTCALL_RETURN_FROM_RPC;
	else
		return TEESMC32_CALL_RETURN_FROM_RPC;
}

static void call_tee(uintptr_t parg32, struct teesmc32_arg *arg32)
{
	u32 ret;
	u32 funcid;
	struct smc_param64 param = { 0 };

	/* Note that we're using TEESMC32 calls since OP-TEE is still 32bit */
	if (irqs_disabled())
		funcid = TEESMC32_FASTCALL_WITH_ARG;
	else
		funcid = TEESMC32_CALL_WITH_ARG;

	param.a1 = parg32;
	e_lock_teez();
	while (true) {
		param.a0 = funcid;

		tee_smc_call64(&param);
		ret = param.a0;

		if (ret == TEESMC_RETURN_EBUSY) {
			/*
			 * Since secure world returned busy, release the
			 * lock we had when entering this function and wait
			 * for "something to happen" (something else to
			 * exit from secure world and needed resources may
			 * have become available).
			 */
			e_lock_wait_completion_teez();
		} else if (TEESMC_RETURN_IS_RPC(ret)) {
			/* Process the RPC. */
			e_unlock_teez();
			funcid = handle_rpc(&param);
			e_lock_teez();
		} else {
			break;
		}
	}
	e_unlock_teez();

	switch (ret) {
	case TEESMC_RETURN_UNKNOWN_FUNCTION:
		arg32->ret = TEEC_ERROR_NOT_IMPLEMENTED;
		arg32->ret_origin = TEEC_ORIGIN_COMMS;
		break;
	case TEESMC_RETURN_OK:
		/* arg32->ret set by secure world */
		break;
	default:
		/* Should not happen */
		arg32->ret = TEEC_ERROR_COMMUNICATION;
		arg32->ret_origin = TEEC_ORIGIN_COMMS;
		break;
	}
}

/*******************************************************************
 * TEE service invoke formating
 *******************************************************************/

/* allocate tee service argument buffer and return virtual address */
static void *alloc_tee_arg(unsigned long *p, size_t l)
{
	if ((p == NULL) || (l == 0))
		return NULL;

	/* assume a 4 bytes aligned is sufficient */
	*p = tee_shm_pool_alloc(DEV, TZop.Allocator, l, 4);
	if (*p == 0)
		return NULL;

	return tee_shm_pool_p2v(DEV, TZop.Allocator, *p);
}

/* free tee service argument buffer (from its physical address) */
static void free_tee_arg(unsigned long p)
{
	if (p)
		tee_shm_pool_free(DEV, TZop.Allocator, p, 0);
}

static uint32_t get_cache_attrs(void)
{
	if (tee_shm_pool_is_cached(TZop.Allocator))
		return TEESMC_ATTR_CACHE_DEFAULT << TEESMC_ATTR_CACHE_SHIFT;
	else
		return 0;
}

static void set_params(
		struct teesmc32_param params32[TEEC_CONFIG_PAYLOAD_REF_COUNT],
		uint32_t param_types,
		TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT])
{
	size_t n;

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		uint8_t a = TEEC_PARAM_TYPE_GET(param_types, n);

		if (a == TEEC_MEMREF_TEMP_INPUT ||
		    a == TEEC_MEMREF_TEMP_OUTPUT ||
		    a == TEEC_MEMREF_TEMP_INOUT)
			a |= get_cache_attrs();

		params32[n].attr = a;
		params32[n].u.value.a = params[n].a;
		params32[n].u.value.b = params[n].b;
	}
}

static void get_params(TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT],
		struct teesmc32_param params32[TEEC_CONFIG_PAYLOAD_REF_COUNT])
{
	size_t n;

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		params[n].a = params32[n].u.value.a;
		params[n].b = params32[n].u.value.b;
	}
}

/*
 * tee_open_session - invoke TEE to open a GP TEE session
 */
static TEEC_Result tee_open_session(struct tee_session *ts,
	enum t_cmd_service_id sec_cmd,
	uint32_t ta_cmd,
	uint32_t param_type,
	TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT],
	uint32_t *origin)
{
	TEEC_Result ret_tee;
	struct teesmc32_arg *arg32;
	uintptr_t parg32;
	struct teesmc32_param *params32;
	struct teesmc_meta_open_session *meta;
	uintptr_t pmeta;
	size_t num_meta = 1;


	dev_dbg(DEV, "> uuid=%08x-%04x-%04x\n",
		((ts->uuid) ? ts->uuid->timeLow : 0xDEAD),
		((ts->uuid) ? ts->uuid->timeMid : 0xDEAD),
		((ts->uuid) ? ts->uuid->
		 timeHiAndVersion : 0xDEAD));

	if (tee_tz_ready == false)
		return TEEC_ERROR_BUSY;

	if (ts->ta)
		num_meta++;

	arg32 = (typeof(arg32))alloc_tee_arg(&parg32, TEESMC32_GET_ARG_SIZE(
				TEEC_CONFIG_PAYLOAD_REF_COUNT + num_meta));
	meta = (typeof(meta))alloc_tee_arg(&pmeta, sizeof(*meta));

	if ((arg32 == NULL) || (meta == NULL)) {
		free_tee_arg(parg32);
		free_tee_arg(pmeta);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	memset(arg32, 0, sizeof(*arg32));
	memset(meta, 0, sizeof(*meta));
	arg32->num_params = TEEC_CONFIG_PAYLOAD_REF_COUNT + num_meta;
	params32 = TEESMC32_GET_PARAMS(arg32);

	arg32->cmd = TEESMC_CMD_OPEN_SESSION;

	params32[0].u.memref.buf_ptr = pmeta;
	params32[0].u.memref.size = sizeof(*meta);
	params32[0].attr = TEESMC_ATTR_TYPE_MEMREF_INPUT |
			 TEESMC_ATTR_META | get_cache_attrs();

	if (ts->ta != NULL) {
		params32[1].u.memref.buf_ptr =
			tee_shm_pool_v2p(DEV, TZop.Allocator, ts->ta);
		params32[1].u.memref.size = ts->tasize;
		params32[1].attr = TEESMC_ATTR_TYPE_MEMREF_INPUT |
				 TEESMC_ATTR_META | get_cache_attrs();
	}

	if (ts->uuid != NULL)
		memcpy(meta->uuid, ts->uuid, TEESMC_UUID_LEN);
	meta->clnt_login = ts->login;

	set_params(params32 + num_meta, param_type, params);

	call_tee(parg32, arg32);

	ts->id = arg32->session;
	ret_tee = arg32->ret;
	if (origin)
		*origin = arg32->ret_origin;

	get_params(params, params32 + num_meta);

	free_tee_arg(parg32);
	free_tee_arg(pmeta);
	dev_dbg(DEV, "< [%d]\n", ret_tee);
	return ret_tee;
}

/*
 * tee_invoke_command - invoke TEE to invoke a GP TEE command
 */
static TEEC_Result tee_invoke_command(struct tee_session *ts,
	enum t_cmd_service_id sec_cmd,
	uint32_t ta_cmd,
	uint32_t param_type,
	TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT],
	uint32_t *origin)
{
	TEEC_Result ret_tee;
	struct teesmc32_arg *arg32;
	uintptr_t parg32;
	struct teesmc32_param *params32;

	dev_dbg(DEV, "> [0x%x] [%d]\n", ts->id, ta_cmd);

	arg32 = (typeof(arg32))alloc_tee_arg(&parg32,
			TEESMC32_GET_ARG_SIZE(TEEC_CONFIG_PAYLOAD_REF_COUNT));
	if (!arg32) {
		free_tee_arg(parg32);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	memset(arg32, 0, sizeof(*arg32));
	arg32->num_params = TEEC_CONFIG_PAYLOAD_REF_COUNT;
	params32 = TEESMC32_GET_PARAMS(arg32);

	arg32->cmd = TEESMC_CMD_INVOKE_COMMAND;
	arg32->session = ts->id;
	arg32->ta_func = ta_cmd;

	set_params(params32, param_type, params);

	call_tee(parg32, arg32);

	ret_tee = arg32->ret;

	get_params(params, params32);

	if (origin)
		*origin = arg32->ret_origin;

	free_tee_arg(parg32);
	dev_dbg(DEV, "< [0x%x]\n", ret_tee);
	return ret_tee;
}

/*
 * tee_cancel_command - invoke TEE to cancel a GP TEE command
 */
static TEEC_Result tee_cancel_command(struct tee_session *ts,
	enum t_cmd_service_id sec_cmd,
	uint32_t ta_cmd,
	uint32_t param_type,
	TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT],
	uint32_t *origin)
{
	TEEC_Result ret_tee = TEEC_SUCCESS;
	struct teesmc32_arg *arg32;
	uintptr_t parg32;

	arg32 = (typeof(arg32))alloc_tee_arg(&parg32, TEESMC32_GET_ARG_SIZE(0));
	if (arg32 == NULL) {
		free_tee_arg(parg32);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	dev_dbg(DEV, "> [0x%x] [%d] [%d]\n",
		ts->id, ta_cmd, mutex_is_locked(&g_mutex_teez));

	memset(arg32, 0, sizeof(*arg32));
	arg32->cmd = TEESMC_CMD_CANCEL;
	arg32->session = ts->id;

	call_tee(parg32, arg32);

	ret_tee = arg32->ret;
	if (origin)
		*origin = arg32->ret_origin;

	free_tee_arg(parg32);
	dev_dbg(DEV, "< [0x%x]\n", ret_tee);
	return ret_tee;
}

/*
 * tee_close_session - invoke TEE to close a GP TEE session
 */
static TEEC_Result tee_close_session(struct tee_session *ts,
	enum t_cmd_service_id sec_cmd,
	u32 ta_cmd,
	u32 param_type,
	TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT],
	u32 *origin)
{
	TEEC_Result ret_tee;
	struct teesmc32_arg *arg32;
	uintptr_t parg32;

	arg32 = (typeof(arg32))alloc_tee_arg(&parg32, TEESMC32_GET_ARG_SIZE(0));
	if (arg32 == NULL) {
		free_tee_arg(parg32);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	dev_dbg(DEV, "> [0x%x]\n", ts->id);

	memset(arg32, 0, sizeof(*arg32));
	arg32->cmd = TEESMC_CMD_CLOSE_SESSION;
	arg32->session = ts->id;

	call_tee(parg32, arg32);

	ret_tee = arg32->ret;
	if (origin)
		*origin = arg32->ret_origin;

	free_tee_arg(parg32);
	dev_dbg(DEV, "< [0x%x]\n", ret_tee);
	return ret_tee;
}

/*
 * Synchronised L2 cache maintenance support
 */
#ifndef CONFIG_ARM_TZ_SUPPORT
/* weak outer_tz_mutex in case not supported by kernel */
bool __weak outer_tz_mutex(unsigned long *p)
{
	return !p;
}
#endif

/* register_l2cc_mutex - Negotiate/Disable outer cache shared mutex */
static int register_l2cc_mutex(bool reg)
{
	unsigned long *vaddr = NULL;
	int ret = 0;
	struct smc_param64 param;
	uintptr_t paddr = 0;

	if ((reg == true) && (tz_outer_cache_mutex != NULL)) {
		dev_err(DEV, "outer cache shared mutex already registered\n");
		return -EINVAL;
	}
	if ((reg == false) && (tz_outer_cache_mutex == NULL))
		return 0;

	if (reg == false) {
		vaddr = tz_outer_cache_mutex;
		tz_outer_cache_mutex = NULL;
		goto out;
	}

	memset(&param, 0, sizeof(param));
	param.a0 = TEESMC32_ST_FASTCALL_L2CC_MUTEX;
	param.a1 = TEESMC_ST_L2CC_MUTEX_GET_ADDR;
	tee_smc_call64(&param);

	if (param.a0 != TEESMC_RETURN_OK) {
		dev_warn(DEV, "no TZ l2cc mutex service supported\n");
		goto out;
	}
	paddr = param.a2;

	vaddr = ioremap_cache(paddr, sizeof(u32));
	if (vaddr == NULL) {
		dev_warn(DEV, "TZ l2cc mutex disabled: ioremap failed\n");
		ret = -ENOMEM;
		goto out;
	}

	if (outer_tz_mutex(vaddr) == false) {
		dev_warn(DEV, "TZ l2cc mutex disabled: outer cache refused\n");
		goto out;
	}

	memset(&param, 0, sizeof(param));
	param.a0 = TEESMC32_ST_FASTCALL_L2CC_MUTEX;
	param.a1 = TEESMC_ST_L2CC_MUTEX_ENABLE;
	tee_smc_call64(&param);

	if (param.a0 != TEESMC_RETURN_OK) {
		dev_warn(DEV, "TZ l2cc mutex disabled: TZ enable failed\n");
		goto out;
	}
	tz_outer_cache_mutex = vaddr;

out:
	if (tz_outer_cache_mutex == NULL) {
		memset(&param, 0, sizeof(param));
		param.a0 = TEESMC32_ST_FASTCALL_L2CC_MUTEX;
		param.a1 = TEESMC_ST_L2CC_MUTEX_DISABLE;
		tee_smc_call64(&param);
		outer_tz_mutex(NULL);
		if (vaddr)
			iounmap(vaddr);
		dev_info(DEV, "outer cache shared mutex disabled\n");
	}

	dev_dbg(DEV, "teetz outer mutex: ret=%d pa=0x%lX va=0x%p %sabled\n",
		ret, paddr, vaddr, tz_outer_cache_mutex ? "en" : "dis");
	return ret;
}

/* configure_shm - Negotiate Shared Memory configuration with teetz. */
static int configure_shm(void)
{
	struct smc_param64 param = { 0 };
	int ret = 0;

	if (shm_paddr)
		return -EINVAL;

	param.a0 = TEESMC32_ST_FASTCALL_GET_SHM_CONFIG;
	tee_smc_call64(&param);

	if (param.a0 != TEESMC_RETURN_OK) {
		dev_err(DEV, "shm service not available: %X", (uint)param.a0);
		ret = -EINVAL;
		goto out;
	}

	shm_paddr = param.a1;
	shm_size = param.a2;
	shm_cached = (bool)param.a3;

	if (shm_cached)
		shm_vaddr = ioremap_cache(shm_paddr, shm_size);
	else
		shm_vaddr = ioremap_nocache(shm_paddr, shm_size);

	if (shm_vaddr == NULL) {
		dev_err(DEV, "shm ioremap failed\n");
		ret = -ENOMEM;
		goto out;
	}

	TZop.Allocator = tee_shm_pool_create(
			DEV, shm_size, shm_vaddr, shm_paddr);

	if (!TZop.Allocator) {
		dev_err(DEV, "shm pool creation failed (%zu)", shm_size);
		ret = -EINVAL;
		goto out;
	}

	if (shm_cached)
		tee_shm_pool_set_cached(TZop.Allocator);
out:
	if (ret)
		shm_paddr = 0;

	dev_dbg(DEV, "teetz shm: ret=%d pa=0x%lX va=0x%p size=%zu, %scached",
		ret, shm_paddr, shm_vaddr, shm_size,
			shm_cached == 1 ? "" : "un");
	return ret;
}
/*
 * call_tz_sec_world - wrapper for invoking TEE services
 */
static TEEC_Result call_tz_sec_world(struct tee_session *ts,
	enum t_cmd_service_id sec_cmd,
	u32 ta_cmd,
	u32 param_type,
	TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT],
	u32 *origin)
{
	int ret;

	switch (sec_cmd) {

	case CMD_TEEC_OPEN_SESSION:
		ret = tee_open_session(ts, sec_cmd, ta_cmd, param_type,
				params, origin);
		break;

	case CMD_TEEC_INVOKE_COMMAND:
		ret = tee_invoke_command(ts, sec_cmd, ta_cmd, param_type,
				params, origin);
		break;

	case CMD_TEEC_CANCEL_COMMAND:
		ret = tee_cancel_command(ts, sec_cmd, ta_cmd, param_type,
				params, origin);
		break;

	case CMD_TEEC_CLOSE_SESSION:
		ret = tee_close_session(ts, sec_cmd, ta_cmd, param_type,
				params, origin);
		break;

	case CMD_TEEC_REGISTER_MEMORY:
	case CMD_TEEC_UNREGISTER_MEMORY:
		ret = TEEC_SUCCESS;
		break;	/* TODO: check if these shall be transfered to TEE */

	default:
		ret = TEEC_ERROR_BAD_PARAMETERS;
	}

	return ret;
}

static TEEC_Result TZ_register_shm(ulong paddr, ulong size, void **handle)
{
	return TEEC_SUCCESS;	/* nothing to do ? */
}

static TEEC_Result TZ_unregister_shm(void *handle)
{
	return TEEC_SUCCESS;	/* nothing to do ! */
}

static struct miscdevice tee_tz_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = TEE_TZ_NAME,
	.fops = &tee_fops,
};

struct tee_targetop TZop = {
	.miscdev = &tee_tz_miscdev,
	.call_sec_world = call_tz_sec_world,
	.register_shm = TZ_register_shm,
	.unregister_shm = TZ_unregister_shm,
	.page_size = SZ_4K, /* min size alignment */
	.Allocator = NULL,
};

/*******************************************************************
 * Starting TEE support
 *******************************************************************/

static bool teesmc_api_uid_is_st(void)
{
	struct smc_param64 param = { .a0 = TEESMC32_CALLS_UID };

	tee_smc_call64(&param);

	if (param.a0 == TEESMC_ST_UID_R0 && param.a1 == TEESMC_ST_UID_R1 &&
	    param.a2 == TEESMC_ST_UID_R2 && (param.a3 == TEESMC_ST_UID32_R3 ||
					     param.a3 == TEESMC_ST_UID64_R3))
		return true;

	return false;
}

static bool teesmc_os_uuid_is_optee(void)
{
	struct smc_param64 param = { .a0 = TEESMC32_CALL_GET_OS_UUID };

	tee_smc_call64(&param);

	if (param.a0 == TEESMC_OS_OPTEE_UUID_R0 &&
	    param.a1 == TEESMC_OS_OPTEE_UUID_R1 &&
	    param.a2 == TEESMC_OS_OPTEE_UUID_R2 &&
	    param.a3 == TEESMC_OS_OPTEE_UUID_R3)
		return true;

	return false;
}

static int start_tz_world(void)
{
	int ret;

	/* allow SMC call, mutex will prevent any other access */
	mutex_lock(&g_mutex_teez);
	tee_tz_ready = true;

	/* Check that we're talking to the expected TEE */
	if (!teesmc_api_uid_is_st() || !teesmc_os_uuid_is_optee()) {
		ret = -EINVAL;
		goto out;
	}

	ret = configure_shm();
	if (ret)
		goto out;

	ret = register_l2cc_mutex(true);

out:
	if (ret)
		tee_tz_ready = false;

	mutex_unlock(&g_mutex_teez);
	return ret;
}

static void stop_tz_world(void)
{
	mutex_lock(&g_mutex_teez);
	register_l2cc_mutex(false);
	tee_shm_pool_destroy(DEV, TZop.Allocator);
	iounmap(shm_vaddr);
	mutex_unlock(&g_mutex_teez);
}

/*******************************************************************
 * TEE TZ driver inits
 *******************************************************************/

int __init tee_tz_init(void)
{
	int ret;

	mutex_init(&tee_tz_data.mutex_tee);

	tee_tz_data.memory_pool = NULL;

	ret = misc_register(&tee_tz_miscdev);
	if (ret) {
		pr_err("Can't register tee_tz\n");
		goto exit;
	}

#if (CFG_TEE_DRV_DEBUGFS == 1)
	ret = tee_debug_init(DEV);
	if (ret)
		goto err_deregister;
#endif

	ret = start_tz_world();
	if (ret) {
		dev_err(DEV, "Can't start tee-tz\n");
		goto err_dbg;
	}

	return 0;

err_dbg:
#if (CFG_TEE_DRV_DEBUGFS == 1)
	tee_debug_remove(DEV);
err_deregister:
#endif
	misc_deregister(&tee_tz_miscdev);
exit:
	/*
	 * Temporary workaround: TEE TZ firmware may not be available.
	 * In case TZ driver fails, just forbid access to TZ-TEE.
	 */
	if (ret) {
		pr_err("TEE/TZ driver failed. It is now disabled.\n");
		ret = 0;
	}
	return ret;
}

void tee_tz_exit(void)
{
	if (tee_tz_ready == false)
		return;

	stop_tz_world();
#if (CFG_TEE_DRV_DEBUGFS == 1)
	tee_debug_remove(DEV);
#endif
	misc_deregister(&tee_tz_miscdev);
}
