#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/sched.h>
#include <linux/jiffies.h>

#include <optee/tee_core.h>
#include <optee/tee_ioc.h>
#include <optee/tee_shm.h>
#include <optee/tee_supp_com.h>
#include <optee/tee_mutex_wait.h>

#include "teesmc.h"
#include "teesmc_st.h"

#include "tee_mem.h"
#include "tee_tz_priv.h"
#include "handle.h"

#define _TEE_TZ_NAME "armtz"
#define DEV (tee_tz->tee->dev)

/* magic config: bit 1 is set, Secure TEE shall handler NSec IRQs */
#define SEC_ROM_NO_FLAG_MASK	0x0000
#define SEC_ROM_IRQ_ENABLE_MASK	0x0001
#define SEC_ROM_DEFAULT		SEC_ROM_IRQ_ENABLE_MASK
#define TEE_RETURN_BUSY		0x3
#define ALLOC_ALIGN		SZ_4K

#define CAPABLE(tee) !(tee->conf & TEE_CONF_FW_NOT_CAPABLE)

static struct handle_db shm_handle_db = HANDLE_DB_INITIALIZER;

static inline void e_lock_teez(struct tee_tz *tee_tz)
{
	mutex_lock(&tee_tz->mutex);
}

static inline void e_unlock_teez(struct tee_tz *tee_tz)
{
	/*
	 * If at least one thread is waiting for "something to happen(i.e. smc
	 * call has finished)", let that thread know "something has happened".
	 */
	if (tee_tz->c_waiters)
		complete(&tee_tz->c);
	mutex_unlock(&tee_tz->mutex);
}


static void e_lock_wait_completion_teez(struct tee_tz *tee_tz)
{
	/*
	 * Release the lock until "something happens" and then reacquire it
	 * again.
	 *
	 * This is needed when TEE returns "busy" and we need to try again
	 * later.
	 */
	tee_tz->c_waiters++;
	mutex_unlock(&tee_tz->mutex);
	/*
	 * Wait at most one second. Secure world is normally never busy
	 * more than that so we should normally never timeout.
	 */
	wait_for_completion_timeout(&tee_tz->c, HZ);
	mutex_lock(&tee_tz->mutex);
	tee_tz->c_waiters--;
}

static void handle_rpc_func_cmd_mutex_wait(struct tee_tz *tee_tz,
						struct teesmc32_arg *arg32)
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
		tee_mutex_wait_sleep(DEV, &tee_tz->mutex_wait,
				     params[1].u.value.a,
				     params[1].u.value.b);
		break;
	case TEE_MUTEX_WAIT_WAKEUP:
		tee_mutex_wait_wakeup(DEV, &tee_tz->mutex_wait,
				      params[1].u.value.a,
				      params[1].u.value.b);
		break;
	case TEE_MUTEX_WAIT_DELETE:
		tee_mutex_wait_delete(DEV, &tee_tz->mutex_wait,
				      params[1].u.value.a);
		break;
	default:
		goto bad;
	}

	arg32->ret = TEEC_SUCCESS;
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

	arg32->ret = TEEC_SUCCESS;
	return;
bad:
	arg32->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_rpc_func_cmd_to_supplicant(struct tee_tz *tee_tz,
						struct teesmc32_arg *arg32)
{
	struct teesmc32_param *params;
	struct tee_rpc_invoke inv;
	size_t n;
	uint32_t ret;

	/* initialize the result code for RPC */
	arg32->ret = TEEC_ERROR_GENERIC;

	if (arg32->num_params > TEE_RPC_BUFFER_NUMBER)
		return;

	params = TEESMC32_GET_PARAMS(arg32);

	memset(&inv, 0, sizeof(inv));
	inv.cmd = arg32->cmd;
	/*
	 * Set a suitable error code in case tee-supplicant
	 * ignores the request.
	 */
	inv.ret = TEEC_ERROR_NOT_IMPLEMENTED;
	inv.num_params = arg32->num_params;
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
			return;
		}
	}

	ret = tee_supp_cmd(tee_tz->tee, TEE_RPC_ICMD_INVOKE,
				  &inv, sizeof(inv));
	if (ret == TEEC_RPC_OK)
		arg32->ret = inv.ret;

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

static void handle_rpc_func_cmd(struct tee_tz *tee_tz, u32 parg32)
{
	struct teesmc32_arg *arg32;

	arg32 = tee_shm_pool_p2v(DEV, tee_tz->shm_pool, parg32);

	switch (arg32->cmd) {
	case TEE_RPC_MUTEX_WAIT:
		handle_rpc_func_cmd_mutex_wait(tee_tz, arg32);
		break;
	case TEE_RPC_WAIT:
		handle_rpc_func_cmd_wait(arg32);
		break;
	default:
		handle_rpc_func_cmd_to_supplicant(tee_tz, arg32);
	}
}

static u32 handle_rpc(struct tee_tz *tee_tz, struct smc_param *param)
{
	struct tee_shm *shm;
	int cookie;

	switch (TEESMC_RETURN_GET_RPC_FUNC(param->a0)) {
	case TEESMC_RPC_FUNC_ALLOC_ARG:
		param->a1 = tee_shm_pool_alloc(DEV, tee_tz->shm_pool,
					param->a1, 4);
		break;
	case TEESMC_RPC_FUNC_ALLOC_PAYLOAD:
		/* Can't support payload shared memory with this interface */
		param->a2 = 0;
		break;
	case TEESMC_RPC_FUNC_FREE_ARG:
		tee_shm_pool_free(DEV, tee_tz->shm_pool, param->a1, 0);
		break;
	case TEESMC_RPC_FUNC_FREE_PAYLOAD:
		/* Can't support payload shared memory with this interface */
		break;
	case TEESMC_ST_RPC_FUNC_ALLOC_PAYLOAD:
		shm = tee_shm_alloc_from_rpc(tee_tz->tee, param->a1,
					TEE_SHM_TEMP | TEE_SHM_FROM_RPC);
		if (!shm) {
			param->a1 = 0;
			break;
		}
		cookie = handle_get(&shm_handle_db, shm);
		if (cookie < 0) {
			tee_shm_free_from_rpc(shm);
			param->a1 = 0;
			break;
		}
		param->a1 = shm->paddr;
		param->a2 = cookie;
		break;
	case TEESMC_ST_RPC_FUNC_FREE_PAYLOAD:
		if (param->a1) {
			shm = handle_put(&shm_handle_db, param->a1);
			if (shm)
				tee_shm_free_from_rpc(shm);
		}
		break;
	case TEESMC_RPC_FUNC_IRQ:
		break;
	case TEESMC_RPC_FUNC_CMD:
		handle_rpc_func_cmd(tee_tz, param->a1);
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

static void call_tee(struct tee_tz *tee_tz,
			uintptr_t parg32, struct teesmc32_arg *arg32)
{
	u32 ret;
	u32 funcid;
	struct smc_param param = { 0 };

	if (irqs_disabled())
		funcid = TEESMC32_FASTCALL_WITH_ARG;
	else
		funcid = TEESMC32_CALL_WITH_ARG;

	/*
	 * Commented out elements used to visualize the layout dynamic part
	 * of the struct. Note that these fields are not available at all
	 * if num_params == 0.
	 *
	 * params is accessed through the macro TEESMC32_GET_PARAMS
	 */

	/* struct teesmc32_param params[num_params]; */


	param.a1 = parg32;
	e_lock_teez(tee_tz);
	while (true) {
		param.a0 = funcid;

		tee_smc_call(&param);
		ret = param.a0;

		if (ret == TEESMC_RETURN_EBUSY) {
			/*
			 * Since secure world returned busy, release the
			 * lock we had when entering this function and wait
			 * for "something to happen" (something else to
			 * exit from secure world and needed resources may
			 * have become available).
			 */
			e_lock_wait_completion_teez(tee_tz);
		} else if (TEESMC_RETURN_IS_RPC(ret)) {
			/* Process the RPC. */
			e_unlock_teez(tee_tz);
			funcid = handle_rpc(tee_tz, &param);
			e_lock_teez(tee_tz);
		} else {
			break;
		}
	}
	e_unlock_teez(tee_tz);

	switch (ret) {
	case TEESMC_RETURN_UNKNOWN_FUNCTION:
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
static void *alloc_tee_arg(struct tee_tz *tee_tz, unsigned long *p, size_t l)
{
	void *vaddr;

	WARN_ON(!CAPABLE(tee_tz->tee));

	if ((p == NULL) || (l == 0))
		return NULL;

	/* assume a 4 bytes aligned is sufficient */
	*p = tee_shm_pool_alloc(DEV, tee_tz->shm_pool, l, ALLOC_ALIGN);
	if (*p == 0)
		return NULL;

	vaddr = tee_shm_pool_p2v(DEV, tee_tz->shm_pool, *p);

	return vaddr;
}

/* free tee service argument buffer (from its physical address) */
static void free_tee_arg(struct tee_tz *tee_tz, unsigned long p)
{
	BUG_ON(!CAPABLE(tee_tz->tee));

	if (p)
		tee_shm_pool_free(DEV, tee_tz->shm_pool, p, 0);
}

static uint32_t get_cache_attrs(struct tee_tz *tee_tz)
{
	if (tee_shm_pool_is_cached(tee_tz->shm_pool))
		return TEESMC_ATTR_CACHE_DEFAULT << TEESMC_ATTR_CACHE_SHIFT;
	else
		return TEESMC_ATTR_CACHE_NONCACHE << TEESMC_ATTR_CACHE_SHIFT;
}

static uint32_t param_type_teec2teesmc(uint8_t type)
{
	switch (type) {
	case TEEC_NONE:
		return TEESMC_ATTR_TYPE_NONE;
	case TEEC_VALUE_INPUT:
		return TEESMC_ATTR_TYPE_VALUE_INPUT;
	case TEEC_VALUE_OUTPUT:
		return TEESMC_ATTR_TYPE_VALUE_OUTPUT;
	case TEEC_VALUE_INOUT:
		return TEESMC_ATTR_TYPE_VALUE_INOUT;
	case TEEC_MEMREF_TEMP_INPUT:
	case TEEC_MEMREF_PARTIAL_INPUT:
		return TEESMC_ATTR_TYPE_MEMREF_INPUT;
	case TEEC_MEMREF_TEMP_OUTPUT:
	case TEEC_MEMREF_PARTIAL_OUTPUT:
		return TEESMC_ATTR_TYPE_MEMREF_OUTPUT;
	case TEEC_MEMREF_WHOLE:
	case TEEC_MEMREF_TEMP_INOUT:
	case TEEC_MEMREF_PARTIAL_INOUT:
		return TEESMC_ATTR_TYPE_MEMREF_INOUT;
	default:
		WARN_ON(true);
		return 0;
	}
}

static void set_params(struct tee_tz *tee_tz,
		struct teesmc32_param params32[TEEC_CONFIG_PAYLOAD_REF_COUNT],
		uint32_t param_types,
		struct tee_data *data)
{
	size_t n;
	struct tee_shm **shm;
	struct teec_val *value;

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		uint32_t type = TEEC_PARAM_TYPE_GET(param_types, n);

		params32[n].attr = param_type_teec2teesmc(type);
		if (params32[n].attr == TEESMC_ATTR_TYPE_NONE)
			continue;
		if (params32[n].attr < TEESMC_ATTR_TYPE_MEMREF_INPUT) {
			value = (struct teec_val *)&data->params[n];
			params32[n].u.value.a = value->a;
			params32[n].u.value.b = value->b;
			continue;
		}
		shm = (struct tee_shm **)&data->params[n];
		params32[n].attr |= get_cache_attrs(tee_tz);
		params32[n].u.memref.buf_ptr = (*shm)->paddr;
		params32[n].u.memref.size = (*shm)->size_req;
	}
}

static void get_params(struct tee_data *data,
		struct teesmc32_param params32[TEEC_CONFIG_PAYLOAD_REF_COUNT])
{
	size_t n;
	struct tee_shm **shm;
	struct teec_val *value;

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		if (params32[n].attr == TEESMC_ATTR_TYPE_NONE)
			continue;
		if (params32[n].attr < TEESMC_ATTR_TYPE_MEMREF_INPUT) {
			value = (struct teec_val *)&data->params[n];
			value->a = params32[n].u.value.a;
			value->b = params32[n].u.value.b;
			continue;
		}
		shm = (struct tee_shm **)&data->params[n];
		(*shm)->size_req = params32[n].u.memref.size;
	}
}


/*
 * tee_open_session - invoke TEE to open a GP TEE session
 */
static int tz_open(struct tee_session *sess, struct tee_cmd *cmd)
{
	struct tee *tee;
	struct tee_tz *tee_tz;
	int ret = 0;

	struct teesmc32_arg *arg32;
	struct teesmc32_param *params32;
	struct teesmc_meta_open_session *meta;
	uintptr_t parg32;
	uintptr_t pmeta;
	size_t num_meta = 1;
	uint8_t *ta;
	struct teec_uuid *uuid;

	BUG_ON(!sess->ctx->tee);
	BUG_ON(!sess->ctx->tee->priv);
	tee = sess->ctx->tee;
	tee_tz = tee->priv;

	if (cmd->uuid)
		uuid = cmd->uuid->kaddr;
	else
		uuid = NULL;

	dev_dbg(tee->dev, "> ta kaddr %p, uuid=%08x-%04x-%04x\n",
		(cmd->ta) ? cmd->ta->kaddr : NULL,
		((uuid) ? uuid->time_low : 0xDEAD),
		((uuid) ? uuid->time_mid : 0xDEAD),
		((uuid) ? uuid->time_hi_and_ver : 0xDEAD));

	if (!CAPABLE(tee_tz->tee)) {
		dev_dbg(tee->dev, "< not capable\n");
		return -EBUSY;
	}

	/* case ta binary is inside the open request */
	ta = NULL;
	if (cmd->ta) {
		ta = cmd->ta->kaddr;
		num_meta++;
	}

	arg32 = alloc_tee_arg(tee_tz, &parg32, TEESMC32_GET_ARG_SIZE(
				TEEC_CONFIG_PAYLOAD_REF_COUNT + num_meta));
	meta = alloc_tee_arg(tee_tz, &pmeta, sizeof(*meta));

	if ((arg32 == NULL) || (meta == NULL)) {
		free_tee_arg(tee_tz, parg32);
		free_tee_arg(tee_tz, pmeta);
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
			 TEESMC_ATTR_META | get_cache_attrs(tee_tz);

	if (ta) {
		params32[1].u.memref.buf_ptr =
			tee_shm_pool_v2p(DEV, tee_tz->shm_pool, cmd->ta->kaddr);
		params32[1].u.memref.size = cmd->ta->size_req;
		params32[1].attr = TEESMC_ATTR_TYPE_MEMREF_INPUT |
				 TEESMC_ATTR_META | get_cache_attrs(tee_tz);
	}

	if (uuid != NULL)
		memcpy(meta->uuid, uuid, TEESMC_UUID_LEN);
	meta->clnt_login = 0; /* FIXME: is this reliable ? used ? */

	params32 += num_meta;
	set_params(tee_tz, params32, cmd->param.type, &cmd->param);

	call_tee(tee_tz, parg32, arg32);

	get_params(&cmd->param, params32);

	if (arg32->ret != TEEC_ERROR_COMMUNICATION) {
		sess->sessid = arg32->session;
		cmd->err = arg32->ret;
		cmd->origin = arg32->ret_origin;
	} else
		ret = -EBUSY;

	free_tee_arg(tee_tz, parg32);
	free_tee_arg(tee_tz, pmeta);

	dev_dbg(DEV, "< %x:%d\n", arg32->ret, ret);
	return ret;
}

/*
 * tee_invoke_command - invoke TEE to invoke a GP TEE command
 */
static int tz_invoke(struct tee_session *sess, struct tee_cmd *cmd)
{
	struct tee *tee;
	struct tee_tz *tee_tz;
	int ret = 0;

	struct teesmc32_arg *arg32;
	uintptr_t parg32;
	struct teesmc32_param *params32;

	BUG_ON(!sess->ctx->tee);
	BUG_ON(!sess->ctx->tee->priv);
	tee = sess->ctx->tee;
	tee_tz = tee->priv;

	dev_dbg(DEV, "> sessid %x cmd %x type %x\n",
		sess->sessid, cmd->cmd, cmd->param.type);

	if (!CAPABLE(tee)) {
		dev_dbg(tee->dev, "< not capable\n");
		return -EBUSY;
	}

	arg32 = (typeof(arg32))alloc_tee_arg(tee_tz, &parg32,
			TEESMC32_GET_ARG_SIZE(TEEC_CONFIG_PAYLOAD_REF_COUNT));
	if (!arg32) {
		free_tee_arg(tee_tz, parg32);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	memset(arg32, 0, sizeof(*arg32));
	arg32->num_params = TEEC_CONFIG_PAYLOAD_REF_COUNT;
	params32 = TEESMC32_GET_PARAMS(arg32);

	arg32->cmd = TEESMC_CMD_INVOKE_COMMAND;
	arg32->session = sess->sessid;
	arg32->ta_func = cmd->cmd;

	set_params(tee_tz, params32, cmd->param.type, &cmd->param);

	call_tee(tee_tz, parg32, arg32);

	get_params(&cmd->param, params32);

	if (arg32->ret != TEEC_ERROR_COMMUNICATION) {
		cmd->err = arg32->ret;
		cmd->origin = arg32->ret_origin;
	} else
		ret = -EBUSY;

	free_tee_arg(tee_tz, parg32);

	dev_dbg(DEV, "< %x:%d\n", arg32->ret, ret);
	return ret;
}

/*
 * tee_cancel_command - invoke TEE to cancel a GP TEE command
 */
static int tz_cancel(struct tee_session *sess, struct tee_cmd *cmd)
{
	struct tee *tee;
	struct tee_tz *tee_tz;
	int ret = 0;

	struct teesmc32_arg *arg32;
	uintptr_t parg32;

	BUG_ON(!sess->ctx->tee);
	BUG_ON(!sess->ctx->tee->priv);
	tee = sess->ctx->tee;
	tee_tz = tee->priv;

	dev_dbg(DEV, "cancel on sessid=%08x\n", sess->sessid);

	arg32 = alloc_tee_arg(tee_tz, &parg32, TEESMC32_GET_ARG_SIZE(0));
	if (arg32 == NULL) {
		free_tee_arg(tee_tz, parg32);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	memset(arg32, 0, sizeof(*arg32));
	arg32->cmd = TEESMC_CMD_CANCEL;
	arg32->session = sess->sessid;

	call_tee(tee_tz, parg32, arg32);

	if (arg32->ret == TEEC_ERROR_COMMUNICATION)
		ret = -EBUSY;

	free_tee_arg(tee_tz, parg32);

	dev_dbg(DEV, "< %x:%d\n", arg32->ret, ret);
	return ret;
}

/*
 * tee_close_session - invoke TEE to close a GP TEE session
 */
static int tz_close(struct tee_session *sess)
{
	struct tee *tee;
	struct tee_tz *tee_tz;
	int ret = 0;

	struct teesmc32_arg *arg32;
	uintptr_t parg32;

	BUG_ON(!sess->ctx->tee);
	BUG_ON(!sess->ctx->tee->priv);
	tee = sess->ctx->tee;
	tee_tz = tee->priv;

	dev_dbg(DEV, "close on sessid=%08x\n", sess->sessid);

	if (!CAPABLE(tee)) {
		dev_dbg(tee->dev, "< not capable\n");
		return -EBUSY;
	}

	arg32 = alloc_tee_arg(tee_tz, &parg32, TEESMC32_GET_ARG_SIZE(0));
	if (arg32 == NULL) {
		free_tee_arg(tee_tz, parg32);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	dev_dbg(DEV, "> [%x]\n", sess->sessid);

	memset(arg32, 0, sizeof(*arg32));
	arg32->cmd = TEESMC_CMD_CLOSE_SESSION;
	arg32->session = sess->sessid;

	call_tee(tee_tz, parg32, arg32);

	if (arg32->ret == TEEC_ERROR_COMMUNICATION)
		ret = -EBUSY;

	free_tee_arg(tee_tz, parg32);

	dev_dbg(DEV, "< %x:%d\n", arg32->ret, ret);
	return ret;
}

static struct tee_shm *tz_alloc(struct tee *tee, size_t size, uint32_t flags)
{
	struct tee_shm *shm = NULL;
	struct tee_tz *tee_tz;

	BUG_ON(!tee->priv);
	tee_tz = tee->priv;

	dev_dbg(DEV, "%s: s=%d,flags=0x%08x\n", __func__, (int)size, flags);

	shm = devm_kzalloc(tee->dev, sizeof(struct tee_shm), GFP_KERNEL);
	if (!shm)
		return ERR_PTR(-ENOMEM);

	shm->size_alloc = ((size / SZ_4K) + 1) * SZ_4K;
	shm->size_req = size;
	shm->paddr = tee_shm_pool_alloc(tee->dev, tee_tz->shm_pool,
					shm->size_alloc, ALLOC_ALIGN);
	if (!shm->paddr) {
		dev_err(tee->dev, "%s: cannot alloc memory, size 0x%lx\n",
			__func__, (unsigned long)shm->size_alloc);
		devm_kfree(tee->dev, shm);
		return ERR_PTR(-ENOMEM);
	}
	shm->kaddr = tee_shm_pool_p2v(tee->dev, tee_tz->shm_pool, shm->paddr);
	if (!shm->kaddr) {
		dev_err(tee->dev, "%s: p2v(%p)=0\n", __func__,
			(void *)shm->paddr);
		tee_shm_pool_free(tee->dev, tee_tz->shm_pool, shm->paddr, NULL);
		devm_kfree(tee->dev, shm);
		return ERR_PTR(-EFAULT);
	}
	shm->flags = flags;
	if (tee_tz->shm_cached)
		shm->flags |= TEE_SHM_CACHED;

	dev_dbg(tee->dev, "%s: kaddr=%p, paddr=%p, shm=%p, size %x:%x\n",
		__func__, shm->kaddr, (void *)shm->paddr, shm,
		(unsigned int)shm->size_req, (unsigned int)shm->size_alloc);

	return shm;
}

static void tz_free(struct tee_shm *shm)
{
	int size;
	int ret;
	struct tee *tee;
	struct tee_tz *tee_tz;

	BUG_ON(!shm->tee);
	BUG_ON(!shm->tee->priv);
	tee = shm->tee;
	tee_tz = tee->priv;

	dev_dbg(tee->dev, "%s: shm=%p\n", __func__, shm);

	ret = tee_shm_pool_free(tee->dev, tee_tz->shm_pool, shm->paddr, &size);
	if (!ret) {
		devm_kfree(tee->dev, shm);
		shm = NULL;
	}
}

static int tz_shm_inc_ref(struct tee_shm *shm)
{
	struct tee *tee;
	struct tee_tz *tee_tz;

	BUG_ON(!shm->tee);
	BUG_ON(!shm->tee->priv);
	tee = shm->tee;
	tee_tz = tee->priv;

	return tee_shm_pool_incref(tee->dev, tee_tz->shm_pool, shm->paddr);
}

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
static int register_outercache_mutex(struct tee_tz *tee_tz, bool reg)
{
	unsigned long *vaddr = NULL;
	int ret = 0;
	struct smc_param param;
	uintptr_t paddr = 0;

	dev_dbg(tee_tz->tee->dev, ">\n");
	BUG_ON(!CAPABLE(tee_tz->tee));

	if (tee_tz->tz_outer_cache_mutex != NULL) {
		if (reg) {
			dev_err(DEV, "outer cache shared mutex already registered\n");
			return -EINVAL;
		}
	} else if (!reg)
		return 0;

	mutex_lock(&tee_tz->mutex);

	if (!reg) {
		vaddr = tee_tz->tz_outer_cache_mutex;
		tee_tz->tz_outer_cache_mutex = NULL;
		goto out;
	}

	memset(&param, 0, sizeof(param));
	param.a0 = TEESMC32_FASTCALL_L2CC_MUTEX;
	param.a1 = TEESMC_L2CC_MUTEX_GET_ADDR;
	tee_smc_call(&param);

	if (param.a0 != TEESMC_RETURN_OK) {
		dev_warn(DEV, "no TZ l2cc mutex service supported\n");
		goto out;
	}
	paddr = param.a2;
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
	param.a0 = TEESMC32_FASTCALL_L2CC_MUTEX;
	param.a1 = TEESMC_L2CC_MUTEX_ENABLE;
	tee_smc_call(&param);

	if (param.a0 != TEESMC_RETURN_OK) {

		dev_warn(DEV, "TZ l2cc mutex disabled: TZ enable failed\n");
		goto out;
	}
	tee_tz->tz_outer_cache_mutex = vaddr;

out:
	if (tee_tz->tz_outer_cache_mutex == NULL) {
		memset(&param, 0, sizeof(param));
		param.a0 = TEESMC32_FASTCALL_L2CC_MUTEX;
		param.a1 = TEESMC_L2CC_MUTEX_DISABLE;
		tee_smc_call(&param);
		outer_tz_mutex(NULL);
		if (vaddr)
			iounmap(vaddr);
		dev_dbg(DEV, "outer cache shared mutex disabled\n");
	}

	mutex_unlock(&tee_tz->mutex);
	dev_dbg(DEV, "< teetz outer mutex: ret=%d pa=0x%lX va=0x%p %sabled\n",
		ret, paddr, vaddr, tee_tz->tz_outer_cache_mutex ? "en" : "dis");
	return ret;
}
#endif

/* configure_shm - Negotiate Shared Memory configuration with teetz. */
static int configure_shm(struct tee_tz *tee_tz)
{
	struct smc_param param = { 0 };
	size_t shm_size = -1;
	int ret = 0;

	dev_dbg(DEV, ">\n");
	BUG_ON(!CAPABLE(tee_tz->tee));

	mutex_lock(&tee_tz->mutex);
	param.a0 = TEESMC32_FASTCALL_GET_SHM_CONFIG;
	tee_smc_call(&param);
	mutex_unlock(&tee_tz->mutex);

	if (param.a0 != TEESMC_RETURN_OK) {
		dev_err(DEV, "shm service not available: %X", (uint)param.a0);
		ret = -EINVAL;
		goto out;
	}

	tee_tz->shm_paddr = param.a1;
	shm_size = param.a2;
	tee_tz->shm_cached = (bool)param.a3;

	if (tee_tz->shm_cached)
		tee_tz->shm_vaddr =
			ioremap_cache(tee_tz->shm_paddr, shm_size);
	else
		tee_tz->shm_vaddr =
			ioremap_nocache(tee_tz->shm_paddr, shm_size);

	if (tee_tz->shm_vaddr == NULL) {
		dev_err(DEV, "shm ioremap failed\n");
		ret = -ENOMEM;
		goto out;
	}

	tee_tz->shm_pool = tee_shm_pool_create(DEV, shm_size,
					tee_tz->shm_vaddr, tee_tz->shm_paddr);

	if (!tee_tz->shm_pool) {
		dev_err(DEV, "shm pool creation failed (%zu)", shm_size);
		ret = -EINVAL;
		goto out;
	}

	if (tee_tz->shm_cached)
		tee_shm_pool_set_cached(tee_tz->shm_pool);
out:
	dev_dbg(DEV, "< ret=%d pa=0x%lX va=0x%p size=%zu, %scached",
		ret, tee_tz->shm_paddr, tee_tz->shm_vaddr, shm_size,
		(tee_tz->shm_cached == 1) ? "" : "un");
	return ret;
}


/******************************************************************************/

static int tz_start(struct tee *tee)
{
	struct tee_tz *tee_tz;
	int ret;

	BUG_ON(!tee || !tee->priv);
	dev_dbg(tee->dev, ">\n");
	if (!CAPABLE(tee)) {
		dev_dbg(tee->dev, "< not capable\n");
		return -EBUSY;
	}

	tee_tz = tee->priv;
	BUG_ON(tee_tz->started);
	tee_tz->started = true;

	ret = configure_shm(tee_tz);
	if (ret)
		goto exit;


#ifdef CONFIG_OUTER_CACHE
	ret = register_outercache_mutex(tee_tz, true);
	if (ret)
		goto exit;
#endif

exit:
	if (ret)
		tee_tz->started = false;

	dev_dbg(tee->dev, "< ret=%d dev=%s\n", ret, tee->name);
	return ret;
}

static int tz_stop(struct tee *tee)
{
	struct tee_tz *tee_tz;

	BUG_ON(!tee || !tee->priv);

	tee_tz = tee->priv;

	dev_dbg(tee->dev, "> dev=%s\n", tee->name);
	if (!CAPABLE(tee)) {
		dev_dbg(tee->dev, "< not capable\n");
		return -EBUSY;
	}

#ifdef CONFIG_OUTER_CACHE
	register_outercache_mutex(tee_tz, false);
#endif
	tee_shm_pool_destroy(tee->dev, tee_tz->shm_pool);
	iounmap(tee_tz->shm_vaddr);
	tee_tz->started = false;

	dev_dbg(tee->dev, "< ret=0 dev=%s\n", tee->name);
	return 0;
}

/******************************************************************************/

const struct tee_ops tee_tz_fops = {
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
	struct tee_tz *tee_tz = tee->priv;

	tee_tz = tee_tz;

	tee->shm_flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	tee->test = 0;

	tee_tz->started = false;
	tee_tz->sess_id = 0xAB000000;
	mutex_init(&tee_tz->mutex);
	init_completion(&tee_tz->c);
	tee_tz->c_waiters = 0;

	ret = tee_mutex_wait_init(&tee_tz->mutex_wait);

	if (ret)
		dev_err(tee->dev, "%s: dev=%s, Failed to initialize secure ARMv7 OP-TEE driver(%d)\n",
				__func__, tee->name, ret);
	else
		dev_dbg(tee->dev, "%s: dev=%s, Initialize secure ARMv7 OP-TEE driver successfully\n",
				__func__, tee->name);
	return ret;
}

static void tz_tee_deinit(struct platform_device *pdev)
{
	struct tee *tee = platform_get_drvdata(pdev);
	struct tee_tz *tee_tz = tee->priv;

	if (!CAPABLE(tee))
		return;

	tee_mutex_wait_exit(&tee_tz->mutex_wait);

	dev_dbg(tee->dev, "%s: dev=%s, Secure ARMv7 OP-TEE driver deinit(%d)\n",
		__func__, tee->name, tee_tz->started);
}

static int tz_tee_probe(struct platform_device *pdev)
{
	int ret = 0;
	struct device *dev = &pdev->dev;
	struct tee *tee;
	struct tee_tz *tee_tz;

	pr_info("%s: name=\"%s\", id=%d, pdev_name=\"%s\"\n", __func__,
		pdev->name, pdev->id, dev_name(dev));

	tee = tee_core_alloc(dev, _TEE_TZ_NAME, pdev->id, &tee_tz_fops,
			     sizeof(struct tee_tz));
	if (!tee)
		return -ENOMEM;

	tee_tz = tee->priv;
	tee_tz->tee = tee;

	platform_set_drvdata(pdev, tee);

	ret = tz_tee_init(pdev);
	if (ret)
		goto bail1;

	ret = tee_core_add(tee);
	if (ret)
		goto bail0;

	pr_debug("tee=%p, id=%d, device minor id=%d\n", tee, tee->id,
		 tee->miscdev.minor);

	return 0;

bail1:
	tz_tee_deinit(pdev);
bail0:
	return ret;
}

static int tz_tee_remove(struct platform_device *pdev)
{
	struct tee *tee = platform_get_drvdata(pdev);
	struct device *dev = &pdev->dev;
	/*struct tee_tz *tee_tz;*/

	pr_info("%s: name=\"%s\", id=%d, pdev_name=\"%s\"\n", __func__,
		pdev->name, pdev->id, dev_name(dev));

	pr_debug("tee=%p, id=%d, device minor id=%d, name=%s\n",
		 tee, tee->id, tee->miscdev.minor, tee->name);

	tz_tee_deinit(pdev);
	tee_core_del(tee);
	return 0;
}

static struct platform_driver tz_tee_driver = {
	.probe = tz_tee_probe,
	.remove = tz_tee_remove,
	.driver = {
		.name = "armv7sec",
		.owner = THIS_MODULE,
		},
};

static struct platform_device tz_0_plt_device = {
	.name = "armv7sec",
	.id = 0,
};

static int __init tee_tz_init(void)
{
	int ret;

	pr_info("OP-TEE ARMv7 driver initialization\n");

	pr_debug("Register OP-TEE ARMv7 driver \"%s\"\n",
			tz_tee_driver.driver.name);

	ret = platform_driver_register(&tz_tee_driver);
	if (ret != 0) {
		pr_err("failed to register the platform driver(%d)\n", ret);
		goto bail0;
	}

	ret = platform_device_register(&tz_0_plt_device);
	if (ret != 0) {
		pr_err("failed to register the platform devices 0 (%d)\n", ret);
		goto bail1;
	}

	return ret;

bail1:
	platform_driver_unregister(&tz_tee_driver);
bail0:
	return ret;
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
