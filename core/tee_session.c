#include <linux/slab.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/file.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/anon_inodes.h>

#include <optee/tee_shm.h>

#include "tee_core_priv.h"

#define UUID_STR_SIZE 35

static int init_tee_cmd(struct tee_context *ctx, struct tee_cmd_io *cmd_io,
			 struct tee_cmd *cmd);
static void update_client_tee_cmd(struct tee_context *ctx,
				   struct tee_cmd_io *cmd_io,
				   struct tee_cmd *cmd);
static void release_tee_cmd(struct tee_context *ctx, struct tee_cmd *cmd);


static char *uuid_to_str(const struct teec_uuid *uuid)
{
	static char uuid_str[UUID_STR_SIZE];

	if (uuid) {
		const uint8_t *seq_mode = uuid->clock_seq_and_mode;

		sprintf(uuid_str,
			"%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x",
			uuid->time_low, uuid->time_mid, uuid->time_hi_and_ver,
			seq_mode[0], seq_mode[1], seq_mode[2], seq_mode[3],
			seq_mode[4], seq_mode[5], seq_mode[6], seq_mode[7]);
	} else {
		sprintf(uuid_str, "NULL");
	}

	return uuid_str;
}

/* Defined as macro to let the put_user macro see the types */
#define tee_context_copy_simple(ctx, from, to)			\
	do {							\
		if ((ctx)->usr_client)				\
			put_user(from, to);			\
		else						\
			*to = from;				\
	} while (0)

static inline int tee_session_is_opened(struct tee_session *sess)
{
	if (sess && sess->sessid)
		return (sess->sessid != 0);
	return 0;
}

static int tee_session_open_be(struct tee_session *sess,
			       struct tee_cmd_io *cmd_io)
{
	int ret = -EINVAL;
	struct tee *tee;
	struct tee_cmd cmd;
	struct tee_context *ctx;

	BUG_ON(!sess || !sess->ctx || !sess->ctx->tee);

	ctx = sess->ctx;
	tee = ctx->tee;

	tee_dbg(tee, "%s: > open a new session", __func__);

	sess->sessid = 0;
	ret = init_tee_cmd(ctx, cmd_io, &cmd);
	if (ret)
		goto out;

	if (cmd.uuid) {
		tee_dbg(tee, "%s: UUID=%s\n", __func__,
			uuid_to_str((struct teec_uuid *) cmd.uuid->kaddr));
	}

	ret = tee->ops->open(sess, &cmd);
	if (ret == 0)
		update_client_tee_cmd(ctx, cmd_io, &cmd);
	else {
		/* propagate the reason of the error */
		cmd_io->origin = cmd.origin;
		cmd_io->err = cmd.err;
	}

out:
	release_tee_cmd(ctx, &cmd);
	tee_dbg(tee, "%s: < ret=%d, sessid=%08x", __func__, ret,
		sess->sessid);
	return ret;
}

int tee_session_invoke_be(struct tee_session *sess, struct tee_cmd_io *cmd_io)
{
	int ret = -EINVAL;
	struct tee *tee;
	struct tee_cmd cmd;
	struct tee_context *ctx;

	BUG_ON(!sess || !sess->ctx || !sess->ctx->tee);

	ctx = sess->ctx;
	tee = ctx->tee;

	tee_dbg(tee, "%s: > sessid=%08x, cmd=0x%08x\n", __func__,
		sess->sessid, cmd_io->cmd);

	ret = init_tee_cmd(ctx, cmd_io, &cmd);
	if (ret)
		goto out;

	ret = tee->ops->invoke(sess, &cmd);
	if (!ret)
		update_client_tee_cmd(ctx, cmd_io, &cmd);
	else {
		/* propagate the reason of the error */
		cmd_io->origin = cmd.origin;
		cmd_io->err = cmd.err;
	}

out:
	release_tee_cmd(ctx, &cmd);
	tee_dbg(tee, "%s: < ret=%d", __func__, ret);
	return ret;
}

static int tee_session_close_be(struct tee_session *sess)
{
	int ret = -EINVAL;
	struct tee *tee;

	BUG_ON(!sess || !sess->ctx || !sess->ctx->tee);

	tee = sess->ctx->tee;

	tee_dbg(tee, "%s: > sessid=%08x", __func__, sess->sessid);

	ret = tee->ops->close(sess);
	sess->sessid = 0;

	tee_dbg(tee, "%s: < ret=%d", __func__, ret);
	return ret;
}

static int tee_session_cancel_be(struct tee_session *sess,
				 struct tee_cmd_io *cmd_io)
{
	int ret = -EINVAL;
	struct tee *tee;
	struct tee_cmd cmd;
	struct tee_context *ctx;

	BUG_ON(!sess || !sess->ctx || !sess->ctx->tee);

	ctx = sess->ctx;
	tee = ctx->tee;

	tee_dbg(tee, "%s: > sessid=%08x, cmd=0x%08x\n", __func__,
		sess->sessid, cmd_io->cmd);

	ret = init_tee_cmd(ctx, cmd_io, &cmd);
	if (ret)
		goto out;

	ret = tee->ops->cancel(sess, &cmd);

out:
	release_tee_cmd(ctx, &cmd);
	tee_dbg(tee, "%s: < ret=%d", __func__, ret);
	return ret;
}

static int tee_do_invoke_command(struct tee_session *sess,
				 struct tee_cmd_io __user *u_cmd)
{
	int ret = -EINVAL;
	struct tee *tee;
	struct tee_cmd_io k_cmd;
	struct tee_context *ctx;

	BUG_ON(!sess->ctx);
	BUG_ON(!sess->ctx->tee);
	ctx = sess->ctx;
	tee = sess->ctx->tee;

	tee_dbg(tee, "%s: > sessid=%08x\n", __func__, sess->sessid);

	BUG_ON(!sess->sessid);

	if (tee_context_copy(true, ctx,
			&k_cmd, (void *)u_cmd, sizeof(struct tee_cmd_io))) {
		tee_err(tee, "%s: tee_context_copy failed\n",
			__func__);
		goto exit;
	}

	if ((k_cmd.op == NULL) || (k_cmd.uuid != NULL) ||
	    (k_cmd.data != NULL) || (k_cmd.data_size != 0)) {
		tee_err(tee,
			"%s: op or/and data parameters are not valid\n",
			__func__);
		goto exit;
	}

	ret = tee_session_invoke_be(sess, &k_cmd);
	if (ret)
		tee_err(tee, "%s: tee_invoke_command failed\n",
			__func__);

	tee_context_copy_simple(ctx, k_cmd.err, &u_cmd->err);
	tee_context_copy_simple(ctx, k_cmd.origin, &u_cmd->origin);

exit:
	tee_dbg(tee, "%s: < ret=%d\n", __func__, ret);
	return ret;
}

static int tee_do_cancel_cmd(struct tee_session *sess,
			     struct tee_cmd_io __user *u_cmd)
{
	int ret = -EINVAL;
	struct tee *tee;
	struct tee_cmd_io k_cmd;
	struct tee_context *ctx;

	BUG_ON(!sess->ctx);
	BUG_ON(!sess->ctx->tee);
	ctx = sess->ctx;
	tee = sess->ctx->tee;

	tee_dbg(tee, "%s: > sessid=%08x\n", __func__, sess->sessid);

	BUG_ON(!sess->sessid);

	if (tee_context_copy(true, ctx,
			&k_cmd, (void *)u_cmd, sizeof(struct tee_cmd_io))) {
		tee_err(tee, "%s: tee_context_copy failed\n",
			__func__);
		goto exit;
	}

	if ((k_cmd.op == NULL) || (k_cmd.uuid != NULL) ||
	    (k_cmd.data != NULL) || (k_cmd.data_size != 0)) {
		tee_err(tee,
			"%s: op or/and data parameters are not valid\n",
			__func__);
		goto exit;
	}

	ret = tee_session_cancel_be(sess, &k_cmd);
	if (ret)
		tee_err(tee, "%s: tee_invoke_command failed\n",
			__func__);

	tee_context_copy_simple(ctx, k_cmd.err, &u_cmd->err);
	tee_context_copy_simple(ctx, k_cmd.origin, &u_cmd->origin);

exit:
	tee_dbg(tee, "%s: < ret=%d", __func__, ret);
	return ret;
}

static long tee_session_ioctl(struct file *filp, unsigned int cmd,
			      unsigned long arg)
{
	struct tee *tee;
	struct tee_session *sess = filp->private_data;
	int ret;

	BUG_ON(!sess || !sess->ctx || !sess->ctx->tee);

	tee = sess->ctx->tee;

	tee_dbg(tee, "%s: > cmd nr=%d\n", __func__, _IOC_NR(cmd));

	switch (cmd) {
	case TEE_INVOKE_COMMAND_IOC:
		ret =
		    tee_do_invoke_command(sess,
					  (struct tee_cmd_io __user *)arg);
		break;
	case TEE_REQUEST_CANCELLATION_IOC:
		ret = tee_do_cancel_cmd(sess, (struct tee_cmd_io __user *)arg);
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	tee_dbg(tee, "%s: < ret=%d\n", __func__, ret);

	return ret;
}

static int tee_session_release(struct inode *inode, struct file *filp)
{
	struct tee_session *sess = filp->private_data;
	int ret = 0;

	BUG_ON(!sess || !sess->ctx || !sess->ctx->tee);

	ret = tee_session_close_and_destroy(sess);
	return ret;
}

const struct file_operations tee_session_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = tee_session_ioctl,
	.release = tee_session_release,
};

int tee_session_close_and_destroy(struct tee_session *sess)
{
	int ret;
	struct tee *tee;
	struct tee_context *ctx;

	if (!sess || !sess->ctx || !sess->ctx->tee)
		return -EINVAL;

	ctx = sess->ctx;
	tee = ctx->tee;

	tee_dbg(tee, "%s: > sess=%p\n", __func__, sess);

	if (!tee_session_is_opened(sess))
		return -EINVAL;

	ret = tee_session_close_be(sess);

	mutex_lock(&sess->ctx->tee->lock);
	tee_dec_stats(&tee->stats[TEE_STATS_SESSION_IDX]);
	list_del(&sess->entry);
	mutex_unlock(&sess->ctx->tee->lock);

	devm_kfree(TEE_DEV(tee), sess);
	tee_context_put(ctx);
	tee_put(tee);

	tee_dbg(tee, "%s: <\n", __func__);
	return ret;
}

struct tee_session *tee_session_create_and_open(struct tee_context *ctx,
						struct tee_cmd_io *cmd_io)
{
	int ret = 0;
	struct tee_session *sess;
	struct tee *tee;

	BUG_ON(!ctx->tee);

	tee = ctx->tee;

	tee_dbg(tee, "%s: >\n", __func__);
	ret = tee_get(tee);
	if (ret)
		return ERR_PTR(-EBUSY);

	sess = devm_kzalloc(TEE_DEV(tee),
			    sizeof(struct tee_session), GFP_KERNEL);
	if (!sess)
		return ERR_PTR(-ENOMEM);

	tee_context_get(ctx);
	sess->ctx = ctx;

	ret = tee_session_open_be(sess, cmd_io);
	if (ret || !sess->sessid || cmd_io->err) {
		tee_err(tee, "%s: ERROR ret=%d (err=0x%08x, org=%d,  sessid=0x%08x)\n",
				__func__, ret, cmd_io->err,
				cmd_io->origin, sess->sessid);
		tee_put(tee);
		tee_context_put(ctx);
		devm_kfree(TEE_DEV(tee), sess);
		if (ret)
			return ERR_PTR(ret);
		else
			return NULL;
	}

	mutex_lock(&tee->lock);
	tee_inc_stats(&tee->stats[TEE_STATS_SESSION_IDX]);
	list_add_tail(&sess->entry, &ctx->list_sess);
	mutex_unlock(&tee->lock);

	tee_dbg(tee, "%s: < sess=%p\n", __func__, sess);
	return sess;
}

int tee_session_create_fd(struct tee_context *ctx, struct tee_cmd_io *cmd_io)
{
	int ret;
	struct tee_session *sess;
	struct tee *tee = ctx->tee;

	BUG_ON(cmd_io->fd_sess > 0);

	tee_dbg(tee, "%s: >\n", __func__);

	sess = tee_session_create_and_open(ctx, cmd_io);
	if (IS_ERR_OR_NULL(sess)) {
		ret = PTR_ERR(sess);
		tee_dbg(tee, "%s: ERROR can't create the session (ret=%d, err=0x%08x, org=%d)\n",
			__func__, ret, cmd_io->err, cmd_io->origin);
		cmd_io->fd_sess = -1;
		goto out;
	}

	/* Retrieve a fd */
	cmd_io->fd_sess = -1;
	ret =
	    anon_inode_getfd("tee_session", &tee_session_fops, sess, O_CLOEXEC);
	if (ret < 0) {
		tee_err(tee, "%s: ERROR can't get a fd (ret=%d)\n",
			__func__, ret);
		tee_session_close_and_destroy(sess);
		goto out;
	}
	cmd_io->fd_sess = ret;
	ret = 0;

out:
	tee_dbg(tee, "%s: < ret=%d, sess=%p, fd=%d\n", __func__,
		ret, sess, cmd_io->fd_sess);
	return ret;
}


static struct tee_shm *tee_session_shm_create(struct tee_context *ctx,
				  struct tee      *tee,
				  struct teec_shm *c_shm,
				  uint32_t         buf_offset,
				  size_t           size,
				  int              type)
{
	struct tee_shm *shm;

	if (check_shm(tee, (struct tee_shm_io *)c_shm)) {
		shm = tee_context_create_tmpref_buffer(ctx, size,
					c_shm->buffer + buf_offset, type);
		if (IS_ERR_OR_NULL(shm))
			return ERR_PTR(-ENOMEM);
	} else {
		struct tee_shm *shm_ref;
		/* The buffer is already allocated by the tee
		 * get a reference on it
		 */
		shm_ref = tee_shm_get(ctx, (struct tee_shm_io *)c_shm);

		if (!shm_ref)
			/* not allocated by us,
			 * is it a use case ? */
			BUG_ON(1);

		shm = devm_kzalloc(tee->dev,
				   sizeof(struct tee_shm), GFP_KERNEL);

		if (!shm)
			return ERR_PTR(-ENOMEM);

		shm->parent = shm_ref;
		shm->ctx = ctx;
		shm->tee = tee;
		shm->dev = tee->dev;
		shm->size_req = size;
		shm->size_alloc = 0;
		shm->kaddr = shm_ref->kaddr + buf_offset;
		shm->paddr = shm_ref->paddr + buf_offset;
		shm->flags = shm_ref->flags | TEE_SHM_PARENT;
	}

	return shm;
}

static int change_param_type(uint32_t flag)
{
	int type;

	if (flag == TEEC_MEM_INPUT || flag == TEEC_MEMREF_PARTIAL_INPUT)
		type = TEEC_MEMREF_TEMP_INPUT;
	else if (flag == TEEC_MEM_OUTPUT || flag == TEEC_MEMREF_PARTIAL_OUTPUT)
		type = TEEC_MEMREF_TEMP_OUTPUT;
	else if (flag == (TEEC_MEM_INPUT | TEEC_MEM_OUTPUT)
			|| flag == TEEC_MEMREF_PARTIAL_INOUT)
		type = TEEC_MEMREF_TEMP_INOUT;

	else
		type = flag;

	return type;
}

static int copy_op_params(struct tee_context *ctx, struct tee_cmd_io *cmd_io,
		    struct tee_cmd *cmd)
{
	int res = -EINVAL;
	int idx;
	uint32_t offset;
	uint32_t size;
	struct teec_op_desc op;
	struct tee_data *param = &cmd->param;
	struct tee *tee;

	if (!ctx || !ctx->tee) {
		pr_err("TEE Session: NULL pointer error in %s\n", __func__);
		return res;
	}

	tee = ctx->tee;

	if (tee_context_copy(true, ctx, &op, cmd_io->op,
				sizeof(struct teec_op_desc)))
		goto out;

	cmd->param.type_original = op.paramTypes;

	if (cmd->param.type_original == TEEC_PARAM_TYPES(TEEC_NONE,
			TEEC_NONE, TEEC_NONE, TEEC_NONE)) {
		param->type = cmd->param.type_original;
		res = 0;
		goto out;
	}

	for (idx = 0; idx < TEEC_CONFIG_PAYLOAD_REF_COUNT; ++idx) {
		int type = TEEC_PARAM_TYPE_GET(op.paramTypes, idx);

		switch (type) {
		case TEEC_NONE:
			break;
		case TEEC_VALUE_INPUT:
		case TEEC_VALUE_OUTPUT:
		case TEEC_VALUE_INOUT:
			param->params[idx].value = op.params[idx].value;
			tee_dbg(tee, "param[%d]:type=%d,a=%08x,b=%08x (VALUE)\n",
				idx, type, param->params[idx].value.a,
				param->params[idx].value.b);
			break;

		case TEEC_MEMREF_TEMP_INPUT:
		case TEEC_MEMREF_TEMP_OUTPUT:
		case TEEC_MEMREF_TEMP_INOUT:
			tee_dbg(tee, "> param[%d]:type=%d,buffer=%p,s=%zu (TMPREF)\n",
				idx, type, op.params[idx].tmpref.buffer,
				op.params[idx].tmpref.size);

			param->params[idx].shm =
				tee_context_create_tmpref_buffer(ctx,
						op.params[idx].tmpref.size,
						op.params[idx].tmpref.buffer,
						type);
			if (IS_ERR_OR_NULL(param->params[idx].shm))
				return -ENOMEM;

			tee_dbg(tee, "< %d %p:%zu (TMPREF)\n",
				idx, (void *)param->params[idx].shm->paddr,
				param->params[idx].shm->size_req);
			break;

		case TEEC_MEMREF_WHOLE:
			if (ctx->usr_client &&
			    tee_context_copy(true, ctx,	&param->c_shm[idx],
					     op.params[idx].memref.parent,
					     sizeof(struct teec_shm))) {
					res = TEEC_ERROR_BAD_PARAMETERS;
					goto out;
				}
			else
				param->c_shm[idx] =
					*op.params[idx].memref.parent;

			BUG_ON(!param->c_shm[idx].buffer);
			BUG_ON(!param->c_shm[idx].size);

			type = change_param_type(param->c_shm[idx].flags);

			param->params[idx].shm =
				tee_session_shm_create(ctx, tee,
				       &param->c_shm[idx],
				       0, param->c_shm[idx].size, type);

			if (IS_ERR_OR_NULL(param->params[idx].shm))
				return PTR_ERR(param->params[idx].shm);

			break;

		case TEEC_MEMREF_PARTIAL_INPUT:
		case TEEC_MEMREF_PARTIAL_OUTPUT:
		case TEEC_MEMREF_PARTIAL_INOUT:
			offset = op.params[idx].memref.offset;
			size = op.params[idx].memref.size;

			if (ctx->usr_client &&
			    tee_context_copy(true, ctx, &param->c_shm[idx],
					     op.params[idx].memref.parent,
					     sizeof(struct teec_shm))) {
				res = TEEC_ERROR_BAD_PARAMETERS;
				goto out;
			} else
				param->c_shm[idx] =
					*op.params[idx].memref.parent;

			tee_dbg(tee, "> param[%d]:type=%d,buffer=%p, offset=%x s=%d (PARTIAL)\n",
				idx, type, param->c_shm[idx].buffer,
				offset, size);

			type = change_param_type(type);

			param->params[idx].shm =
				tee_session_shm_create(ctx, tee,
				       &param->c_shm[idx],
				       offset, param->c_shm[idx].size, type);

			if (IS_ERR_OR_NULL(param->params[idx].shm))
				return PTR_ERR(param->params[idx].shm);

			break;

		default:
			BUG_ON(1);
		}

		param->type |= (type << (idx * 4));
	}
	res = 0;

out:
	tee_dbg(tee, "%s: < fd=%d\n", __func__, res);
	return res;
}

static int copy_ta_uuid(struct tee_context *ctx,
			struct tee_cmd_io *cmd_io,
			struct tee_cmd *cmd)
{
	int ret = 0;

	if (cmd_io->uuid != NULL) {
		tee_dbg(ctx->tee, "%s: copy UUID value...\n", __func__);
		cmd->uuid =
		    tee_context_alloc_shm_tmp(ctx, sizeof(*cmd_io->uuid),
					      cmd_io->uuid, TEEC_MEM_INPUT);
		ret = IS_ERR(cmd->uuid);
	}

	return ret;
}

static int copy_ta_image(struct tee_context *ctx, struct tee_cmd_io *cmd_io,
			  struct tee_cmd *cmd)
{
	int res = -EINVAL;
	struct tee *tee = ctx->tee;

	tee_dbg(tee, "%s: > data=%p uuid=%p\n", __func__,
		     cmd_io->data, cmd_io->uuid);

	if (((cmd_io->data != NULL) && (cmd_io->data_size == 0)) ||
	    ((cmd_io->data == NULL) && (cmd_io->data_size != 0)))
		goto out_failed;

	if ((cmd_io->data != NULL) && (cmd_io->data_size > 0)) {
		tee_dbg(tee, "%s: copy DATA image (s=%d)...\n",
			__func__,
			cmd_io->data_size);
		cmd->ta =
		    tee_context_alloc_shm_tmp(ctx, cmd_io->data_size,
					      cmd_io->data, TEEC_MEM_INPUT);
		if (IS_ERR_OR_NULL(cmd->ta))
			goto out_failed;
	}

	res = 0;
	goto out;

out_failed:
	tee_shm_free(cmd->uuid);
	tee_shm_free(cmd->ta);

out:
	tee_dbg(tee, "%s: < res=%d", __func__, res);
	return res;
}

static int init_tee_cmd(struct tee_context *ctx, struct tee_cmd_io *cmd_io,
			 struct tee_cmd *cmd)
{
	int ret = -EINVAL;
	struct tee *tee = ctx->tee;

	tee_dbg(tee, "%s: > set tee_cmd...\n", __func__);

	memset(cmd, 0, sizeof(struct tee_cmd));

	cmd->cmd = cmd_io->cmd;
	cmd->origin = TEEC_ORIGIN_TEE;
	cmd->err = TEEC_ERROR_BAD_PARAMETERS;
	cmd_io->origin = cmd->origin;
	cmd_io->err = cmd->err;

	ret = copy_op_params(ctx, cmd_io, cmd);
	if (ret == 0) {
		ret = copy_ta_image(ctx, cmd_io, cmd);
		if (ret == 0)
			ret = copy_ta_uuid(ctx, cmd_io, cmd);
	}

	if (ret)
		release_tee_cmd(ctx, cmd);

	tee_dbg(tee, "%s: < ret=%d\n", __func__, ret);

	return ret;
}

static void update_client_tee_cmd(struct tee_context *ctx,
				   struct tee_cmd_io *cmd_io,
				   struct tee_cmd *cmd)
{
	int idx;
	struct tee *tee = ctx->tee;

	BUG_ON(!cmd_io);
	BUG_ON(!cmd_io->op);
	BUG_ON(!cmd_io->op->params);
	BUG_ON(!cmd);
	BUG_ON(!ctx);

	tee_dbg(tee, "%s: returned err=0x%08x (origin=%d)\n", __func__,
		cmd->err, cmd->origin);

	cmd_io->origin = cmd->origin;
	cmd_io->err = cmd->err;

	if (cmd->param.type_original == TEEC_PARAM_TYPES(TEEC_NONE,
			TEEC_NONE, TEEC_NONE, TEEC_NONE))
		return;

	for (idx = 0; idx < TEEC_CONFIG_PAYLOAD_REF_COUNT; ++idx) {
		int type = TEEC_PARAM_TYPE_GET(cmd->param.type_original, idx);

		tee_dbg(tee, "%s: id %d type %d\n", __func__, idx, type);
		switch (type) {
		case TEEC_NONE:
		case TEEC_VALUE_INPUT:
		case TEEC_MEMREF_TEMP_INPUT:
		case TEEC_MEMREF_PARTIAL_INPUT:
			break;
		case TEEC_VALUE_OUTPUT:
		case TEEC_VALUE_INOUT:{
				tee_dbg(tee, "%s: a=%08x, b=%08x\n",
					__func__,
					cmd->param.params[idx].value.a,
					cmd->param.params[idx].value.b);
				if (tee_context_copy(false,
				     ctx, &cmd_io->op->params[idx].value,
				     &cmd->param.params[idx].value,
				     sizeof(cmd_io->op->params[idx].value)))
					tee_err(tee,
						"%s:%d: can't update %d result to user\n",
						__func__, __LINE__, idx);
				break;
			}
		case TEEC_MEMREF_TEMP_OUTPUT:
		case TEEC_MEMREF_TEMP_INOUT:{
				/* Returned updated size */
				size_t size =
					cmd->param.params[idx].shm->size_req;
				if (size !=
					cmd_io->op->params[idx].tmpref.size) {
					tee_dbg(tee,
						"Size has been updated by the TA %zu != %zu\n",
						size,
						cmd_io->op->params[idx].tmpref.
						size);
					tee_context_copy_simple(ctx, size,
						     &cmd_io->op->params[idx].
						     tmpref.size);
				}

				BUG_ON(!cmd->param.params[idx].shm);
				BUG_ON(!
				       (cmd->param.params[idx].shm->
					flags & TEE_SHM_TEMP));
				tee_dbg(tee, "%s: tmpref %p\n", __func__,
					cmd->param.params[idx].shm->kaddr);

				/* ensure we do not exceed
				 * the shared buffer length */
				if (size > cmd_io->op->params[idx].tmpref.size)
					tee_err(tee,
						"  *** Wrong returned size from %d:%zu > %zu\n",
						idx, size,
						cmd_io->op->params[idx].tmpref.
						size);

				else if (tee_context_copy(false, ctx,
					  cmd_io->op->params[idx].tmpref.buffer,
					  cmd->param.params[idx].shm->kaddr,
					  size))
					tee_err(tee,
						"%s:%d: can't update %d result to user\n",
						__func__, __LINE__, idx);
				break;
			}
		case TEEC_MEMREF_WHOLE:{
				/* Returned updated size */
				size_t size =
					cmd->param.params[idx].shm->size_req;
				if (size !=
					cmd_io->op->params[idx].memref.size) {
					tee_dbg(tee,
						"Size has been updated by the TA %zu != %zu\n",
						size,
						cmd_io->op->params[idx].memref.
						size);
					tee_context_copy_simple(ctx, size,
						     &cmd_io->op->params[idx].
						     memref.size);
				}

				/* ensure we do not exceed
				 * the shared buffer length */
				if (size > cmd->param.c_shm[idx].size)
					tee_err(tee,
						"  *** Wrong returned size from %d:%zu > %zu\n",
						idx, size,
						cmd->param.c_shm[idx].size);

				else if ((cmd->param.params[idx].shm->flags &
					(TEE_SHM_MAPPED | TEE_SHM_TEMP)) ==
					(TEE_SHM_MAPPED | TEE_SHM_TEMP)) {
					BUG_ON(!cmd->param.c_shm[idx].buffer);
					BUG_ON(!cmd->param.c_shm[idx].size > 0);
					tee_dbg(tee, "%s: whole %p\n",
						__func__,
						cmd->param.params[idx].shm->
						kaddr);
					if (tee_context_copy(false, ctx,
					     cmd->param.c_shm[idx].buffer,
					     cmd->param.params[idx].shm->kaddr,
					     size))
						tee_err(tee,
							"%s: can't update %d result to user\n",
							__func__, idx);
				}
				break;
			}
		case TEEC_MEMREF_PARTIAL_OUTPUT:
		case TEEC_MEMREF_PARTIAL_INOUT:{
				int offset =
				    cmd_io->op->params[idx].memref.offset;
				/* Returned updated size */
				size_t size =
					cmd->param.params[idx].shm->size_req;

				if (size !=
					cmd_io->op->params[idx].memref.size) {
					tee_dbg(tee,
						"Size has been updated by the TA %zu != %zu\n",
						size,
						cmd_io->op->params[idx].memref.
						size);
					tee_context_copy_simple(ctx, size,
						     &cmd_io->op->params[idx].
						     memref.size);
				}

				/* ensure we do not exceed
				 * the shared buffer length */
				if ((offset + size) >
				    cmd->param.c_shm[idx].size)
					tee_err(tee,
						"  *** Wrong returned size from %d:%d +%zu > %zu\n",
						idx, offset, size,
						cmd->param.c_shm[idx].size);

				/* If we allocated a tmpref buffer,
				 * copy back data to the user buffer */
				else if ((cmd->param.params[idx].shm->flags &
					(TEE_SHM_MAPPED | TEE_SHM_TEMP)) ==
					(TEE_SHM_MAPPED | TEE_SHM_TEMP)) {
					BUG_ON(!cmd->param.c_shm[idx].buffer);
					BUG_ON(!cmd->param.c_shm[idx].size > 0);
					if (tee_context_copy(false, ctx,
					     cmd->param.c_shm[idx].buffer +
					     offset,
					     cmd->param.params[idx].shm->kaddr,
					     size))
						tee_err(tee,
							"%s: can't update %d result to user\n",
							__func__, idx);
				}
				break;
			}
		default:
			BUG_ON(1);
		}
	}

}

static void release_tee_cmd(struct tee_context *ctx, struct tee_cmd *cmd)
{
	int idx;
	struct tee *tee = ctx->tee;

	BUG_ON(!cmd);
	BUG_ON(!ctx);
	BUG_ON(!ctx->tee);

	ctx = ctx;

	tee_dbg(tee, "%s: > free the temporary objects...\n", __func__);

	tee_shm_free(cmd->ta);
	tee_shm_free(cmd->uuid);

	if (cmd->param.type_original == TEEC_PARAM_TYPES(TEEC_NONE,
			TEEC_NONE, TEEC_NONE, TEEC_NONE))
		goto out;

	for (idx = 0; idx < TEEC_CONFIG_PAYLOAD_REF_COUNT; ++idx) {
		int type = TEEC_PARAM_TYPE_GET(cmd->param.type_original, idx);

		switch (type) {
		case TEEC_NONE:
		case TEEC_VALUE_INPUT:
		case TEEC_VALUE_OUTPUT:
		case TEEC_VALUE_INOUT:
			break;
		case TEEC_MEMREF_TEMP_INPUT:
		case TEEC_MEMREF_TEMP_OUTPUT:
		case TEEC_MEMREF_TEMP_INOUT:
		case TEEC_MEMREF_WHOLE:
		case TEEC_MEMREF_PARTIAL_INPUT:
		case TEEC_MEMREF_PARTIAL_OUTPUT:
		case TEEC_MEMREF_PARTIAL_INOUT:
			if (IS_ERR_OR_NULL(cmd->param.params[idx].shm))
				break;

			if ((cmd->param.params[idx].shm->flags &
				(TEE_SHM_MAPPED | TEE_SHM_TEMP)) ==
				(TEE_SHM_MAPPED | TEE_SHM_TEMP)) {
				tee_shm_free(cmd->param.params[idx].shm);
			} else {
				BUG_ON(!cmd->param.params[idx].shm->parent);
				tee_shm_free(
					cmd->param.params[idx].shm->parent);
				BUG_ON(!(cmd->param.params[idx].shm->flags &
						TEE_SHM_PARENT));
				devm_kfree(ctx->tee->dev,
						cmd->param.params[idx].shm);
			}
			break;
		default:
			BUG_ON(1);
		}
	}

out:
	memset(cmd, 0, sizeof(struct tee_cmd));
	tee_dbg(tee, "%s: <\n", __func__);
}
