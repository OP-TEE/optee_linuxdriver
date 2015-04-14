#include <linux/slab.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/file.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/sched.h>

#include <optee/tee_shm.h>

#include "tee_core_priv.h"

#define TEE_CONTEXT_DUMP_MIN_LEN 80

/**
 * tee_context_dump -	Dump in a buffer the information (ctx, sess & shm)
 *			associated to a TEE.
 */
int tee_context_dump(struct tee *tee, char *buff, size_t len)
{
	struct list_head *ptr_ctx, *ptr_sess, *ptr_shm;
	struct tee_context *ctx;
	struct tee_session *sess;
	struct tee_shm *shm;
	int i = 0;
	int j = 0;
	int pos = 0;

	BUG_ON(!tee);

	if (len < TEE_CONTEXT_DUMP_MIN_LEN || list_empty(&tee->list_ctx))
		return 0;

	mutex_lock(&tee->lock);

	list_for_each(ptr_ctx, &tee->list_ctx) {
		ctx = list_entry(ptr_ctx, struct tee_context, entry);

		pos += sprintf(buff + pos,
				"[%02d] ctx=%p (refcount=%d) (usr=%d)",
				i, ctx,
				(int)atomic_read(&ctx->refcount.
					refcount),
				ctx->usr_client);
		pos += sprintf(buff + pos, "name=\"%s\" (tgid=%d)\n",
				ctx->name,
				ctx->tgid);
		if ((len - pos) < TEE_CONTEXT_DUMP_MIN_LEN) {
			pos = 0;
			goto out;
		}

		if (list_empty(&ctx->list_sess))
			goto out;

		j = 0;
		list_for_each(ptr_sess, &ctx->list_sess) {
			sess = list_entry(ptr_sess,
					struct tee_session,
					entry);

			pos += sprintf(buff + pos,
					"[%02d.%d] sess=%p sessid=%08x\n",
					i, j, sess,
					sess->sessid);

			if ((len - pos) < TEE_CONTEXT_DUMP_MIN_LEN) {
				pos = 0;
				goto out;
			}

			j++;
		}

		if (list_empty(&ctx->list_shm))
			goto out;

		j = 0;
		list_for_each(ptr_shm, &ctx->list_shm) {
			shm = list_entry(ptr_shm, struct tee_shm, entry);

			pos += sprintf(buff + pos,
					"[%02d.%d] shm=%p paddr=%p kaddr=%p",
					i, j, shm,
					&shm->paddr,
					shm->kaddr);
			pos += sprintf(buff + pos,
					" s=%zu(%zu)\n",
					shm->size_req,
					shm->size_alloc);
			if ((len - pos) < TEE_CONTEXT_DUMP_MIN_LEN) {
				pos = 0;
				goto out;
			}

			j++;
		}

		i++;
	}

out:
	mutex_unlock(&tee->lock);
	return pos;
}

/**
 * tee_context_create - Allocate and create a new context.
 *			Reference on the back-end is requested.
 */
struct tee_context *tee_context_create(struct tee *tee)
{
	int ret;
	struct tee_context *ctx;

	tee_dbg(tee, "%s: >\n", __func__);

	ctx = devm_kzalloc(TEE_DEV(tee),
			   sizeof(struct tee_context), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	kref_init(&ctx->refcount);
	INIT_LIST_HEAD(&ctx->list_sess);
	INIT_LIST_HEAD(&ctx->list_shm);

	ctx->tee = tee;
	snprintf(ctx->name, sizeof(ctx->name), "%s", current->comm);
	ctx->tgid = current->tgid;

	ret = tee_get(tee);
	if (ret) {
		devm_kfree(TEE_DEV(tee), ctx);
		return ERR_PTR(ret);
	}

	mutex_lock(&tee->lock);
	tee_inc_stats(&tee->stats[TEE_STATS_CONTEXT_IDX]);
	list_add_tail(&ctx->entry, &tee->list_ctx);
	mutex_unlock(&tee->lock);

	tee_dbg(ctx->tee, "%s: < ctx=%p is created\n", __func__, ctx);
	return ctx;
}

/**
 * tee_context_do_release - Final function to release
 *                           and free a context.
 */
static void tee_context_do_release(struct kref *kref)
{
	struct tee_context *ctx;
	struct tee *tee;

	ctx = container_of(kref, struct tee_context, refcount);

	BUG_ON(!ctx || !ctx->tee);

	tee = ctx->tee;

	tee_dbg(tee, "%s: > ctx=%p\n", __func__, ctx);

	mutex_lock(&tee->lock);
	tee_dec_stats(&tee->stats[TEE_STATS_CONTEXT_IDX]);
	list_del(&ctx->entry);
	mutex_unlock(&tee->lock);

	devm_kfree(TEE_DEV(tee), ctx);
	tee_put(tee);

	tee_dbg(tee, "%s: < ctx=%p is destroyed\n", __func__, ctx);
}

/**
 * tee_context_get - Increase the reference count of
 *                   the context.
 */
void tee_context_get(struct tee_context *ctx)
{
	BUG_ON(!ctx || !ctx->tee);

	kref_get(&ctx->refcount);

	tee_dbg(ctx->tee, "%s: ctx=%p, kref=%d\n", __func__,
		ctx, (int)atomic_read(&ctx->refcount.refcount));
}

static int is_in_list(struct tee *tee, struct list_head *entry)
{
	int present = 1;

	mutex_lock(&tee->lock);
	if ((entry->next == LIST_POISON1) && (entry->prev == LIST_POISON2))
		present = 0;
	mutex_unlock(&tee->lock);
	return present;
}

/**
 * tee_context_put - Decreases the reference count of
 *                   the context. If 0, the final
 *                   release function is called.
 */
void tee_context_put(struct tee_context *ctx)
{
	struct tee_context *_ctx = ctx;
	struct tee *tee;

	BUG_ON(!ctx || !ctx->tee);
	tee = ctx->tee;

	if (!is_in_list(tee, &ctx->entry))
		return;

	kref_put(&ctx->refcount, tee_context_do_release);

	tee_dbg(tee, "%s: ctx=%p, kref=%d\n", __func__,
		_ctx, (int)atomic_read(&ctx->refcount.refcount));
}

/**
 * tee_context_destroy - Request to destroy a context.
 */
void tee_context_destroy(struct tee_context *ctx)
{
	struct tee *tee;

	if (!ctx || !ctx->tee)
		return;

	tee = ctx->tee;

	tee_dbg(tee, "%s: ctx=%p\n", __func__, ctx);

	tee_context_put(ctx);
}

int tee_context_copy(bool from_user, struct tee_context *ctx,
			void *to, const void *from, size_t size)
{
	int ret = 0;

	if (size <= 0 || to == NULL || from == NULL)
		return -EINVAL;

	if (!ctx->usr_client) {
		memcpy(to, from, size);
		return 0;
	} else if (from_user)
		ret = copy_from_user(to, from, size);
	else
		ret = copy_to_user(to, from, size);

	return ret;
}

struct tee_shm *tee_context_alloc_shm_tmp(struct tee_context *ctx,
					  size_t size, const void *data,
					  int type)
{
	struct tee_shm *shm;

	type &= (TEEC_MEM_INPUT | TEEC_MEM_OUTPUT);

	shm = tee_shm_alloc(ctx, size, TEE_SHM_MAPPED | TEE_SHM_TEMP | type);
	if (IS_ERR_OR_NULL(shm)) {
		tee_err(ctx->tee, "%s: buffer allocation failed (%ld)\n",
			__func__, PTR_ERR(shm));
		return shm;
	}

	if (type & TEEC_MEM_INPUT) {
		if (tee_context_copy(true, ctx, shm->kaddr, data, size)) {
			tee_err(ctx->tee, "%s: tee_context_copy failed\n",
					__func__);
			tee_shm_free(shm);
			shm = NULL;
		}
	}

	return shm;
}

struct tee_shm *tee_context_create_tmpref_buffer(struct tee_context *ctx,
						 size_t size,
						 const void *buffer, int type)
{
	struct tee_shm *shm = NULL;
	int flags;

	switch (type) {
	case TEEC_MEMREF_TEMP_OUTPUT:
		flags = TEEC_MEM_OUTPUT;
		break;
	case TEEC_MEMREF_TEMP_INPUT:
		flags = TEEC_MEM_INPUT;
		break;
	case TEEC_MEMREF_TEMP_INOUT:
		flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
		break;
	default:
		BUG_ON(1);
	};
	shm = tee_context_alloc_shm_tmp(ctx, size, buffer, flags);
	return shm;
}
