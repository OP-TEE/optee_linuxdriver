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
#include <linux/types.h>
#include <linux/dma-buf.h>

#include <linux/sched.h>
#include <linux/mm.h>

#include "tee_core_priv.h"
#include "tee_shm.h"

#define INMSG dev_dbg(_DEV(tee), "%s: >\n", __func__)
#define OUTMSG(val) \
	dev_dbg(_DEV(tee), "%s: < %lld\n", __func__, \
		(long long int)(uintptr_t)val)

/* TODO
#if (sizeof(TEEC_SharedMemory) != sizeof(tee_shm))
#error "sizeof(TEEC_SharedMemory) != sizeof(tee_shm))"
#endif
*/

struct tee_shm *tee_shm_alloc_from_rpc(struct tee *tee, size_t size,
				       uint32_t flags)
{
	struct tee_shm *shm;

	INMSG;

	shm = tee->ops->alloc(tee, size, flags);
	if (IS_ERR_OR_NULL(shm)) {
		dev_err(_DEV(tee),
			"%s: allocation failed (s=%d,flags=0x%08x) err=%ld\n",
			__func__, (int)size, flags, PTR_ERR(shm));
		shm = NULL;
	} else {
		mutex_lock(&tee->lock);
		tee_inc_stats(&tee->stats[TEE_STATS_SHM_IDX]);
		list_add_tail(&shm->entry, &tee->list_rpc_shm);
		mutex_unlock(&tee->lock);
		shm->ctx = NULL;
		shm->tee = tee;
	}

	OUTMSG(shm);
	return shm;
}
EXPORT_SYMBOL(tee_shm_alloc_from_rpc);

void tee_shm_free_from_rpc(struct tee_shm *shm)
{
	if (shm == NULL)
		return;
	if (shm->ctx == NULL) {
		mutex_lock(&shm->tee->lock);
		tee_dec_stats(&shm->tee->stats[TEE_STATS_SHM_IDX]);
		list_del(&shm->entry);
		mutex_unlock(&shm->tee->lock);
		shm->tee->ops->free(shm);
	} else
		tee_shm_free(shm);
}
EXPORT_SYMBOL(tee_shm_free_from_rpc);


struct tee_shm *tee_shm_alloc(struct tee_context *ctx, size_t size,
			      uint32_t flags)
{
	struct tee_shm *shm;
	struct tee *tee;

	BUG_ON(!ctx);
	BUG_ON(!ctx->tee);

	tee = ctx->tee;

	INMSG;

	if (!ctx->usr_client)
		flags |= TEE_SHM_FROM_KAPI;

	shm = tee->ops->alloc(tee, size, flags);
	if (IS_ERR_OR_NULL(shm)) {
		dev_err(_DEV(tee),
			"%s: allocation failed (s=%d,flags=0x%08x) err=%ld\n",
			__func__, (int)size, flags, PTR_ERR(shm));
	} else {
		shm->ctx = ctx;
		shm->tee = tee;

		dev_dbg(_DEV(ctx->tee), "%s: shm=%p, paddr=%p,s=%d/%d app=\"%s\" pid=%d\n",
			 __func__, shm, (void *)shm->paddr, (int)shm->size_req,
			 (int)shm->size_alloc, current->comm, current->pid);
	}



	OUTMSG(shm);
	return shm;
}

void tee_shm_free(struct tee_shm *shm)
{
	struct tee *tee;

	if (IS_ERR_OR_NULL(shm))
		return;
	tee = shm->tee;
	if (tee == NULL)
		pr_warn("invalid call to tee_shm_free(%p): NULL tee\n", shm);
	else if (shm->ctx == NULL)
		dev_warn(_DEV(tee), "tee_shm_free(%p): NULL context\n", shm);
	else if (shm->ctx->tee == NULL)
		dev_warn(_DEV(tee), "tee_shm_free(%p): NULL tee\n", shm);
	else
		shm->ctx->tee->ops->free(shm);
}

/*
 * tee_shm dma_buf operations
 */
static struct sg_table *_tee_shm_dmabuf_map_dma_buf(struct dma_buf_attachment
						    *attach,
						    enum dma_data_direction dir)
{
	return NULL;
}

static void _tee_shm_dmabuf_unmap_dma_buf(struct dma_buf_attachment *attach,
					  struct sg_table *table,
					  enum dma_data_direction dir)
{
	return;
}

static void _tee_shm_dmabuf_release(struct dma_buf *dmabuf)
{
	struct tee_shm *shm = dmabuf->priv;
	struct device *dev;
	struct tee_context *ctx;
	struct tee *tee;
	BUG_ON(!shm);
	BUG_ON(!shm->ctx);
	BUG_ON(!shm->ctx->tee);
	tee = shm->ctx->tee;

	INMSG;

	ctx = shm->ctx;
	dev = shm->dev;
	dev_dbg(_DEV(ctx->tee), "%s: shm=%p, paddr=%p,s=%d/%d app=\"%s\" pid=%d\n",
		 __func__, shm, (void *)shm->paddr, (int)shm->size_req,
		 (int)shm->size_alloc, current->comm, current->pid);

	mutex_lock(&ctx->tee->lock);
	tee_dec_stats(&tee->stats[TEE_STATS_SHM_IDX]);
	list_del(&shm->entry);
	mutex_unlock(&ctx->tee->lock);

	tee_shm_free(shm);
	tee_put(ctx->tee);
	tee_context_put(ctx);
	if (dev)
		put_device(dev);

	OUTMSG(0);
}

static int _tee_shm_dmabuf_mmap(struct dma_buf *dmabuf,
				struct vm_area_struct *vma)
{
	struct tee_shm *shm = dmabuf->priv;
	size_t size = vma->vm_end - vma->vm_start;
	struct tee *tee;
	int ret;
	pgprot_t prot;
	BUG_ON(!shm);
	BUG_ON(!shm->ctx);
	BUG_ON(!shm->ctx->tee);
	tee = shm->ctx->tee;

	INMSG;

	if (shm->flags & TEE_SHM_CACHED)
		prot = vma->vm_page_prot;
	else
		prot = pgprot_noncached(vma->vm_page_prot);

	ret =
	    remap_pfn_range(vma, vma->vm_start, shm->paddr >> PAGE_SHIFT, size,
			    prot);
	if (!ret)
		vma->vm_private_data = (void *)shm;

	dev_dbg(_DEV(shm->ctx->tee), "%s: map the shm (p@=%p,s=%dKiB) => %x\n",
		__func__, (void *)shm->paddr, (int)size / 1024,
		(unsigned int)vma->vm_start);

	OUTMSG(ret);
	return ret;
}

static void *_tee_shm_dmabuf_kmap_atomic(struct dma_buf *dmabuf,
					 unsigned long pgnum)
{
	return NULL;
}

static void *_tee_shm_dmabuf_kmap(struct dma_buf *dmabuf, unsigned long pgnum)
{
	return NULL;
}

struct dma_buf_ops _tee_shm_dma_buf_ops = {
	.map_dma_buf = _tee_shm_dmabuf_map_dma_buf,
	.unmap_dma_buf = _tee_shm_dmabuf_unmap_dma_buf,
	.release = _tee_shm_dmabuf_release,
	.kmap_atomic = _tee_shm_dmabuf_kmap_atomic,
	.kmap = _tee_shm_dmabuf_kmap,
	.mmap = _tee_shm_dmabuf_mmap,
};

static int get_fd(struct tee *tee, struct tee_shm *shm)
{
	struct dma_buf *dmabuf;
	int fd = -1;

	dmabuf = dma_buf_export(shm, &_tee_shm_dma_buf_ops, shm->size_alloc,
				O_RDWR, NULL);
	if (IS_ERR_OR_NULL(dmabuf)) {
		dev_err(_DEV(tee), "%s: dmabuf: couldn't export buffer (%ld)\n",
			__func__, PTR_ERR(dmabuf));
		goto out;
	}

	fd = dma_buf_fd(dmabuf, O_CLOEXEC);

out:
	OUTMSG(fd);
	return fd;
}

int tee_shm_alloc_fd(struct tee_context *ctx, struct tee_shm_io *shm_io)
{
	struct tee_shm *shm;
	struct tee *tee = ctx->tee;
	int ret;

	INMSG;

	shm_io->fd_shm = 0;

	shm = tee_shm_alloc(ctx, shm_io->size, shm_io->flags);
	if (IS_ERR_OR_NULL(shm)) {
		dev_err(_DEV(tee), "%s: buffer allocation failed (%ld)\n",
			__func__, PTR_ERR(shm));
		return PTR_ERR(shm);
	}

	shm_io->fd_shm = get_fd(tee, shm);
	if (shm_io->fd_shm <= 0) {
		tee_shm_free(shm);
		ret = -ENOMEM;
		goto out;
	}
	shm->dev = get_device(tee->dev);
	ret = tee_get(tee);
	BUG_ON(ret);		/* tee_core_get must not issue */
	tee_context_get(ctx);

	mutex_lock(&tee->lock);
	tee_inc_stats(&tee->stats[TEE_STATS_SHM_IDX]);
	list_add_tail(&shm->entry, &ctx->list_shm);
	mutex_unlock(&tee->lock);
out:
	OUTMSG(ret);
	return ret;
}

/* Buffer allocated by rpc from fw and to be accessed by the user
 * Not need to be registered as it is not allocated by the user */
int tee_shm_get_fd(struct tee_context *ctx, struct tee_shm_io *shm_io)
{
	struct tee_shm *shm = NULL;
	struct tee *tee = ctx->tee;
	int ret;
	struct list_head *pshm;

	INMSG;

	shm_io->fd_shm = 0;

	if (!list_empty(&tee->list_rpc_shm)) {
		list_for_each(pshm, &tee->list_rpc_shm) {
			shm = list_entry(pshm, struct tee_shm, entry);
			if ((void *)shm->paddr == shm_io->buffer)
				goto found;
		}
	}

	dev_err(tee->dev, "Can't find shm for %p\n", (void *)shm_io->buffer);
	ret = -ENOMEM;
	goto out;

found:
	shm_io->fd_shm = get_fd(tee, shm);
	if (shm_io->fd_shm <= 0) {
		tee_shm_free(shm);
		ret = -ENOMEM;
		goto out;
	}

	shm->ctx = ctx;
	ret = tee->ops->shm_inc_ref(shm);
	BUG_ON(!ret);		/* to do: path error */
	mutex_lock(&tee->lock);
	list_move(&shm->entry, &ctx->list_shm);
	mutex_unlock(&tee->lock);

	shm->dev = get_device(tee->dev);
	ret = tee_get(tee);
	BUG_ON(ret);
	tee_context_get(ctx);

out:
	OUTMSG(ret);
	return ret;
}

int check_shm(struct tee *tee, struct tee_shm_io *shm_io)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	struct tee_shm *shm;
	int ret = 0;

	INMSG;

	if (shm_io->flags & TEE_SHM_FROM_KAPI) {
		/* TODO fixme will not work on 64-bit platform */
		shm = (struct tee_shm *)(uintptr_t)shm_io->fd_shm;
		BUG_ON(!shm);
		/* must be size_req but not in line with above test */
		if (shm->size_req < shm_io->size) {
			dev_err(tee->dev, "[%s] %p not big enough %x %zu %zu\n",
				__func__, shm_io->buffer,
				(unsigned int)shm->paddr, shm->size_req,
				shm_io->size);
			ret = -EINVAL;
		}
		goto out;
	}

	/* if the caller is the kernel api, active_mm is mm */
	if (!mm)
		mm = current->active_mm;

	vma = find_vma(mm, (unsigned long)shm_io->buffer);
	if (!vma) {
		dev_err(tee->dev, "[%s] %p can't find vma\n", __func__,
			shm_io->buffer);
		ret = -EINVAL;
		goto out;
	}

	shm = vma->vm_private_data;

	/* It's a VMA => consider it a a user address */
	if (!(vma->vm_flags & (VM_IO | VM_PFNMAP))) {
		dev_err(tee->dev, "[%s] %p not Contiguous %x\n", __func__,
			shm_io->buffer, shm ? (unsigned int)shm->paddr : 0);
		ret = -EINVAL;
		goto out;
	}

	/* Contiguous ? */
	if (vma->vm_end - vma->vm_start < shm_io->size) {
		dev_err(tee->dev, "[%s] %p not big enough %x %ld %zu\n",
			__func__, shm_io->buffer,
			shm ? (unsigned int)shm->paddr : 0,
			vma->vm_end - vma->vm_start, shm_io->size);
		ret = -EINVAL;
	}

out:
	OUTMSG(ret);
	return ret;
}

static dma_addr_t get_phy_addr(struct tee *tee, struct tee_shm_io *shm_io)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	struct tee_shm *shm;

	INMSG;

	/* if the caller is the kernel api, active_mm is mm */
	if (!mm)
		mm = current->active_mm;

	vma = find_vma(mm, (unsigned long)shm_io->buffer);
	BUG_ON(!vma);
	shm = vma->vm_private_data;

	OUTMSG(shm->paddr);
	/* Consider it has been allowd by the TEE */
	return shm->paddr;
}

struct tee_shm *tee_shm_get(struct tee_context *ctx, struct tee_shm_io *shm_io)
{
	struct tee_shm *shm;
	struct list_head *pshm;
	int ret;
	dma_addr_t buffer;
	struct tee *tee = ctx->tee;

	INMSG;

	if (shm_io->flags & TEE_SHM_FROM_KAPI) {
		/* TODO fixme will not work on 64-bit platform */
		shm = (struct tee_shm *)(uintptr_t)shm_io->fd_shm;
		BUG_ON(!shm);
		ret = ctx->tee->ops->shm_inc_ref(shm);
		BUG_ON(!ret);	/* to do: path error */
		OUTMSG(shm);
		return shm;
	}

	buffer = get_phy_addr(ctx->tee, shm_io);
	if (!buffer)
		return NULL;

	if (!list_empty(&ctx->list_shm)) {
		list_for_each(pshm, &ctx->list_shm) {
			shm = list_entry(pshm, struct tee_shm, entry);
			BUG_ON(!shm);
			/* if this ok, do not need to get_phys_addr
			 * if ((void *)shm->kaddr == shm_io->buffer) { */
			if (shm->paddr == buffer) {
				ret = ctx->tee->ops->shm_inc_ref(shm);
				BUG_ON(!ret);
				OUTMSG(shm);
				return shm;
			}
		}
	}
	BUG_ON(1);
	return NULL;
}

void tee_shm_put(struct tee_shm *shm)
{
	tee_shm_free(shm);
}
