/*
* Copyright (C) STMicroelectronics 2014. All rights reserved.
*
* This code is STMicroelectronics proprietary and confidential.
* Any use of the code for whatever purpose is subject to
* specific written permission of STMicroelectronics SA.
*/

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/anon_inodes.h>
#include <linux/semaphore.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/device.h>

#include <optee/tee_shm.h>
#include <optee/tee_core.h>
#include <optee/tee_supp_com.h>

enum teec_rpc_result tee_supp_cmd(struct tee *tee,
				  uint32_t id, void *data, size_t datalen)
{
	struct tee_rpc *rpc = tee->rpc;
	enum teec_rpc_result res = TEEC_RPC_FAIL;
	size_t size;
	struct task_struct *task = current;
	struct tee_rpc_alloc *alloc;
	struct tee_shm *shmint;
	struct tee_rpc_free *free;

	dev_dbg(tee->dev, "> tgid:[%d] id:[0x%08x]\n", task->tgid, id);

	if (atomic_read(&rpc->used) == 0) {
		dev_err(tee->dev, "%s: ERROR Supplicant application NOT ready\n"
				, __func__);
		goto out;
	}

	switch (id) {
	case TEE_RPC_ICMD_ALLOCATE:
		alloc = (struct tee_rpc_alloc *)data;
		size = alloc->size;
		memset(alloc, 0, sizeof(struct tee_rpc_alloc));
		shmint =
			tee_shm_alloc_from_rpc(tee, size,
					TEE_SHM_TEMP |
					TEE_SHM_FROM_RPC);
		if (shmint == NULL)
			break;

		alloc->size = size;
		alloc->data = (void *)shmint->paddr;
		alloc->shm = shmint;
		res = TEEC_RPC_OK;
		break;

	case TEE_RPC_ICMD_FREE:
		free = (struct tee_rpc_free *)data;
		tee_shm_free(free->shm);
		res = TEEC_RPC_OK;
		break;

	case TEE_RPC_ICMD_INVOKE:
		if (sizeof(rpc->comm_to_user) < datalen)
			break;

		mutex_lock(&rpc->out_sync);
		memcpy(&rpc->comm_to_user, data, datalen);
		mutex_unlock(&rpc->out_sync);

		dev_dbg(tee->dev,
				"Supplicant Cmd: %x. Give hand to supplicant\n",
				rpc->comm_to_user.cmd);

		up(&rpc->data_to_user);
		down(&rpc->data_from_user);

		dev_dbg(tee->dev,
				"Supplicant Cmd: %x. Give hand to fw\n",
				rpc->comm_to_user.cmd);

		mutex_lock(&rpc->in_sync);
		memcpy(data, &rpc->comm_from_user, datalen);
		mutex_unlock(&rpc->in_sync);

		res = TEEC_RPC_OK;
		break;

	default:
		/* not supported */
		break;
	}

out:
	dev_dbg(tee->dev, "< res: [%d]\n", res);

	return res;
}
EXPORT_SYMBOL(tee_supp_cmd);

ssize_t tee_supp_read(struct file *filp, char __user *buffer,
		  size_t length, loff_t *offset)
{
	struct tee_context *ctx = (struct tee_context *)(filp->private_data);
	struct tee *tee;
	struct tee_rpc *rpc;
	struct task_struct *task = current;
	int ret;

	BUG_ON(!ctx);
	tee = ctx->tee;
	BUG_ON(!tee);
	BUG_ON(!tee->dev);
	BUG_ON(!tee->rpc);

	dev_dbg(tee->dev, "> ctx %p\n", ctx);

	rpc = tee->rpc;

	if (atomic_read(&rpc->used) == 0) {
		dev_err(tee->dev, "%s: ERROR Supplicant application NOT ready\n"
				, __func__);
		ret = -EPERM;
		goto out;
	}

	if (down_interruptible(&rpc->data_to_user))
		return -ERESTARTSYS;

	dev_dbg(tee->dev, "> tgid:[%d]\n", task->tgid);

	mutex_lock(&rpc->out_sync);

	ret =
	    sizeof(rpc->comm_to_user) - sizeof(rpc->comm_to_user.cmds) +
	    sizeof(rpc->comm_to_user.cmds[0]) * rpc->comm_to_user.num_params;
	if (length < ret) {
		ret = -EINVAL;
	} else {
		if (copy_to_user(buffer, &rpc->comm_to_user, ret)) {
			dev_err(tee->dev,
				"[%s] error, copy_to_user failed!\n", __func__);
			ret = -EINVAL;
		}
	}

	mutex_unlock(&rpc->out_sync);

out:
	dev_dbg(tee->dev, "< [%d]\n", ret);
	return ret;
}

ssize_t tee_supp_write(struct file *filp, const char __user *buffer,
		   size_t length, loff_t *offset)
{
	struct tee_context *ctx = (struct tee_context *)(filp->private_data);
	struct tee *tee;
	struct tee_rpc *rpc;
	struct task_struct *task = current;
	int ret = 0;

	BUG_ON(!ctx);
	BUG_ON(!ctx->tee);
	BUG_ON(!ctx->tee->rpc);
	tee = ctx->tee;
	rpc = tee->rpc;
	dev_dbg(tee->dev, "> tgid:[%d]\n", task->tgid);

	if (atomic_read(&rpc->used) == 0) {
		dev_err(tee->dev, "%s: ERROR Supplicant application NOT ready\n"
				, __func__);
		goto out;
	}

	if (length > 0 && length < sizeof(rpc->comm_from_user)) {
		uint32_t i;

		mutex_lock(&rpc->in_sync);

		if (copy_from_user(&rpc->comm_from_user, buffer, length)) {
			dev_err(tee->dev,
				"%s: ERROR, tee_session copy_from_user failed\n",
				__func__);
			mutex_unlock(&rpc->in_sync);
			ret = -EINVAL;
			goto out;
		}

		/* Translate virtual address of caller into physical address */
		for (i = 0; i < rpc->comm_from_user.num_params; i++) {
			if (rpc->comm_from_user.cmds[i].type == TEE_RPC_BUFFER
			    && rpc->comm_from_user.cmds[i].buffer) {
				struct vm_area_struct *vma =
				    find_vma(current->mm,
					     (unsigned long)rpc->
					     comm_from_user.cmds[i].buffer);
				if (vma != NULL) {
					struct tee_shm *shm =
					    vma->vm_private_data;
					BUG_ON(!shm);
					dev_dbg(tee->dev,
						"%d gid2pa(0x%p => %x)\n", i,
						rpc->comm_from_user.cmds[i].
						buffer,
						(unsigned int)shm->paddr);
					rpc->comm_from_user.cmds[i].buffer =
					    (void *)shm->paddr;
				} else
					dev_dbg(tee->dev,
						" gid2pa(0x%p => NULL\n)",
						rpc->comm_from_user.cmds[i].
						buffer);
			}
		}

		mutex_unlock(&rpc->in_sync);
		up(&rpc->data_from_user);
		ret = length;
	}

out:
	dev_dbg(tee->dev, "< [%d]\n", ret);
	return ret;
}

int tee_supp_init(struct tee *tee)
{
	struct tee_rpc *rpc =
	    devm_kzalloc(tee->dev, sizeof(struct tee_rpc), GFP_KERNEL);
	if (!rpc) {
		dev_err(tee->dev, "%s: can't allocate tee_rpc structure\n",
				__func__);
		return -ENOMEM;
	}

	rpc->data_from_user = (struct semaphore)
	    __SEMAPHORE_INITIALIZER(rpc->data_from_user, 0);
	rpc->data_to_user = (struct semaphore)
	    __SEMAPHORE_INITIALIZER(rpc->data_to_user, 0);
	mutex_init(&rpc->out_sync);
	mutex_init(&rpc->in_sync);
	atomic_set(&rpc->used, 0);
	tee->rpc = rpc;
	return 0;
}

void tee_supp_deinit(struct tee *tee)
{
	devm_kfree(tee->dev, tee->rpc);
	tee->rpc = NULL;
}
