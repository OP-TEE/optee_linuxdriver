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
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/anon_inodes.h>
#include <linux/semaphore.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/device.h>

#include "tee-op.h"
#include "tee_mem.h"
#include "tee_service.h"
#include "tee_supp_com.h"
#include "tee_driver.h"

enum teec_rpc_result tee_supp_cmd(struct tee_targetop *op,
					     uint32_t id, void *data,
					     unsigned int datalen)
{
	struct device *dev = op->miscdev->this_device;
	struct tee_rpc_priv_data *rpc = &tee_get_drvdata(dev)->rpc;
	enum teec_rpc_result res = TEEC_RPC_FAIL;
	size_t size; /* size of block */
	struct task_struct *task = current;

	dev_dbg(dev, "> tgid:[%d] op:[0x%p] id:[0x%x]\n",
		task->tgid, (void *)op, id);

	switch (id) {
	case TEE_RPC_ICMD_ALLOCATE:
		{
			struct tee_rpc_alloc *alloc;
			struct tee_shm *shmint;

			alloc = (struct tee_rpc_alloc *)data;
			size = alloc->size;
			memset(alloc, 0, sizeof(struct tee_rpc_alloc));
			shmint = tee_shm_allocate(op, 0, size, 0);
			if (shmint == NULL)
				break;

			alloc->size = size;
			alloc->data = (void *)shmint->paddr;
			alloc->shm = shmint;
			res = TEEC_RPC_OK;

			break;
		}
	case TEE_RPC_ICMD_FREE:
		{
			struct tee_rpc_free *free;

			free = (struct tee_rpc_free *)data;
			tee_shm_unallocate(free->shm);
			res = TEEC_RPC_OK;
			break;
		}
	case TEE_RPC_ICMD_INVOKE:
		{
			if (sizeof(rpc->commToUser) < datalen)
				break;

			/*
			 * Don't allow interleaved requests (from two
			 * different threads) as the second request will
			 * overwrite the first request.
			 */
			mutex_lock(&rpc->reqsync);

			mutex_lock(&rpc->outsync);

			memcpy(&rpc->commToUser, data, datalen);

			mutex_unlock(&rpc->outsync);

			dev_dbg(dev, "Supplicant Cmd: %x. Give hand to supplicant\n",
					rpc->commToUser.cmd);

			up(&rpc->datatouser);

			down(&rpc->datafromuser);

			dev_dbg(dev, "Supplicant Cmd: %x. Give hand to fw\n",
					rpc->commToUser.cmd);

			mutex_lock(&rpc->insync);

			memcpy(data, &rpc->commFromUser, datalen);

			mutex_unlock(&rpc->insync);

			mutex_unlock(&rpc->reqsync);

			res = TEEC_RPC_OK;

			break;
		}
	default:
		/* not supported */
		break;
	}

	dev_dbg(dev, "< res: [%d]\n", res);

	return res;
}

ssize_t tee_supp_read(struct file *filp, char __user *buffer,
			 size_t length, loff_t *offset)
{
	struct tee_session *ts = (struct tee_session *)(filp->private_data);
	struct device *dev = ts->op->miscdev->this_device;
	struct tee_rpc_priv_data *rpc = &tee_get_drvdata(dev)->rpc;
	struct task_struct *task = current;
	int ret;

	if (down_interruptible(&rpc->datatouser))
		return -ERESTARTSYS;

	dev_dbg(dev, "> tgid:[%d] ts:[0x%p]\n", task->tgid, (void *)ts);

	mutex_lock(&rpc->outsync);

	ret =
	    sizeof(rpc->commToUser) - sizeof(rpc->commToUser.cmds) +
	    sizeof(rpc->commToUser.cmds[0]) * rpc->commToUser.nbr_bf;
	if (length < ret) {
		ret = -EINVAL;
	} else {
		if (copy_to_user(buffer, &rpc->commToUser, ret)) {
			dev_err(dev,
				"[%s] error, copy_to_user failed!\n", __func__);
			ret = -EINVAL;
		}
	}

	mutex_unlock(&rpc->outsync);

	dev_dbg(dev, "< [%d]\n", ret);
	return ret;
}

ssize_t tee_supp_write(struct file *filp, const char __user *buffer,
			  size_t length, loff_t *offset)
{
	struct tee_session *ts = (struct tee_session *)(filp->private_data);
	struct device *dev = ts->op->miscdev->this_device;
	struct tee_rpc_priv_data *rpc = &tee_get_drvdata(dev)->rpc;
	struct task_struct *task = current;
	dev_dbg(dev, "> tgid:[%d] ts:[0x%p]\n", task->tgid, (void *)ts);

	if (length > 0 && length < sizeof(rpc->commFromUser)) {
		uint32_t i;

		mutex_lock(&rpc->insync);

		if (copy_from_user(&rpc->commFromUser, buffer, length)) {
			dev_err(dev,
				"[%s] error, tee_session copy_from_user failed\n",
				__func__);
			mutex_unlock(&rpc->insync);
			return -EINVAL;
		}

		/* Translate virtual address of caller into physical address */
		for (i = 0; i < rpc->commFromUser.nbr_bf; i++) {
			if (rpc->commFromUser.cmds[i].type == TEE_RPC_BUFFER &&
			    rpc->commFromUser.cmds[i].buffer) {
				struct vm_area_struct *vma =
				    find_vma(current->mm,
					     (unsigned long)rpc->commFromUser.
					     cmds[i].buffer);
				if (vma != NULL) {

					unsigned long paddr =
					    (unsigned long)vma->vm_private_data;

					dev_dbg(dev, " gid2pa(0x%p => %lx)\n",
						rpc->
						commFromUser.cmds[i].buffer,
						paddr);
					rpc->commFromUser.cmds[i].buffer =
					(void *)paddr;
				} else
				       dev_dbg(dev,
					       " gid2pa(0x%p => NULL\n)",
				       rpc->commFromUser.cmds[i].buffer);
			}
		}

		mutex_unlock(&rpc->insync);
		up(&rpc->datafromuser);
		dev_dbg(dev, "< [%zu]\n", length);
		return length;
	}

	dev_dbg(dev, "< [0]\n");
	return 0;
}

int tee_supp_init(struct tee_rpc_priv_data *rpc)
{
	rpc->datafromuser = (struct semaphore)
		__SEMAPHORE_INITIALIZER(rpc->datafromuser, 0);
	rpc->datatouser = (struct semaphore)
		__SEMAPHORE_INITIALIZER(rpc->datatouser, 0);
	mutex_init(&rpc->outsync);
	mutex_init(&rpc->insync);
	mutex_init(&rpc->reqsync);
	return 0;
}

void tee_supp_exit(void)
{
}

