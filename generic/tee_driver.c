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
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "tee-op.h"
#include "tee_supp_com.h"
#include "tee_mem.h"
#include "tee_service.h"
#include "tee_debug.h"
#include "tee_tz.h"
#include "tee_mutex_wait.h"


#include "tee_driver.h"

/******************************************************************************/

static TEEC_Result copy_ta(
	struct device *dev, struct tee_session *ts, struct tee_cmd *ku_buffer)
{
	unsigned long paddr;
	dev_dbg(dev, "> session: [0x%p]\n", ts);

	paddr = tee_shm_pool_alloc(dev, ts->op->Allocator,
				  ku_buffer->data_size, 0);
	if (paddr == 0x0) {
		dev_err(dev, "error, out of memory\n");
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	ts->ta = tee_shm_pool_p2v(dev, ts->op->Allocator, paddr);
	ts->tasize = ku_buffer->data_size;
	ts->tafd = 0;

	if (copy_from_user(ts->ta, ku_buffer->data, ku_buffer->data_size)) {
		tee_shm_pool_free(dev, ts->op->Allocator, paddr,
				  NULL);
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	dev_dbg(dev, "<\n");

	return TEEC_SUCCESS;
}

/*
 * Direct return => Linux Error
 */
static int invoke_command(struct device *dev, struct tee_session *ts,
			  int sec_cmd, struct tee_cmd __user *u_buffer)
{
	struct tee_cmd ku_buffer;
	TEEC_Operation op;
	uint32_t param_type = 0x0;
	TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
	unsigned long tmp_allocated_memories[TEEC_CONFIG_PAYLOAD_REF_COUNT] = {
		0, };
	TEEC_Result res;
	bool ta_allocated = false;
	bool uid_allocated = false;
	int ret = 0;
	unsigned long paddr;

	if (copy_from_user
	    (&ku_buffer, (void *)u_buffer, sizeof(struct tee_cmd))) {
		dev_err(dev, "[%s] copy_from_user failed\n",
			__func__);
		ret = -EINVAL;
		goto exit;
	}

	if (ku_buffer.op == NULL)
		goto inval;

	if (ku_buffer.data && ts->ta == NULL) {
		res = copy_ta(dev, ts, &ku_buffer);
		if (res != TEEC_SUCCESS)
			goto error;
		ta_allocated = true;
	}
	if (ku_buffer.uuid && ts->uuid == NULL) {
		res = allocate_uuid(ts);
		if (res != TEEC_SUCCESS)
			goto error;
		uid_allocated = true;

		if (copy_from_user(
				ts->uuid, ku_buffer.uuid, sizeof(TEEC_UUID))) {
			ret = -EINVAL;
			goto exit;
		}
	}

	if (copy_from_user(&op, ku_buffer.op, sizeof(TEEC_Operation))) {
		ret = -EINVAL;
		goto exit;
	}

	res = copy_op(ts, &op, tmp_allocated_memories, &param_type, params);
	if (res != TEEC_SUCCESS)
		goto error;

	res = ts->op->call_sec_world(ts, sec_cmd, ku_buffer.cmd, param_type,
				   params, &ku_buffer.origin);

	if (res != TEEC_SUCCESS) {
		dev_err(dev,
			"invoke_command: call_sec_world , err [%x], org [%x]\n",
			res, ku_buffer.origin);

		(void)uncopy_op(ts, &op, tmp_allocated_memories, params);
	} else {
		res = uncopy_op(ts, &op, tmp_allocated_memories, params);
	}

	if (copy_to_user(ku_buffer.op, &op, sizeof(TEEC_Operation))) {
		ret = -EINVAL;
		goto exit;
	}

	goto out;

inval:
	res = TEEC_ERROR_BAD_PARAMETERS;
error:
	ku_buffer.origin = TEEC_ORIGIN_API;
out:
	/* Update error code */
	put_user(res, &u_buffer->err);
	put_user(ku_buffer.origin, &u_buffer->origin);

exit:
	if (ret && ta_allocated) {
		paddr = tee_shm_pool_v2p(
				dev, ts->op->Allocator, ts->ta);
		tee_shm_pool_free(
				dev, ts->op->Allocator, paddr, NULL);
	}

	if (ret && uid_allocated) {
		paddr = tee_shm_pool_v2p(
				dev, ts->op->Allocator, ts->uuid);
		tee_shm_pool_free(
				dev, ts->op->Allocator, paddr, NULL);
	}

	return ret;
}

static int tee_share_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct tee_shm *shmint = (struct tee_shm *)(filp->private_data);
	struct device *dev = shmint->op->miscdev->this_device;
	size_t size = vma->vm_end - vma->vm_start;
	pgprot_t prot;

	if (shmint != NULL) {
		dev_dbg(dev, "[%s] %x => %x (+%zu)\n", __func__,
			(unsigned int)shmint->
				paddr, (unsigned int)vma->vm_start,
			size);

		if (tee_shm_pool_is_cached(shmint->op->Allocator))
			prot = vma->vm_page_prot;
		else
			prot = pgprot_noncached(vma->vm_page_prot);

		if (remap_pfn_range(vma, vma->vm_start,
				    shmint->paddr >> PAGE_SHIFT, size, prot))
			return -EAGAIN;
		BUG_ON(vma->vm_private_data != NULL);
		vma->vm_private_data = (void *)shmint->paddr;
	}

	return 0;

}

static int tee_share_release(struct inode *inode, struct file *filp)
{
	struct tee_shm *shmint = (struct tee_shm *)(filp->private_data);
	struct device *dev = shmint->op->miscdev->this_device;

	dev_dbg(dev, "> %p\n", (void *)shmint);
	if (shmint != NULL) {
		tee_shm_unallocate(shmint);
		filp->private_data = NULL;
	}

	dev_dbg(dev, "< [0]\n");
	return 0;
}

const struct file_operations tee_share_fops = {
	.owner = THIS_MODULE,
	.release = tee_share_release,
	.mmap = tee_share_mmap,
};

static int tee_open(struct inode *inode, struct file *filp)
{
	filp->private_data =
		tee_create_session(filp->f_path.dentry->d_iname, true);
	if (filp->private_data == NULL)
		return -ENOMEM;

	return 0;
}

static int tee_release(struct inode *inode, struct file *filp)
{
	struct tee_session *ts = filp->private_data;

	tee_delete_session(ts);

	return 0;
}

#if (CFG_TEE_DRV_DEBUGFS == 1)
inline int tee_debug_do_dump_cmd_hist(struct device *dev,
	const char line[], int ret, char *output, int max_size)
{
	if (max_size > 0 && output)
		ret += snprintf(output + ret, max_size - ret, line);
	else
		dev_info(dev, line);

	return ret;
}

int tee_debug_dump_cmd_hist(struct device *dev, char *output, int max_size)
{
	struct tee_debug_cmd cmd;
	int age = 1;
	struct tee_driver *tee = tee_get_drvdata(dev);
	int ret = 0;
	char tmp[256];

	ret = tee_debug_do_dump_cmd_hist(dev,
		"History of the commands\n", ret, output, max_size);

	ret = tee_debug_do_dump_cmd_hist(dev,
		"\t\t\t\t\t\t\t\t\t\tduration (ms)\n", ret, output, max_size);

	ret = tee_debug_do_dump_cmd_hist(dev,
		"\tdate (ms)\tsession\t\ttee cmd\t\t\tta cmd\tres\tarm\n",
		ret, output, max_size);

	mutex_lock(&tee->mutex_tee);

	while (kfifo_out(&tee->cmds, &cmd, sizeof(cmd))) {
		snprintf(tmp, sizeof(tmp),
			 "%04d\t[%lld]\t[0x%p]\t[%s]\t[%d]\t[%d]\t[%lld]\n",
			 age++, cmd.begin, cmd.ts, tee_cmd_str(cmd.cmd),
			 cmd.ta_cmd, cmd.ret, cmd.duration);
		ret = tee_debug_do_dump_cmd_hist(
				dev, tmp, ret, output, max_size);
	}

	mutex_unlock(&tee->mutex_tee);
	return ret;
}
#endif

static long tee_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct tee_session *ts = (struct tee_session *)(filp->private_data);
	struct device *dev = ts->op->miscdev->this_device;
	__u32 state;
	int ret = 0;

	dev_dbg(dev, "> cmd:[0x%x]\n", cmd);

	mutex_lock(&ts->syncstate);
	state = ts->state;
	mutex_unlock(&ts->syncstate);

	switch (cmd) {
	case TEE_OPEN_SESSION_IOC:
		if (state != TEED_STATE_OPEN_DEV) {
			dev_err(dev, "[%s] invalid state\n",
				__func__);
			ret = -EINVAL;
		} else {
			ret = invoke_command(dev, ts, CMD_TEEC_OPEN_SESSION,
					   (struct tee_cmd *)arg);
			if (ret == 0) {
				mutex_lock(&ts->syncstate);
				ts->state = TEED_STATE_OPEN_SESSION;
				mutex_unlock(&ts->syncstate);
			}
		}
		break;

	case TEE_CLOSE_SESSION_IOC:
		if (state != TEED_STATE_OPEN_SESSION) {
			dev_err(dev, "[%s] invalid state\n",
				__func__);
			ret = -EINVAL;
		} else {
			if (ts->
			    op->call_sec_world(ts, CMD_TEEC_CLOSE_SESSION,
					       0, 0x0, NULL,
					       NULL) != TEEC_SUCCESS)
				ret = -EINVAL;

			mutex_lock(&ts->syncstate);
			ts->state = TEED_STATE_OPEN_DEV;
			mutex_unlock(&ts->syncstate);
		}

		break;

	case TEE_INVOKE_COMMAND_IOC:
		if (state != TEED_STATE_OPEN_SESSION) {
			dev_err(dev, "[%s] invalid state\n",
				__func__);
			ret = -EINVAL;
		} else {
			ret =
			    invoke_command(dev, ts, CMD_TEEC_INVOKE_COMMAND,
					   (struct tee_cmd *)arg);
		}
		break;
	case TEE_REQUEST_CANCELLATION_IOC:
		if (state != TEED_STATE_OPEN_SESSION) {
			dev_err(dev, "[%s] invalid state\n",
				__func__);
			ret = -EINVAL;
		} else {
			if (ts->
			    op->call_sec_world(ts, CMD_TEEC_CANCEL_COMMAND,
					       0, 0x0, NULL,
					       NULL) != TEEC_SUCCESS)
				ret = -EINVAL;
		}
		break;

	case TEE_ALLOC_SHM_IOC:
		{
			TEEC_SharedMemory shm;
			struct file *file;
			struct tee_shm *shmint;

			if (copy_from_user(&shm, (void __user *)arg,
					   sizeof(TEEC_SharedMemory)))
				return -EFAULT;

			shmint =
			    tee_shm_allocate(ts->op, shm.buffer,
					     shm.size, shm.flags);
			if (shmint == NULL)
				return -ENOMEM;

			shm.d.fd = get_unused_fd();
			if (shm.d.fd < 0) {
				tee_shm_unallocate(shmint);
				return -ENFILE;
			}

			file =
			    anon_inode_getfile("tee_share_fd", &tee_share_fops,
					       shmint, O_RDWR);
			if (IS_ERR_OR_NULL(file)) {
				put_unused_fd(shm.d.fd);
				tee_shm_unallocate(shmint);
				return -ENFILE;
			}
			fd_install(shm.d.fd, file);

			if (copy_to_user((void __user *)arg,
					 &shm, sizeof(TEEC_SharedMemory)))
				return -EFAULT;
		};
		break;

	default:
		ret = -ENOSYS;
		break;
	}

	dev_dbg(dev, "< [%d]\n", ret);

	return ret;
}


struct tee_driver *tee_get_drvdata(struct device *dev)
{
	if (strcmp(DEV_NAME(dev), TEE_TZ_NAME) == 0)
		return &tee_tz_data;
	BUG_ON(1);
	return NULL;
}

const struct file_operations tee_fops = {
	.owner = THIS_MODULE,
	.open = tee_open,
	.release = tee_release,
	.unlocked_ioctl = tee_ioctl,
	.read = tee_supp_read,
	.write = tee_supp_write,
};


static int __init tee_init(void)
{
	int ret = 0;
	bool tz_init = false;
	bool supp_init = false;
	bool wait_init = false;

	ret = tee_tz_init();
	if (ret)
		goto err;
	tz_init = true;

	ret = tee_supp_init(&tee_tz_data.rpc);
	if (ret)
		goto err;
	supp_init = true;

	ret = tee_mutex_wait_init(&tee_tz_data.mutex_wait);
	if (ret)
		goto err;

	goto exit;
err:
	if (wait_init)
		tee_mutex_wait_exit(&tee_tz_data.mutex_wait);
	if (supp_init)
		tee_supp_exit();
	if (tz_init)
		tee_tz_exit();
exit:
	return ret;
}

static void __exit tee_exit(void)
{
	pr_info("in tee_exit\n");

	tee_mutex_wait_exit(&tee_tz_data.mutex_wait);

	tee_supp_exit();

	tee_tz_exit();
}

module_init(tee_init);
module_exit(tee_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Trusted Execution Enviroment driver");

