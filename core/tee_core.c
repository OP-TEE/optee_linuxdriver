/*
 *  tee_driver.c - TEE core kernel module.
 *
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/idr.h>
#include <linux/platform_device.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <asm-generic/ioctl.h>
#include <linux/sched.h>

#include <optee/tee_core.h>
#include <optee/tee_ioc.h>
#include <optee/tee_shm.h>
#include <optee/tee_supp_com.h>


#include "tee_core_priv.h"
#include "tee_sysfs.h"
#define _TEE_CORE_FW_VER "1:0.1"

static char *_tee_supp_app_name = "tee-supplicant";

/* Store the class misc reference */
static struct class *misc_class;

static int device_match(struct device *device, const void *devname)
{
	struct tee *tee = dev_get_drvdata(device);
	int ret = strncmp(devname, tee->name, sizeof(tee->name));

	if (ret == 0)
		return 1;
	else
		return 0;
}

/*
 * For the kernel API.
 * Get a reference on a device tee from the device needed
 */
struct tee *tee_get_tee(const char *devname)
{
	struct device *device;

	if (!devname)
		return NULL;
	device = class_find_device(misc_class, NULL, devname, device_match);
	if (!device) {
		pr_err("%s:%d - can't find device [%s]\n", __func__, __LINE__,
		       devname);
		return NULL;
	}

	return dev_get_drvdata(device);
}

void tee_inc_stats(struct tee_stats_entry *entry)
{
	entry->count++;
	if (entry->count > entry->max)
		entry->max = entry->count;
}

void tee_dec_stats(struct tee_stats_entry *entry)
{
	entry->count--;
}

/**
 * tee_get - increases refcount of the tee
 * @tee:	[in]	tee to increase refcount of
 *
 * @note: If tee.ops.start() callback function is available,
 * it is called when refcount is equal at 1.
 */
int tee_get(struct tee *tee)
{
	int ret = 0;

	BUG_ON(!tee);

	if (atomic_inc_return(&tee->refcount) == 1) {
		BUG_ON(!try_module_get(tee->ops->owner));
		tee_dbg(tee, "%s: refcount=1 call %s::start()...\n",
			__func__, tee->name);
		get_device(tee->dev);
		if (tee->ops->start)
			ret = tee->ops->start(tee);
	}
	if (ret) {
		put_device(tee->dev);
		module_put(tee->ops->owner);
		tee_err(tee, "%s: %s::start() failed, err=%d\n",
			__func__, tee->name, ret);
		atomic_dec(&tee->refcount);
	} else {
		int count = (int)atomic_read(&tee->refcount);

		tee_dbg(tee, "%s: refcount=%d\n", __func__, count);
		if (count > tee->max_refcount)
			tee->max_refcount = count;
	}
	return ret;
}

/**
 * tee_put - decreases refcount of the tee
 * @tee:	[in]	tee to reduce refcount of
 *
 * @note: If tee.ops.stop() callback function is available,
 * it is called when refcount is equal at 0.
 */
int tee_put(struct tee *tee)
{
	int ret = 0;
	int count;

	BUG_ON(!tee);

	if (atomic_dec_and_test(&tee->refcount)) {
		tee_dbg(tee, "%s: refcount=0 call %s::stop()...\n",
			__func__, tee->name);
		if (tee->ops->stop)
			ret = tee->ops->stop(tee);
		module_put(tee->ops->owner);
		put_device(tee->dev);
	}
	if (ret) {
		tee_err(tee, "%s: %s::stop() has failed, ret=%d\n",
			__func__, tee->name, ret);
	}

	count = (int)atomic_read(&tee->refcount);
	tee_dbg(tee, "%s: refcount=%d\n", __func__, count);
	return ret;
}

static int tee_supp_open(struct tee *tee)
{
	int ret = 0;

	tee_dbg(tee, "%s: appclient=\"%s\" pid=%d\n", __func__,
		current->comm, current->pid);

	BUG_ON(!tee->rpc);

	if (strncmp(_tee_supp_app_name, current->comm,
			strlen(_tee_supp_app_name)) == 0) {
		if (atomic_add_return(1, &tee->rpc->used) > 1) {
			ret = -EBUSY;
			dev_err(tee->dev, "%s: ERROR Only one Supplicant is allowed\n",
					__func__);
			atomic_sub(1, &tee->rpc->used);
		}
	}

	return ret;
}

static void tee_supp_release(struct tee *tee)
{
	tee_dbg(tee, "%s: appclient=\"%s\" pid=%d\n", __func__,
		current->comm, current->pid);

	BUG_ON(!tee->rpc);

	if ((atomic_read(&tee->rpc->used) == 1) &&
			(strncmp(_tee_supp_app_name, current->comm,
					strlen(_tee_supp_app_name)) == 0))
		atomic_sub(1, &tee->rpc->used);
}

static int tee_ctx_open(struct inode *inode, struct file *filp)
{
	struct tee_context *ctx;
	struct tee *tee;
	int ret;

	tee = container_of(filp->private_data, struct tee, miscdev);

	BUG_ON(!tee);
	BUG_ON(tee->miscdev.minor != iminor(inode));

	tee_dbg(tee, "%s: > name=\"%s\"\n", __func__, tee->name);

	ret = tee_supp_open(tee);
	if (ret)
		return ret;

	ctx = tee_context_create(tee);
	if (IS_ERR_OR_NULL(ctx))
		return PTR_ERR(ctx);

	ctx->usr_client = 1;
	filp->private_data = ctx;

	tee_dbg(tee, "%s: < ctx=%p is created\n",
		__func__, (void *)ctx);

	return 0;
}

static int tee_ctx_release(struct inode *inode, struct file *filp)
{
	struct tee_context *ctx = filp->private_data;
	struct tee *tee;

	if (!ctx)
		return -EINVAL;

	BUG_ON(!ctx->tee);
	tee = ctx->tee;
	BUG_ON(tee->miscdev.minor != iminor(inode));

	tee_dbg(tee, "%s: > ctx=%p\n", __func__, ctx);

	tee_context_destroy(ctx);
	tee_supp_release(tee);

	tee_dbg(tee, "%s: < ctx=%p is destroyed\n", __func__, ctx);
	return 0;
}

static int tee_do_create_session(struct tee_context *ctx,
				 struct tee_cmd_io __user *u_cmd)
{
	int ret = -EINVAL;
	struct tee_cmd_io k_cmd;
	struct tee *tee;

	tee = ctx->tee;
	BUG_ON(!ctx->usr_client);

	tee_dbg(tee, "%s: >\n", __func__);

	if (copy_from_user(&k_cmd, (void *)u_cmd, sizeof(struct tee_cmd_io))) {
		tee_err(tee, "%s: copy_from_user failed\n", __func__);
		goto exit;
	}

	if (k_cmd.fd_sess > 0) {
		tee_err(tee, "%s: invalid fd_sess %d\n", __func__,
			k_cmd.fd_sess);
		goto exit;
	}

	if ((k_cmd.op == NULL) || (k_cmd.uuid == NULL) ||
	    ((k_cmd.data != NULL) && (k_cmd.data_size == 0)) ||
	    ((k_cmd.data == NULL) && (k_cmd.data_size != 0))) {
		tee_err(tee,
			"%s: op or/and data parameters are not valid\n",
			__func__);
		goto exit;
	}

	ret = tee_session_create_fd(ctx, &k_cmd);
	put_user(k_cmd.err, &u_cmd->err);
	put_user(k_cmd.origin, &u_cmd->origin);
	if (ret)
		goto exit;

	put_user(k_cmd.fd_sess, &u_cmd->fd_sess);

exit:
	tee_dbg(tee, "%s: < ret=%d, sessfd=%d\n", __func__, ret,
		k_cmd.fd_sess);
	return ret;
}

static int tee_do_shm_alloc(struct tee_context *ctx,
			    struct tee_shm_io __user *u_shm)
{
	int ret = -EINVAL;
	struct tee_shm_io k_shm;
	struct tee *tee = ctx->tee;

	BUG_ON(!ctx->usr_client);

	tee_dbg(tee, "%s: >\n", __func__);

	if (copy_from_user(&k_shm, (void *)u_shm, sizeof(struct tee_shm_io))) {
		tee_err(tee, "%s: copy_from_user failed\n", __func__);
		goto exit;
	}

	if ((k_shm.buffer != NULL) || (k_shm.fd_shm != 0) ||
	    ((k_shm.flags & tee->shm_flags) == 0) || (k_shm.registered != 0)) {
		tee_err(tee,
			"%s: shm parameters are not valid %p %d %08x %08x %d\n",
			__func__, (void *)k_shm.buffer, k_shm.fd_shm,
			(unsigned int)k_shm.flags, (unsigned int)tee->shm_flags,
			k_shm.registered);
		goto exit;
	}

	ret = tee_shm_alloc_fd(ctx, &k_shm);
	if (ret)
		goto exit;

	put_user(k_shm.fd_shm, &u_shm->fd_shm);

exit:
	tee_dbg(tee, "%s: < ret=%d, shmfd=%d\n", __func__, ret,
		k_shm.fd_shm);
	return ret;
}

static int tee_do_get_fd_for_rpc_shm(struct tee_context *ctx,
				     struct tee_shm_io __user *u_shm)
{
	int ret = -EINVAL;
	struct tee_shm_io k_shm;
	struct tee *tee = ctx->tee;

	tee_dbg(tee, "%s: >\n", __func__);
	BUG_ON(!ctx->usr_client);

	if (copy_from_user(&k_shm, (void *)u_shm, sizeof(struct tee_shm_io))) {
		tee_err(tee, "%s: copy_from_user failed\n", __func__);
		goto exit;
	}

	if ((k_shm.buffer == NULL) || (k_shm.size == 0) || (k_shm.fd_shm != 0)
	    || (k_shm.flags & ~(tee->shm_flags))
	    || ((k_shm.flags & tee->shm_flags) == 0)
	    || (k_shm.registered != 0)) {
		tee_err(tee, "%s: shm parameters are not valid\n",
			__func__);
		goto exit;
	}

	ret = tee_shm_get_fd(ctx, &k_shm);
	if (ret)
		goto exit;

	put_user(k_shm.fd_shm, &u_shm->fd_shm);

exit:
	tee_dbg(tee, "%s: < ret=%d, shmfd=%d\n", __func__, ret,
		k_shm.fd_shm);
	return ret;
}

static long tee_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = -EINVAL;
	struct tee_context *ctx = filp->private_data;

	BUG_ON(!ctx);
	BUG_ON(!ctx->tee);

	tee_dbg(ctx->tee, "%s: > cmd nr=%d\n", __func__, _IOC_NR(cmd));

	switch (cmd) {
	case TEE_OPEN_SESSION_IOC:
		ret =
		    tee_do_create_session(ctx, (struct tee_cmd_io __user *)arg);
		break;
	case TEE_ALLOC_SHM_IOC:
		ret = tee_do_shm_alloc(ctx, (struct tee_shm_io __user *)arg);
		break;
	case TEE_GET_FD_FOR_RPC_SHM_IOC:
		ret =
		    tee_do_get_fd_for_rpc_shm(ctx,
					      (struct tee_shm_io __user *)arg);
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	tee_dbg(ctx->tee, "%s: < ret=%d\n", __func__, ret);

	return ret;
}

const struct file_operations tee_fops = {
	.owner = THIS_MODULE,
	.read = tee_supp_read,
	.write = tee_supp_write,
	.open = tee_ctx_open,
	.release = tee_ctx_release,
	.unlocked_ioctl = tee_ioctl
};

static void tee_plt_device_release(struct device *dev)
{
	pr_debug("%s: (dev=%p)....\n", __func__, dev);
}

struct tee *tee_core_alloc(struct device *dev, char *name, int id,
			   const struct tee_ops *ops, size_t len)
{
	struct tee *tee;

	if (!dev || !name || !ops ||
	    !ops->open || !ops->close || !ops->alloc || !ops->free)
		return NULL;

	tee = devm_kzalloc(dev, sizeof(struct tee) + len, GFP_KERNEL);
	if (!tee)
		return NULL;

	if (!dev->release)
		dev->release = tee_plt_device_release;

	tee->dev = dev;
	tee->id = id;
	tee->ops = ops;
	tee->priv = &tee[1];

	snprintf(tee->name, sizeof(tee->name), "optee%s%02d", name, tee->id);
	pr_info("TEE core: Alloc the misc device \"%s\" (id=%d)\n", tee->name,
		tee->id);

	tee->miscdev.parent = dev;
	tee->miscdev.minor = MISC_DYNAMIC_MINOR;
	tee->miscdev.name = tee->name;
	tee->miscdev.fops = &tee_fops;

	mutex_init(&tee->lock);
	atomic_set(&tee->refcount, 0);
	INIT_LIST_HEAD(&tee->list_ctx);
	INIT_LIST_HEAD(&tee->list_rpc_shm);

	tee->state = TEE_OFFLINE;

	tee_supp_init(tee);

	return tee;
}
EXPORT_SYMBOL(tee_core_alloc);

int tee_core_add(struct tee *tee)
{
	int ret = 0;

	if (!tee)
		return -EINVAL;

	ret = misc_register(&tee->miscdev);
	if (ret != 0) {
		pr_err("TEE Core: misc_register() failed name=\"%s\"\n",
		       tee->name);
		return ret;
	}

	dev_set_drvdata(tee->miscdev.this_device, tee);

	tee_init_sysfs(tee);

	/* Register a static reference on the class misc
	 * to allow finding device by class */
	BUG_ON(!tee->miscdev.this_device->class);
	if (misc_class)
		BUG_ON(misc_class != tee->miscdev.this_device->class);
	else
		misc_class = tee->miscdev.this_device->class;

	pr_info("TEE Core: Register the misc device \"%s\" (id=%d,minor=%d)\n",
		dev_name(tee->miscdev.this_device), tee->id,
		tee->miscdev.minor);
	return ret;
}
EXPORT_SYMBOL(tee_core_add);

int tee_core_del(struct tee *tee)
{
	if (tee) {
		pr_info("TEE Core: Destroy the misc device \"%s\" (id=%d)\n",
			dev_name(tee->miscdev.this_device), tee->id);

		tee_supp_deinit(tee);

		tee_cleanup_sysfs(tee);

		if (tee->miscdev.minor != MISC_DYNAMIC_MINOR) {
			pr_info("TEE Core: Deregister the misc device \"%s\" (id=%d)\n",
			     dev_name(tee->miscdev.this_device), tee->id);
			misc_deregister(&tee->miscdev);
		}
	}

	return 0;
}
EXPORT_SYMBOL(tee_core_del);

static int __init tee_core_init(void)
{
	pr_info("\nTEE Core Framework initialization (ver %s)\n",
		_TEE_CORE_FW_VER);
	return 0;
}

static void __exit tee_core_exit(void)
{
	pr_info("TEE Core Framework unregistered\n");
}

module_init(tee_core_init);
module_exit(tee_core_exit);

MODULE_AUTHOR("STMicroelectronics");
MODULE_DESCRIPTION("STM Secure TEE Framework/Core TEEC v1.0");
MODULE_SUPPORTED_DEVICE("");
MODULE_VERSION(_TEE_CORE_FW_VER);
MODULE_LICENSE("GPL");
