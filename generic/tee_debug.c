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
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/device.h>

#include "tee-op.h"
#include "tee_driver.h"
#include "tee_debug.h"

static struct dentry *tee_debug_root;

#define CMD_HIST_DEPTH       20
#define CMD_HIST_FIFO_SIZE   roundup_pow_of_two(	\
		CMD_HIST_DEPTH * sizeof(struct tee_debug_cmd))

static ssize_t tee_read_file_hist(struct file *file, char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	ssize_t ret = 0;
	struct device *dev = file->private_data;
	static const int MAX_SIZE = 2 * PAGE_SIZE;
	char *buf;

	buf = devm_kzalloc(dev, MAX_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = tee_debug_dump_cmd_hist(dev, buf, MAX_SIZE);

	ret = simple_read_from_buffer(user_buf, count, ppos, buf, ret);

	devm_kfree(dev, buf);

	return ret;
}

static const struct file_operations tee_debug_fops_hist = {
	.open = simple_open,
	.read = tee_read_file_hist,
	.llseek = default_llseek,
};

int tee_debug_init(struct device *dev)
{
	char buf[20];
	struct dentry *entry = 0;
	int ret = 0;
	struct tee_driver *tee = tee_get_drvdata(dev);

	dev_dbg(dev, ">\n");

	ret = kfifo_alloc(&tee->cmds, CMD_HIST_FIFO_SIZE, GFP_KERNEL);
	if (ret) {
		dev_err(dev, "Can't allocate [%lu] bytes the fifo for the history cmds\n",
			CMD_HIST_FIFO_SIZE);
		ret = -ENOMEM;
		goto exit;
	}

	if (!tee_debug_root) {
		tee_debug_root = debugfs_create_dir("tee", NULL);
		if (!tee_debug_root) {
			dev_err(dev, "Failed to create tee debugfs root\n");
			ret = -EIO;
			goto err_dealloc;
		}
	}

	if (strcmp(DEV_NAME(dev), TEE_TZ_NAME) == 0)
		entry = debugfs_create_file(TEE_TZ_NAME, 0644, tee_debug_root,
				    dev, &tee_debug_fops_tee_tz);
	if (!entry) {
		dev_err(dev, "Failed to create tee debugfs file\n");
		ret = -EIO;
		goto err_remove;
	}

	snprintf(buf, sizeof(buf), "%s_hist", DEV_NAME(dev));
	entry = debugfs_create_file(buf, 0644, tee_debug_root,
				    dev, &tee_debug_fops_hist);
	if (!entry) {
		dev_err(dev, "Failed to create tee debugfs hist file\n");
		ret = -EIO;
		goto err_remove;
	}

	goto exit;

err_remove:
	debugfs_remove_recursive(tee_debug_root);
err_dealloc:
	kfifo_free(&tee->cmds);
exit:
	dev_dbg(dev, "< [%d]\n", ret);
	return ret;
}

void tee_debug_remove(struct device *dev)
{
	struct tee_driver *tee = tee_get_drvdata(dev);
	dev_dbg(dev, ">\n");

	if (tee_debug_root)
		debugfs_remove_recursive(tee_debug_root);
	tee_debug_root = NULL;

	kfifo_free(&tee->cmds);

	dev_dbg(dev, "<\n");
}
