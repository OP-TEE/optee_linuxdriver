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

#include "generic/tee-op.h"
#include "generic/tee_driver.h"
#include "generic/tee_debug.h"
#include "tee_tz.h"

static const char STR_CMD_HIST[] =		"hist";
static const char STR_CMD_HIST_HELP[] =		"cmd";
static const char STR_DUMP_ALLOCATOR[] =	"dump";
static const char STR_DUMP_ALLOCATOR_HELP[] =	"shared memory";

/*****************************************************************************/

static ssize_t tee_write_file_settings_tz(struct file *file,
				       const char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	struct device *dev = file->private_data;
	char *buf;
	char *str;
	int val;

	buf = devm_kzalloc(dev, count, GFP_KERNEL);
	if (!buf) {
		dev_err(dev, "can't allocate work buffer\n");
		return count;
	}

	val = simple_write_to_buffer(buf, count, ppos, user_buf, count);
	if (!val) {
		dev_err(dev, "no user data\n");
		goto out;
	}

	str = strstr(buf, STR_DUMP_ALLOCATOR);
	if (str)
		tee_shm_pool_dump(dev, TZop.Allocator, true);

	str = strstr(buf, STR_CMD_HIST);
	if (str)
		tee_debug_dump_cmd_hist(dev, NULL, 0);

out:
	devm_kfree(dev, buf);
	return count;
}

static ssize_t tee_read_file_settings_tz(
	struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
	ssize_t ret = 0;
	struct device *dev = file->private_data;
	static const int MAX_SIZE = 2 * PAGE_SIZE;
	char *buf;

	buf = devm_kzalloc(dev, MAX_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = snprintf(buf, MAX_SIZE, "teetz debug:\n=========\n");

	ret += snprintf(buf + ret, MAX_SIZE - ret, "Status:\n");

	ret += snprintf(buf + ret, MAX_SIZE - ret,
		"\tOpened session:\t\t[%d]\n", tee_tz_data.count_session);

	ret += snprintf(buf + ret, MAX_SIZE - ret,
		"\tMemory pool:\t[%s]\n", tee_tz_get_memory_pool());

	ret += snprintf(buf + ret, MAX_SIZE - ret,
			"\nAvailable cmd:\n\t[%s] (%s)\n\t[%s] (%s)\n",
			STR_CMD_HIST, STR_CMD_HIST_HELP,
			STR_DUMP_ALLOCATOR, STR_DUMP_ALLOCATOR_HELP);

	ret += snprintf(buf + ret, MAX_SIZE - ret,
			"\n\ti.e.: 'echo dump > /sys/kernel/debug/tee/teetz'\n");

	ret = simple_read_from_buffer(user_buf, count, ppos, buf, ret);

	devm_kfree(dev, buf);

	return ret;
}


const struct file_operations tee_debug_fops_tee_tz = {
	.open = simple_open,
	.read = tee_read_file_settings_tz,
	.write = tee_write_file_settings_tz,
	.llseek = default_llseek,
};

/*****************************************************************************/

