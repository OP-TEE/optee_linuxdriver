/*
 * Copyright (c) 2014, Linaro Limited
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
#ifndef TEE_MUTEX_WAIT_H
#define TEE_MUTEX_WAIT_H

#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/device.h>

struct tee_mutex_wait_private {
	struct mutex mu;
	struct list_head db;
};

int tee_mutex_wait_init(struct tee_mutex_wait_private *priv);
void tee_mutex_wait_exit(struct tee_mutex_wait_private *priv);
void tee_mutex_wait_delete(struct device *dev, u32 key);
void tee_mutex_wait_wakeup(struct device *dev, u32 key, u32 wait_after);
void tee_mutex_wait_sleep(struct device *dev, u32 key, u32 wait_tick);

#endif /*TEE_MUTEX_WAIT_H*/
