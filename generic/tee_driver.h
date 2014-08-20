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
#ifndef TEE_DRIVER_H
#define TEE_DRIVER_H

#include <linux/mutex.h>

#include "tee_supp_com.h"
#include "tee_mutex_wait.h"

/******************************************************************************/

/* Helpers */
#define DEV_NAME(dev)	(dev->kobj.name)

/******************************************************************************/

#if (CFG_TEE_DRV_DEBUGFS == 1)

#include <linux/kfifo.h>

struct tee_debug_cmd {
	enum t_cmd_service_id	cmd;
	struct tee_session	*ts;
	uint32_t		ta_cmd;
	int			ret;
	s64			begin;
	s64			duration;
};

#endif /* CFG_TEE_DRV_DEBUGFS */

struct tee_driver {
	/* protect concurrent access to the tee_driver */
	struct	mutex			mutex_tee;
	int				count_session;
	char				*memory_pool;
	struct	tee_rpc_priv_data	rpc;
	struct  tee_mutex_wait_private	mutex_wait;
#if (CFG_TEE_DRV_DEBUGFS == 1)
	struct	kfifo	cmds;
#endif
};


struct device;
extern const struct file_operations tee_fops;

/******************************************************************************/

struct tee_driver *tee_get_drvdata(struct device *dev);

#if (CFG_TEE_DRV_DEBUGFS == 1)
int tee_debug_dump_cmd_hist(struct device *dev, char *output, int max_size);
#endif

/******************************************************************************/

#endif /* TEE_DRIVER_H */
