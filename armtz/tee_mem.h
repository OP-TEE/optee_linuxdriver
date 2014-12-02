/*
* Copyright (C) STMicroelectronics 2014. All rights reserved.
*
* This code is STMicroelectronics proprietary and confidential.
* Any use of the code for whatever purpose is subject to
* specific written permission of STMicroelectronics SA.
*/

#ifndef TEE_MEM_H
#define TEE_MEM_H

#include <linux/types.h>
#include <linux/device.h>

struct shm_pool;

struct shm_pool *tee_shm_pool_create(struct device *dev, size_t shm_size,
				     void *shm_vaddr, unsigned long shm_paddr);

void tee_shm_pool_destroy(struct device *dev, struct shm_pool *pool);

void *tee_shm_pool_p2v(struct device *dev, struct shm_pool *pool,
		       unsigned long paddr);

unsigned long tee_shm_pool_v2p(struct device *dev, struct shm_pool *pool,
			       void *vaddr);

unsigned long tee_shm_pool_alloc(struct device *dev,
				 struct shm_pool *pool,
				 size_t size, size_t alignment);

int tee_shm_pool_free(struct device *dev, struct shm_pool *pool,
		      unsigned long paddr, uint32_t *size);

bool tee_shm_pool_incref(struct device *dev, struct shm_pool *pool,
			 unsigned long paddr);

void tee_shm_pool_dump(struct device *dev, struct shm_pool *pool, bool forced);

void tee_shm_pool_reset(struct device *dev, struct shm_pool *pool);

bool tee_shm_pool_is_cached(struct shm_pool *pool);

void tee_shm_pool_set_cached(struct shm_pool *pool);

#endif
