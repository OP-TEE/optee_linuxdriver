
#ifndef __TEE_TZ_PRIV__
#define __TEE_TZ_PRIV__

struct tee;
struct shm_pool;
struct tee_rpc_bf;

#ifdef CONFIG_ARM
struct smc_param {
	uint32_t a0;
	uint32_t a1;
	uint32_t a2;
	uint32_t a3;
	uint32_t a4;
	uint32_t a5;
	uint32_t a6;
	uint32_t a7;
};
#endif
#ifdef CONFIG_ARM64
struct smc_param {
	uint64_t a0;
	uint64_t a1;
	uint64_t a2;
	uint64_t a3;
	uint64_t a4;
	uint64_t a5;
	uint64_t a6;
	uint64_t a7;
};
#endif

struct tee_tz {
	uint32_t sess_id;
	bool started;
	struct tee *tee;
	unsigned long shm_paddr;
	void *shm_vaddr;
	struct shm_pool *shm_pool;
	struct mutex mutex;
	struct completion c;
	int c_waiters;
	void *tz_outer_cache_mutex;
	struct tee_rpc_bf *rpc_buffers;
	bool shm_cached;
	struct tee_mutex_wait_private mutex_wait;
};

int tee_smc_call(struct smc_param *param);

#endif /* __TEE_TZ_PRIV__ */
