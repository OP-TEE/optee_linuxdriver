
#ifndef __TEE_SHM_H__
#define __TEE_SHM_H__

#include <linux/types.h>
#include <linux/klist.h>
#include <linux/device.h>

struct tee_context;
struct tee_shm_io;
struct tee;
/**
 * struct tee_shm - internal structure to store a shm object.
 *
 * @entry: list of tee_shm
 * @ctx: tee_context attached to the buffer.
 * @tee: tee attached to the buffer.
 * @dev: device attached to the buffer.
 * @size_req: requested size for the buffer
 * @size_alloc: effective size of the buffer
 * @kaddr: kernel address if mapped kernel side
 * @paddr: physical address
 * @flags: flags which denote the type of the buffer
 * @parent: the parent of shm reference
 */
struct tee_shm {
	struct list_head entry;
	struct tee_context *ctx;
	struct tee *tee;
	struct device *dev;
	size_t size_req;
	size_t size_alloc;
	void *kaddr;
	dma_addr_t paddr;
	uint32_t flags;
	struct tee_shm *parent;
};


int tee_shm_alloc_fd(struct tee_context *ctx, struct tee_shm_io *shm_io);
int tee_shm_get_fd(struct tee_context *ctx, struct tee_shm_io *shm_io);

struct tee_shm *tee_shm_alloc(struct tee_context *ctx, size_t size,
			      uint32_t flags);
void tee_shm_free(struct tee_shm *shm);

int check_shm(struct tee *tee, struct tee_shm_io *shm_io);
struct tee_shm *tee_shm_get(struct tee_context *ctx, struct tee_shm_io *shm_io);
void tee_shm_put(struct tee_shm *shm);

#endif /* __TEE_SHM_H__ */
