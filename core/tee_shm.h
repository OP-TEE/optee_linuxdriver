
#ifndef __TEE_SHM_H__
#define __TEE_SHM_H__

struct tee_context;
struct tee_shm_io;
struct tee;

int tee_shm_alloc_fd(struct tee_context *ctx, struct tee_shm_io *shm_io);
int tee_shm_get_fd(struct tee_context *ctx, struct tee_shm_io *shm_io);

struct tee_shm *tee_shm_alloc(struct tee_context *ctx, size_t size,
			      uint32_t flags);
void tee_shm_free(struct tee_shm *shm);

int check_shm(struct tee *tee, struct tee_shm_io *shm_io);
struct tee_shm *tee_shm_get(struct tee_context *ctx, struct tee_shm_io *shm_io);
void tee_shm_put(struct tee_shm *shm);

#endif /* __TEE_SHM_H__ */
