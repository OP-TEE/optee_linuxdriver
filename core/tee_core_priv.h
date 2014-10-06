
#ifndef __TEE_CORE_PRIV_H__
#define __TEE_CORE_PRIV_H__

#include "linux/tee_core.h"
#include "linux/tee_ioc.h"

/* from tee_core_module.c */
int tee_get(struct tee *tee);
int tee_put(struct tee *tee);

void tee_inc_stats(struct tee_stats_entry *entry);
void tee_dec_stats(struct tee_stats_entry *entry);

/* from tee_context.c */
int tee_context_dump(struct tee *tee, char *buff, size_t len);

struct tee_context *tee_context_create(struct tee *tee);
void tee_context_destroy(struct tee_context *ctx);

void tee_context_get(struct tee_context *ctx);
void tee_context_put(struct tee_context *ctx);

struct tee_shm *tee_context_create_tmpref_buffer(struct tee_context *ctx,
						 size_t size,
						 const void *buffer, int type);
struct tee_shm *tee_context_alloc_shm_tmp(struct tee_context *ctx, size_t size,
					  const void *data, int type);
int tee_context_copy_from_client(const struct tee_context *ctx, void *dest,
				 const void *src, size_t size);

/* from tee_session.c */
int tee_session_create_fd(struct tee_context *ctx, struct tee_cmd_io *cmd_io);
struct tee_session *tee_session_create_and_open(struct tee_context *ctx,
						struct tee_cmd_io *cmd_io);
int tee_session_close_and_destroy(struct tee_session *sess);

struct tee *tee_get_tee(const char *devname);
int tee_session_invoke_be(struct tee_session *sess, struct tee_cmd_io *cmd_io);

#endif
