#ifndef __TEE_CORE_DRV_H__
#define __TEE_CORE_DRV_H__

#include <linux/klist.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/cdev.h>
#include <linux/debugfs.h>
#include <linux/miscdevice.h>
#include <linux/types.h>
#include <linux/atomic.h>

#include <linux/types.h>

#include <linux/tee_client_api.h>

#define TEE_DEV(tee) (tee->miscdev.this_device)

#define tee_dbg(tee, format, ...)  \
	dev_dbg(tee->miscdev.this_device, format, ##__VA_ARGS__)
#define tee_warn(tee, format, ...)  \
	dev_warn(tee->miscdev.this_device, format, ##__VA_ARGS__)
#define tee_err(tee, format, ...)   \
	dev_err(tee->miscdev.this_device, format, ##__VA_ARGS__)

#define TEE_MAX_CLIENT_NAME (128)

struct tee_cmd_io;
struct tee_shm_io;
struct tee_rpc;

enum tee_state {
	TEE_OFFLINE = 0,
	TEE_ONLINE = 1,
	TEE_SUSPENDED = 2,
	TEE_RUNNING = 3,
	TEE_CRASHED = 4,
	TEE_LAST = 5,
};

#define TEE_CONF_TEST_MODE		0x01000000
#define TEE_CONF_FW_NOT_CAPABLE		0x00000001

struct tee_stats_entry {
	int count;
	int max;
};

#define TEE_STATS_CONTEXT_IDX   0
#define TEE_STATS_SESSION_IDX   1
#define TEE_STATS_SHM_IDX       2

#define TEE_MAX_TEE_DEV_NAME (64)
struct tee {
	struct klist_node node;
	char name[TEE_MAX_TEE_DEV_NAME];
	int id;
	void *priv;
	const struct tee_ops *ops;
	struct device *dev;
	struct miscdevice miscdev;
	struct tee_rpc *rpc;
	struct dentry *dbg_dir;
	atomic_t refcount;
	int max_refcount;
	struct tee_stats_entry stats[3];
	struct list_head list_ctx;
	struct list_head list_rpc_shm;
	struct mutex lock;
	unsigned int state;
	uint32_t shm_flags;	/* supported flags for shm allocation */
	uint32_t conf;
	uint32_t test;
};

/**
 * struct tee_context - internal structure to store a TEE context.
 *
 * @tee: tee attached to the tee_context
 * @name: client name
 * @tgid: tgid of the this client
 * @usr_client: indicate if the client is user side client
 * @entry: list of tee_context
 * @list_sess: list of tee_session that denotes all tee_session attached
 * @list_shm: list of tee_shm that denotes all tee_shm attached
 * @refcount: number of objects which reference it (including itself)
 */
struct tee_context {
	struct tee *tee;
	char name[TEE_MAX_CLIENT_NAME];
	int tgid;
	int usr_client;
	struct list_head entry;
	struct list_head list_sess;
	struct list_head list_shm;
	struct kref refcount;
};

/**
 * struct tee_session - internal structure to store a TEE session.
 *
 * @entry: list of tee_context
 * @ctx: tee_context attached to the tee_session
 * @sessid: session ID returned by the secure world
 * @priv: exporter specific private data for this buffer object
 */
struct tee_session {
	struct list_head entry;
	struct tee_context *ctx;
	uint32_t sessid;
	void *priv;
};

#define TEE_SHM_MAPPED			0x01000000
#define TEE_SHM_TEMP			0x02000000
#define TEE_SHM_FROM_RPC		0x04000000
#define TEE_SHM_REGISTERED		0x08000000
#define TEE_SHM_PARENT			0x10000000
#define TEE_SHM_CACHED			0x20000000
#define TEE_SHM_FROM_KAPI		0x40000000

#define TEE_SHM_DRV_PRIV_MASK		0xFF000000

struct tee_data {
	uint32_t type;
	uint32_t type_original;
	struct teec_shm c_shm[TEEC_CONFIG_PAYLOAD_REF_COUNT];
	union {
		struct tee_shm *shm;
		struct teec_val value;
	} params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
};

struct tee_cmd {
	uint32_t err;
	uint32_t origin;
	uint32_t cmd;
	struct tee_shm *uuid;
	struct tee_shm *ta;
	struct tee_data param;
};

struct tee_shm *tee_shm_alloc_from_rpc(struct tee *tee, size_t size,
				       uint32_t flags);
void tee_shm_free_from_rpc(struct tee_shm *);

int tee_core_add(struct tee *tee);
int tee_core_del(struct tee *tee);

struct tee *tee_core_alloc(struct device *dev, char *name, int id,
			   const struct tee_ops *ops, size_t len);

struct tee_ops {
	struct module *owner;
	const char *type;

	int (*start)(struct tee *tee);
	int (*stop)(struct tee *tee);
	int (*open)(struct tee_session *sess, struct tee_cmd *cmd);
	int (*close)(struct tee_session *sess);
	int (*invoke)(struct tee_session *sess, struct tee_cmd *cmd);
	int (*cancel)(struct tee_session *sess, struct tee_cmd *cmd);
	struct tee_shm *(*alloc)(struct tee *tee, size_t size,
				  uint32_t flags);
	void (*free)(struct tee_shm *shm);
	int (*shm_inc_ref)(struct tee_shm *shm);
};

#endif /* __TEE_CORE_DRV_H__ */
