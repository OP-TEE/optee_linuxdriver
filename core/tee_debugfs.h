
#ifndef __TEE_DEBUGFS_H__
#define __TEE_DEBUGFS_H__

struct tee;

void tee_create_debug_dir(struct tee *tee);
void tee_delete_debug_dir(struct tee *tee);

void __init tee_init_debugfs(void);
void __exit tee_exit_debugfs(void);

#endif /* __TEE_DEBUGFS_H__ */
