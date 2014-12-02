
#ifndef __TEE_SYSFS_H__
#define __TEE_SYSFS_H__

struct tee;

void tee_init_sysfs(struct tee *tee);
void tee_cleanup_sysfs(struct tee *tee);

#endif
