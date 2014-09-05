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
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/highmem.h>

#include "tee-op.h"
#include "tee_driver.h"
#include "tee_service.h"
#include "tee_tz.h"

struct tee_targetop *tee_get_target(const char *devname)
{
	if (strcmp(devname, TEE_TZ_NAME) == 0)
		return &TZop;
	return NULL;
}

struct tee_session *tee_create_session(const char *devname, bool userApi)
{
	struct tee_targetop *op;
	struct tee_session *ts;
	struct tee_driver *tee = NULL;
	int count_session = -1;
	struct device *dev = NULL;

	op = tee_get_target(devname);
	if (op == NULL) {
		dev_err(dev, "[%s] Invalid TEE device name '%s'",
			__func__, devname);
		return NULL;
	}

	dev = op->miscdev->this_device;
	dev_dbg(dev, "> count_session:[%d] devname:[%s]\n",
		count_session, devname);

	tee = tee_get_drvdata(dev);
	count_session = tee->count_session;

	ts = (struct tee_session *)devm_kzalloc(dev, sizeof(struct tee_session),
						GFP_KERNEL);
	if (ts == NULL) {
		dev_err(dev, "[%s] allocation failed", __func__);
		return NULL;
	}
	mutex_lock(&tee->mutex_tee);
	tee->count_session++;
	mutex_unlock(&tee->mutex_tee);

	mutex_init(&ts->syncstate);
	ts->op = op;
	ts->state = TEED_STATE_OPEN_DEV;
	ts->id = 0;
	ts->ta = NULL;
	ts->tasize = 0;
	ts->uuid = NULL;
	ts->login = TEEC_LOGIN_PUBLIC;
	ts->userApi = userApi;

	dev_dbg(dev, "< count_session:[%d] ts:[%p]\n", count_session, ts);
	return ts;
}

void tee_delete_session(struct tee_session *ts)
{
	struct device *dev = ts->op->miscdev->this_device;
	struct tee_driver *tee = tee_get_drvdata(dev);
	int count_session = tee->count_session;

	dev_dbg(dev, "> session:[%p] count_session:[%d]\n", ts, count_session);

	/* Close session to secure world if a session is open */
	if (ts->state == TEED_STATE_OPEN_SESSION) {
		ts->op->call_sec_world(ts, CMD_TEEC_CLOSE_SESSION, 0, 0x0,
				       NULL, NULL);
	}

	if (ts->ta != NULL)
		tee_shm_pool_free(dev, ts->op->Allocator,
				  tee_shm_pool_v2p(dev, ts->op->Allocator,
				  ts->ta), NULL);

	if (ts->uuid != NULL)
		tee_shm_pool_free(dev, ts->op->Allocator,
				  tee_shm_pool_v2p(dev, ts->op->Allocator,
				  ts->uuid), NULL);

	mutex_lock(&tee->mutex_tee);
	count_session = --tee->count_session;
	BUG_ON(tee->count_session < 0);
	mutex_unlock(&tee->mutex_tee);

	if (!count_session) {
#if defined(_DUMP_INFO_ALLOCATOR) && (_DUMP_INFO_ALLOCATOR > 1)
		tee_shm_pool_dump(dev, ts->op->Allocator, true);
#endif
		tee_shm_pool_reset(dev, ts->op->Allocator);
	}

	devm_kfree(dev, ts);

	dev_dbg(dev, "<\n");
}

struct ListPhysicalAddr {
	unsigned long paddr; /* Physical address */
	unsigned int refcounter; /* Refcounter */
	struct mem_part *part; /* memory part of the allocation */
	void *handle; /* handle to registered shared memory */
	struct ListPhysicalAddr *next;
};

struct ListPhysicalAddr *_listPhysicalAddr;
static DEFINE_MUTEX(list_paddr_lock);

#define _DUMP_INFO_SHM 0
#if _DUMP_INFO_SHM == 1
static void tee_DumpShm(struct device *dev, char *message)
{
	struct ListPhysicalAddr *list;

	dev_info(dev, "tee_DumpShm() %s\n", message);
	if (!_listPhysicalAddr)
		dev_info(dev, " | No more shared memory\n");
	for (list = _listPhysicalAddr; list; list = list->next) {
		dev_info(dev,
			 "  | paddr [0x%p]  refcounter [%d]  part [0x%p]\n",
			 (void *)list->paddr, list->refcounter, list->part);

	}
}
#endif

struct ListPhysicalAddr *addPhysicalAddr(struct device *dev,
	unsigned long paddr, struct mem_part *part, bool mem_allocated)
{
	struct ListPhysicalAddr *list, *ret;

	dev_dbg(dev, "Adding physical address %p\n", (void *)paddr);

	mutex_lock(&list_paddr_lock);
	list = _listPhysicalAddr;

	while (list) {
		if (list->paddr == paddr) {
			if (part) {
				dev_err(dev, "[%s] Found physical address %p\n",
					__func__, (void *)paddr);
				dev_err(dev, "     but with part==%p\n",
					(void *)part);
				ret = NULL;
				goto out;
			}
			list->refcounter++;
#if _DUMP_INFO_SHM == 1
			tee_DumpShm(dev, "addPhysicalAddr() reference found");
#endif
			ret = list;
			goto out;
		}
		list = list->next;
	}
	mutex_unlock(&list_paddr_lock);

	if (mem_allocated && !part) {
		dev_err(dev, "[%s] New physical address with part==NULL\n",
			__func__);
		return NULL;
	}

	list = (struct ListPhysicalAddr *)devm_kzalloc(dev,
			sizeof(struct ListPhysicalAddr), GFP_KERNEL);
	if (list == NULL) {
		dev_err(dev,
			"[%s] Cannot allocate a new element in the list\n",
			__func__);
		return NULL;
	}

	memset(list, 0, sizeof(struct ListPhysicalAddr));
	list->paddr = paddr;
	list->part = part;
	list->refcounter = 1;
	mutex_lock(&list_paddr_lock);
	list->next = _listPhysicalAddr;
	_listPhysicalAddr = list;
	ret = list;
out:
	mutex_unlock(&list_paddr_lock);
#if _DUMP_INFO_SHM == 1
	tee_DumpShm(dev, "addPhysicalAddr() new reference");
#endif
	return ret;
}

static bool isPhysicalAddr(struct device *dev, unsigned long paddr)
{
	struct ListPhysicalAddr *list;

	mutex_lock(&list_paddr_lock);

	list = _listPhysicalAddr;
	while (list) {
		if (list->paddr == paddr) {
			mutex_unlock(&list_paddr_lock);
			return true;
		}
		list = list->next;
	}
	mutex_unlock(&list_paddr_lock);
	return false;
}

unsigned int removePhysicalAddr(struct device *dev, unsigned long paddr,
		struct mem_part **part, void **handle)
{
	struct ListPhysicalAddr *list, *prev = 0;

	mutex_lock(&list_paddr_lock);

	list = _listPhysicalAddr;
	*part = 0;
	*handle = 0;

	while (list) {
		if (list->paddr == paddr) {
			*part = list->part;
			*handle = list->handle;
			if (list->refcounter == 1) {
				if (prev)
					prev->next = list->next;
				else
					_listPhysicalAddr = list->next;

				mutex_unlock(&list_paddr_lock);
				devm_kfree(dev, list);
#if _DUMP_INFO_SHM == 1
				dev_info(dev, "[0x%p] is removed\n", paddr);
				tee_DumpShm(dev,
					    "removePhysicalAddr() removing a reference");
#endif

				return 0;
			} else {
				list->refcounter--;
				mutex_unlock(&list_paddr_lock);
#if _DUMP_INFO_SHM == 1
				dev_info(dev, "[0x%p] has its refcounter decreased [%d]\n",
					 paddr, list->refcounter);
				tee_DumpShm(dev,
					    "removePhysicalAddr() decreased refcounter");
#endif
				return list->refcounter;
			}
		}
		prev = list;
		list = list->next;
	}
	mutex_unlock(&list_paddr_lock);

	/* error */
	dev_err(dev, "[%s] Cannot find physical address to remove\n", __func__);
	return -1;
}

static unsigned long GetPhysicalContiguous(unsigned long ptr)
{
	struct mm_struct *mm = current->mm;
	/* struct vma_area_struct *vma = find_vma(mm, ptr); */
	unsigned virt_base = (ptr / PAGE_SIZE) * PAGE_SIZE;
	unsigned phys_base = 0;

	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *ptep, pte;

	/* if the caller is the kernel api, active_mm is mm */
	if (!mm)
		mm = current->active_mm;

	spin_lock(&mm->page_table_lock);

	pgd = pgd_offset(mm, virt_base);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		goto out;

	pmd = pmd_offset((pud_t *)pgd, virt_base);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		goto out;

	ptep = pte_offset_map(pmd, virt_base);

	if (!ptep)
		goto out;

	pte = *ptep;

	if (pte_present(pte))
		phys_base = __pa(page_address(pte_page(pte)));

	if (!phys_base)
		goto out;

	spin_unlock(&mm->page_table_lock);
	return phys_base + (ptr - virt_base);

out:
	spin_unlock(&mm->page_table_lock);
	return 0;
}

static unsigned long tee_shm_iscontinuous(
		struct device *dev,
		void *vaddr,
		unsigned long size)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;

	/* if the caller is the kernel api, active_mm is mm */
	if (!mm)
		mm = current->active_mm;

	 vma = find_vma(mm, (unsigned long)vaddr);

	if (vma == NULL) {
		/* It's not a VMA => consider it as a kernel address
		 * And look if it's an internal known phys addr
		 * Note: virt_to_phys is not usable since it can be a direct
		 * map or a vremap address
		 */
		unsigned long paddr;

		paddr = GetPhysicalContiguous((unsigned long)vaddr);
		if (isPhysicalAddr(dev, paddr))
			return paddr;
	} else {
		void *paddr = vma->vm_private_data;
		/* It's a VMA => consider it a a user address */
		if (!(vma->vm_flags & (VM_IO | VM_PFNMAP))) {
			dev_err(dev, "[%s] 0x%p not Contiguous %p\n", __func__,
				vaddr, paddr);
			return 0x0;
		}

		if (vma->vm_end - vma->vm_start < size) {
			dev_err(dev, "[%s] 0x%p not big enough %p %ld %ld\n",
					__func__, vaddr, paddr,
					vma->vm_end - vma->vm_start, size);
			return 0x0;
		}

		return (unsigned long)paddr;
	}

	return 0x0;
}

struct tee_shm *tee_shm_allocate(struct tee_targetop *op,
				 void *vaddr, int size, uint32_t flags)
{
	struct device *dev = op->miscdev->this_device;
	struct tee_shm *shm;
	struct ListPhysicalAddr *list = 0;
	struct mem_part *part = 0, *part_removed = 0;
	void *handle;
	struct tee_driver *tee = NULL;
	tee = tee_get_drvdata(dev);

	dev_dbg(dev, "> vaddr:[%p] size:[%d]\n", (void *)vaddr, size);

	shm = (struct tee_shm *)devm_kzalloc(dev, sizeof(struct tee_shm),
					   GFP_KERNEL);
	if (shm == NULL)
		return NULL;

	shm->op = op;

	/*
	 * Adjust the size in case it is 0 as, from the spec:
	 *      The size is allowed to be zero. In this case memory is
	 *      allocated and the pointer written in to the buffer field
	 *      on return MUST not be NULL but MUST never be de-referenced
	 *      by the Client Application. In this case however, the
	 *      Shared Memory block can be used in Registered Memory References
	 */
	if (size == 0)
		size = 8;

	/* Align the size to be ICS compliant */
	if ((size % op->page_size) != 0)
		size = ((size / op->page_size) + 1) * op->page_size;

	if (vaddr == NULL) {
		shm->paddr = tee_shm_pool_alloc(dev,
			op->Allocator, size, op->page_size);

		if (shm->paddr == 0x0) {
			dev_err(dev, "[%s] out of shared memory (%d)\n",
				__func__, size);
			goto out_shm;
		}
	} else {
		if (flags & SHM_ALLOCATE_FROM_PHYSICAL) {
			shm->paddr = (unsigned long)vaddr;
		} else {
			shm->paddr = tee_shm_iscontinuous(dev, vaddr, size);
			if (shm->paddr == 0x0) {
				dev_err(dev, "[%s] SHM not contiguous (0x%p + %d)\n",
					__func__, vaddr, size);
				goto out_shm;
			}
		}
	}

	list = addPhysicalAddr(dev, shm->paddr, part,
			false);
	if (!list)
		goto out_mem;
	if (list->refcounter == 1)
		if (op->register_shm(shm->paddr, size, &list->handle)
				!= TEEC_SUCCESS) {
			dev_err(dev, "[%s] Cannot register [0x%p] size [%d]\n",
				__func__, (void *)shm->paddr, size);
			goto out_mem;
		}

	dev_dbg(dev, "< %p + %d\n", (void *)shm->paddr, size);
	return shm;

out_mem:
	if (list)
		removePhysicalAddr(dev, shm->paddr, &part_removed, &handle);

	tee_shm_pool_free(dev, shm->op->Allocator, shm->paddr, &size);
out_shm:
	if (shm)
		devm_kfree(dev, shm);
	dev_dbg(dev, "<\n");
	return NULL;
}

void tee_shm_unallocate(struct tee_shm *shm)
{
	struct device *dev = shm->op->miscdev->this_device;
	struct mem_part *part;
	void *handle;
	uint32_t size;
	struct tee_driver *tee = NULL;
	unsigned int refcounter =
		removePhysicalAddr(dev, shm->paddr, &part, &handle);
	tee = tee_get_drvdata(dev);

	if (refcounter == 0) {
		if (handle)
			shm->op->unregister_shm(handle);

		tee_shm_pool_free(dev,
				  shm->op->Allocator, shm->paddr, &size);
	}

	devm_kfree(dev, shm);
}

TEEC_Result allocate_uuid(struct tee_session *ts)
{
	unsigned long paddr;
	struct device *dev = ts->op->miscdev->this_device;

	dev_dbg(dev, "> session: [0x%p]\n", ts);

	paddr = tee_shm_pool_alloc(
			dev, ts->op->Allocator, sizeof(TEEC_UUID), 0);
	if (paddr == 0x0) {
		dev_err(dev, "[%s] error, out of memory\n", __func__);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	ts->uuid = tee_shm_pool_p2v(dev, ts->op->Allocator, paddr);

	dev_dbg(dev, "<\n");
	return TEEC_SUCCESS;
}

static TEEC_Result tee_cpy_memref(struct tee_session *ts, void *buffer,
				  uint32_t size, TEEC_Value *param, int type)
{
	unsigned long paddr;
	void *vaddr;
	size_t size_allocate = (size_t)size;
	struct device *dev = ts->op->miscdev->this_device;

	dev_dbg(dev, "> session: [0x%p] buffer [0x%p]\n", ts, buffer);
	param->b = size;

	/* Size 0 is OK to use.
	 * Artificially set the size to 8 for buffer allocation
	 */
	if (size_allocate == 0)
		size_allocate = 8;

	/*
	 * Allocate consecutive memory
	 */
	paddr = tee_shm_pool_alloc(dev, ts->op->Allocator, size_allocate, 0);
	if (!paddr) {
		dev_err(dev, "[%s] couldn't alloc tee memory\n", __func__);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	vaddr = tee_shm_pool_p2v(dev, ts->op->Allocator, paddr);

	if ((size) && (type != TEEC_MEMREF_TEMP_OUTPUT)) {
		if (ts->userApi) {
			if (copy_from_user(vaddr, buffer, size)) {
				dev_err(dev, "     *** tee_cpy_memref(0x%p, %lx, %d) failed\n",
					buffer, paddr, size);
				tee_shm_pool_free(dev, ts->op->Allocator,
						  paddr, NULL);
				return TEEC_ERROR_BAD_PARAMETERS;
			}
		} else {
			memcpy(vaddr, buffer, size);
		}
	}

	param->a = paddr;

	dev_dbg(dev, "< copied to vaddr [0x%p] paddr [0x%p]\n",
		vaddr, (void *)paddr);
	return TEEC_SUCCESS;
}

static TEEC_Result tee_resolve_shm(struct device *dev, TEEC_SharedMemory *shm,
				   TEEC_Value *param)
{
	unsigned long paddr;

	BUG_ON(shm->buffer == NULL);

	paddr = tee_shm_iscontinuous(dev, shm->buffer, shm->size);
	if (paddr == 0x0)
		return TEEC_ERROR_NOT_SUPPORTED;

	dev_dbg(dev, "[%s] => %lx\n", __func__, paddr);

	param->a = (uint32_t) (paddr);
	param->b = shm->size;

	return TEEC_SUCCESS;
}

TEEC_Result copy_op(struct tee_session *ts, TEEC_Operation *op,
		    unsigned long
		    tmp_allocated_memories[TEEC_CONFIG_PAYLOAD_REF_COUNT],
		    uint32_t *param_type,
		    TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT])
{
	TEEC_Result ret;
	int memref;
	struct device *dev = ts->op->miscdev->this_device;
	dev_dbg(dev, ">\n");

	*param_type = 0;

	for (memref = 0; memref < TEEC_CONFIG_PAYLOAD_REF_COUNT; ++memref)
		tmp_allocated_memories[memref] = 0UL;

	for (memref = 0; memref < TEEC_CONFIG_PAYLOAD_REF_COUNT; ++memref) {
		int type = TEEC_PARAM_TYPE_GET(op->paramTypes, memref);
		dev_dbg(dev, "type [0x%x]\n", type);

		switch (type) {
		case TEEC_NONE:
			break;
		case TEEC_VALUE_INPUT:
		case TEEC_VALUE_OUTPUT:
		case TEEC_VALUE_INOUT: {
				/* nothing to copy or allocate */
				params[memref] = op->params[memref].value;
				dev_dbg(dev, "   params[%d] = %x:%x (VALUE)\n",
					memref, params[memref].a,
					params[memref].b);
				break;
			}
		case TEEC_MEMREF_TEMP_INPUT:
		case TEEC_MEMREF_TEMP_OUTPUT:
		case TEEC_MEMREF_TEMP_INOUT: {
				ret = tee_cpy_memref(ts,
				op->params[memref].tmpref.buffer,
				op->params[memref].tmpref.size,
				&params[memref], type);
				if (ret != TEEC_SUCCESS)
					goto out_failed;
				tmp_allocated_memories[memref] =
					params[memref].a;
				dev_dbg(dev, "   params[%d] = %x + %d (TEMP)\n",
					memref, params[memref].a,
					params[memref].b);
				break;
			}
		case TEEC_MEMREF_WHOLE: {
				TEEC_SharedMemory shm;

				if (ts->userApi) {
					if (copy_from_user(&shm,
							   op->
						params[memref].memref.parent,
					 sizeof(TEEC_SharedMemory))) {
						ret = TEEC_ERROR_BAD_PARAMETERS;
						goto out_failed;
					}
				} else {
					shm = *op->params[memref].memref.parent;
				}

				if (shm.flags == TEEC_MEM_INPUT)
					type = TEEC_MEMREF_TEMP_INPUT;
				else if (shm.flags == TEEC_MEM_OUTPUT)
					type = TEEC_MEMREF_TEMP_OUTPUT;
				else if (shm.flags ==
					 (TEEC_MEM_INPUT | TEEC_MEM_OUTPUT))
					type = TEEC_MEMREF_TEMP_INOUT;

				if (tee_resolve_shm(dev, &shm, &params[memref])
				    != TEEC_SUCCESS) {
					/* This is not a continuous
					 * allocated buffer => Do copy */
					ret = tee_cpy_memref(ts,
							     shm.buffer,
							     shm.size,
							     &params[memref],
							     type);
					if (ret != TEEC_SUCCESS)
						goto out_failed;
					tmp_allocated_memories[memref] =
							params[memref].a;
				}

				dev_dbg(dev,
					"   params[%d] = %x + %d (WHOLE)\n",
					memref, params[memref].a,
					params[memref].b);
				break;
			}
		case TEEC_MEMREF_PARTIAL_INPUT:
		case TEEC_MEMREF_PARTIAL_OUTPUT:
		case TEEC_MEMREF_PARTIAL_INOUT: {
			u32 offset = op->params[memref].memref.offset;
			u32 size = op->params[memref].memref.size;
			TEEC_SharedMemory shm;

			if (ts->userApi) {
				if (copy_from_user(&shm ,
						   op->
						params[memref].memref.parent,
					sizeof(TEEC_SharedMemory))) {
						ret = TEEC_ERROR_BAD_PARAMETERS;
						goto out_failed;
					}
			} else {
				shm = *op->params[memref].memref.parent;
			}

			if (type == TEEC_MEMREF_PARTIAL_INPUT)
				type = TEEC_MEMREF_TEMP_INPUT;
			else if (type == TEEC_MEMREF_PARTIAL_OUTPUT)
				type = TEEC_MEMREF_TEMP_OUTPUT;
			else if (type == TEEC_MEMREF_PARTIAL_INOUT)
				type = TEEC_MEMREF_TEMP_INOUT;

			if (tee_resolve_shm(dev, &shm, &params[memref])
				!= TEEC_SUCCESS) {
				/* This is not a continuous
				 * allocated buffer => Do copy */
				ret = tee_cpy_memref(ts,
						     (uint8_t *)shm.
						     buffer + offset,
						     size,
						     &params[memref],
						     type);
				if (ret != TEEC_SUCCESS)
					goto out_failed;
				tmp_allocated_memories[memref] =
					params[memref].a;
				} else {
					params[memref].a += offset;
					params[memref].b = size;
				}
				dev_dbg(dev,
					"   params[%d] = %x + %d (PARTIAL)\n",
					memref, params[memref].a,
					params[memref].b);
				break;
			}
		default:
			ret = TEEC_ERROR_BAD_PARAMETERS;
			goto out_failed;
		}

		*param_type |= (type << (memref * 4));
	}

	dev_dbg(dev, "< TEEC_SUCCESS\n");
	return TEEC_SUCCESS;

out_failed:
	for (memref = 0; memref < TEEC_CONFIG_PAYLOAD_REF_COUNT; memref++)
		if (tmp_allocated_memories[memref] != 0UL) {
			tee_shm_pool_free(dev, ts->op->Allocator,
					  tmp_allocated_memories[memref], NULL);
		tmp_allocated_memories[memref] = 0UL;
	}
	return ret;
}

static TEEC_Result tee_update_buffer(struct device *dev, struct tee_session *ts,
				     void *buffer,
				     unsigned long paddr, unsigned int size)
{
	void *vaddr = tee_shm_pool_p2v(dev, ts->op->Allocator, paddr);

	dev_dbg(dev, "[%d] [%p] [%p] [%p] %d\n",
		ts->userApi, buffer, (void *)paddr, vaddr, size);

	if (ts->userApi) {
		if (copy_to_user(buffer, vaddr, size)) {
			dev_err(dev,
				"     *** tee_update_buffer(0x%p, %lx, %d) failed\n",
				buffer, paddr, size);
			return TEEC_ERROR_BAD_PARAMETERS;
		}
	} else {
		memcpy(buffer, vaddr, size);
	}

	dev_dbg(dev, "< TEEC_SUCCESS\n");
	return TEEC_SUCCESS;
}

TEEC_Result uncopy_op(struct tee_session *ts, TEEC_Operation *op,
		      unsigned long
		      tmp_allocated_memories[TEEC_CONFIG_PAYLOAD_REF_COUNT],
		      TEEC_Value params[TEEC_CONFIG_PAYLOAD_REF_COUNT])
{
	int memref;
	TEEC_Result ret = TEEC_SUCCESS;
	struct device *dev = ts->op->miscdev->this_device;

	dev_dbg(dev, "> session: [0x%p]\n", ts);


	for (memref = 0; memref < TEEC_CONFIG_PAYLOAD_REF_COUNT; ++memref) {
		int type = TEEC_PARAM_TYPE_GET(op->paramTypes, memref);
		dev_dbg(dev, "type [0x%x]\n", type);
		switch (type) {
		case TEEC_NONE:
		case TEEC_VALUE_INPUT:
		case TEEC_MEMREF_TEMP_INPUT:
		case TEEC_MEMREF_PARTIAL_INPUT:
			/* nothing to copy */
			break;

		case TEEC_VALUE_OUTPUT:
		case TEEC_VALUE_INOUT:
			op->params[memref].value = params[memref];
			break;

		case TEEC_MEMREF_TEMP_OUTPUT:
		case TEEC_MEMREF_TEMP_INOUT:
			{
				op->params[memref].tmpref.size =
				    params[memref].b;
				ret =
				    tee_update_buffer(dev, ts,
						      op->params[memref].tmpref.
						      buffer, params[memref].a,
						      params[memref].b);
				break;
			}
		case TEEC_MEMREF_WHOLE:
			{
				TEEC_SharedMemory shm;

				if (ts->userApi) {
					if (copy_from_user
					    (&shm,
					     op->params[memref].memref.parent,
					     sizeof(TEEC_SharedMemory)))
						goto inval;
				} else {
					shm = *op->params[memref].memref.parent;
				}

				op->params[memref].memref.size =
				    params[memref].b;
				if (tmp_allocated_memories[memref] != 0x0) {
					ret =
					    tee_update_buffer(dev, ts,
							      shm.buffer,
							      params[memref].a,
							      shm.size);
				}
				break;
			}
		case TEEC_MEMREF_PARTIAL_OUTPUT:
		case TEEC_MEMREF_PARTIAL_INOUT:
			{
				u32 offset = op->params[memref].memref.offset;
				size_t size = params[memref].b;
				TEEC_SharedMemory shm;

				if (ts->userApi) {
					if (copy_from_user
					    (&shm,
					     op->params[memref].memref.parent,
					     sizeof(TEEC_SharedMemory)))
						goto inval;
				} else {
					shm = *op->params[memref].memref.parent;
				}

				/* ensure we do not exceed
				 * the shared buffer length */
				if ((offset + size) > shm.size) {
					dev_err(dev,
						"  *** Wrong returned size from %d\n",
						memref);
					goto inval;
				}

				op->params[memref].memref.size = size;
				if (tmp_allocated_memories[memref] != 0x0) {
					ret =
					    tee_update_buffer(dev, ts,
							      shm.buffer +
							      offset,
							      params[memref].a,
							      size);
				}
				break;
			}
		default:
			goto inval;
		}
		if (ret != TEEC_SUCCESS)
			goto out;
	}

	goto out;
inval:
	ret = TEEC_ERROR_BAD_PARAMETERS;
out:
	for (memref = 0; memref < TEEC_CONFIG_PAYLOAD_REF_COUNT; memref++)
		if (tmp_allocated_memories[memref] != 0x0)
			tee_shm_pool_free(dev, ts->op->Allocator,
					  tmp_allocated_memories[memref],
					  NULL);

	dev_dbg(dev, "< [%d]\n", ret);

	return ret;
}
