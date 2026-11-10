/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KGuard - differences between the kernel versions the module builds on
 * (5.15 and later; see kernel/tests/kernel_matrix.sh)
 */
#ifndef _KGUARD_COMPAT_H
#define _KGUARD_COMPAT_H

#include <linux/version.h>
#include <linux/mm.h>
#include <linux/slab.h>

/* vm_flags became read-only behind accessors in 6.3 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
static inline void kguard_vm_flags_clear(struct vm_area_struct *vma,
					 unsigned long flags)
{
	vma->vm_flags &= ~flags;
}
#else
#define kguard_vm_flags_clear(vma, flags) vm_flags_clear(vma, flags)
#endif

/*
 * SLAB_NO_MERGE arrived in 6.5. Before it, the source cache may be merged
 * with another of the same size, so its /proc/slabinfo line can be shared.
 */
#ifndef SLAB_NO_MERGE
#define SLAB_NO_MERGE 0
#endif

/*
 * genl_family.resv_start_op (6.0) makes commands from that number on
 * strictly validated. Before 6.0 every op of a new family already is.
 */
#define KGUARD_HAVE_RESV_START_OP (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0))

#endif /* _KGUARD_COMPAT_H */
