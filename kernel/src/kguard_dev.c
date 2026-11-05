// SPDX-License-Identifier: GPL-2.0
/*
 * KGuard Kernel Module - /dev/kguard character device
 *
 * Gives one reader zero-copy access to the event rings:
 *   open()   claims the rings (one reader at a time, -EBUSY otherwise)
 *   mmap()   maps the ring area (MAP_SHARED, read/write so the reader can
 *            publish its tail)
 *   poll()   sleeps until any ring holds events
 *
 * Who may open it: CAP_NET_ADMIN, or members of the reader_gid group.
 */

#include "kguard.h"

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/wait.h>

static DECLARE_WAIT_QUEUE_HEAD(kguard_wq);

/* Called by producers; cheap when nobody is sleeping in poll() */
void kguard_dev_wakeup(void)
{
	if (wq_has_sleeper(&kguard_wq))
		wake_up_interruptible(&kguard_wq);
}

bool kguard_reader_allowed(void)
{
	int gid = READ_ONCE(kguard_reader_gid);

	if (capable(CAP_NET_ADMIN))
		return true;
	return gid >= 0 && in_group_p(make_kgid(&init_user_ns, gid));
}

static int kguard_dev_open(struct inode *inode, struct file *file)
{
	if (!kguard_reader_allowed())
		return -EPERM;
	if (!kguard_reader_claim())
		return -EBUSY;
	return stream_open(inode, file);
}

static int kguard_dev_release(struct inode *inode, struct file *file)
{
	kguard_reader_release();
	return 0;
}

static int kguard_dev_mmap(struct file *file, struct vm_area_struct *vma)
{
	/* A private mapping would hide the reader's tail updates from the kernel */
	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;
	if (vma->vm_flags & VM_EXEC)
		return -EPERM;
	vm_flags_clear(vma, VM_MAYEXEC);

	return remap_vmalloc_range(vma, kguard_ring_area(), vma->vm_pgoff);
}

static __poll_t kguard_dev_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &kguard_wq, wait);
	return kguard_ring_has_data() ? EPOLLIN | EPOLLRDNORM : 0;
}

static const struct file_operations kguard_dev_fops = {
	.owner		= THIS_MODULE,
	.open		= kguard_dev_open,
	.release	= kguard_dev_release,
	.mmap		= kguard_dev_mmap,
	.poll		= kguard_dev_poll,
	.llseek		= no_llseek,
};

static struct miscdevice kguard_miscdev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= KGUARD_MODULE_NAME,
	.fops	= &kguard_dev_fops,
	/* open() does the real permission check; readers need O_RDWR for mmap */
	.mode	= 0666,
};

int kguard_dev_init(void)
{
	return misc_register(&kguard_miscdev);
}

void kguard_dev_cleanup(void)
{
	misc_deregister(&kguard_miscdev);
}
