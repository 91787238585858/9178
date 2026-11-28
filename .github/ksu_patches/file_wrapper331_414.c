// SPDX-License-Identifier: GPL-2.0
// 4.14-compatible file_wrapper for KernelSU v3.3.1
//
// The upstream v3.3.1 implementation relies on kernel internals that only
// exist on 5.10+ (anon_inode_mnt, alloc_file_pseudo, QSTR_INIT based secure
// anon inodes, security_inode_init_security_anon).  On 4.14 we provide an
// equivalent but simpler wrapper: the same pass-through file_operations,
// installed on a plain anon inode via anon_inode_getfile().

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/anon_inodes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "klog.h" // IWYU pragma: keep

#include "infra/file_wrapper.h"

#define KSU_FILE_WRAPPER_NAME "[ksu_fdwrapper]"

struct ksu_file_wrapper {
	struct file *orig;
	struct file_operations ops;
};

static void ksu_release_file_wrapper(struct ksu_file_wrapper *data);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
typedef unsigned int __poll_t;
#endif

static loff_t ksu_wrapper_llseek(struct file *fp, loff_t off, int flags)
{
	struct ksu_file_wrapper *data = fp->private_data;
	return data->orig->f_op->llseek(data->orig, off, flags);
}

static ssize_t ksu_wrapper_read(struct file *fp, char __user *ptr, size_t sz, loff_t *off)
{
	struct ksu_file_wrapper *data = fp->private_data;
	return data->orig->f_op->read(data->orig, ptr, sz, off);
}

static ssize_t ksu_wrapper_write(struct file *fp, const char __user *ptr, size_t sz, loff_t *off)
{
	struct ksu_file_wrapper *data = fp->private_data;
	return data->orig->f_op->write(data->orig, ptr, sz, off);
}

static ssize_t ksu_wrapper_read_iter(struct kiocb *iocb, struct iov_iter *iovi)
{
	struct ksu_file_wrapper *data = iocb->ki_filp->private_data;
	struct file *orig = data->orig;
	iocb->ki_filp = orig;
	return orig->f_op->read_iter(iocb, iovi);
}

static ssize_t ksu_wrapper_write_iter(struct kiocb *iocb, struct iov_iter *iovi)
{
	struct ksu_file_wrapper *data = iocb->ki_filp->private_data;
	struct file *orig = data->orig;
	iocb->ki_filp = orig;
	return orig->f_op->write_iter(iocb, iovi);
}

static int ksu_wrapper_iterate(struct file *fp, struct dir_context *dc)
{
	struct ksu_file_wrapper *data = fp->private_data;
	return data->orig->f_op->iterate(data->orig, dc);
}

static int ksu_wrapper_iterate_shared(struct file *fp, struct dir_context *dc)
{
	struct ksu_file_wrapper *data = fp->private_data;
	return data->orig->f_op->iterate_shared(data->orig, dc);
}

static __poll_t ksu_wrapper_poll(struct file *fp, struct poll_table_struct *pts)
{
	struct ksu_file_wrapper *data = fp->private_data;
	return data->orig->f_op->poll(data->orig, pts);
}

static long ksu_wrapper_unlocked_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	struct ksu_file_wrapper *data = fp->private_data;
	return data->orig->f_op->unlocked_ioctl(data->orig, cmd, arg);
}

static long ksu_wrapper_compat_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	struct ksu_file_wrapper *data = fp->private_data;
	return data->orig->f_op->compat_ioctl(data->orig, cmd, arg);
}

static int ksu_wrapper_mmap(struct file *fp, struct vm_area_struct *vma)
{
	struct ksu_file_wrapper *data = fp->private_data;
	return data->orig->f_op->mmap(data->orig, vma);
}

static int ksu_wrapper_open(struct inode *ino, struct file *fp)
{
	struct ksu_file_wrapper *data = fp->private_data;
	struct file *orig = data->orig;
	return orig->f_op->open(file_inode(orig), orig);
}

static int ksu_wrapper_flush(struct file *fp, fl_owner_t id)
{
	struct ksu_file_wrapper *data = fp->private_data;
	return data->orig->f_op->flush(data->orig, id);
}

static int ksu_wrapper_fsync(struct file *fp, loff_t off1, loff_t off2, int datasync)
{
	struct ksu_file_wrapper *data = fp->private_data;
	return data->orig->f_op->fsync(data->orig, off1, off2, datasync);
}

static int ksu_wrapper_fasync(int arg, struct file *fp, int arg2)
{
	struct ksu_file_wrapper *data = fp->private_data;
	return data->orig->f_op->fasync(arg, data->orig, arg2);
}

static int ksu_wrapper_lock(struct file *fp, int arg1, struct file_lock *fl)
{
	struct ksu_file_wrapper *data = fp->private_data;
	return data->orig->f_op->lock(data->orig, arg1, fl);
}

static ssize_t ksu_wrapper_sendpage(struct file *fp, struct page *pg, int arg1, size_t sz,
				    loff_t *off, int arg2)
{
	struct ksu_file_wrapper *data = fp->private_data;
	struct file *orig = data->orig;
	if (orig->f_op->sendpage)
		return orig->f_op->sendpage(orig, pg, arg1, sz, off, arg2);
	return -EINVAL;
}

static unsigned long ksu_wrapper_get_unmapped_area(struct file *fp, unsigned long arg1,
						   unsigned long arg2, unsigned long arg3,
						   unsigned long arg4)
{
	struct ksu_file_wrapper *data = fp->private_data;
	struct file *orig = data->orig;
	if (orig->f_op->get_unmapped_area)
		return orig->f_op->get_unmapped_area(orig, arg1, arg2, arg3, arg4);
	return -EINVAL;
}

static int ksu_wrapper_flock(struct file *fp, int arg1, struct file_lock *fl)
{
	struct ksu_file_wrapper *data = fp->private_data;
	struct file *orig = data->orig;
	if (orig->f_op->flock)
		return orig->f_op->flock(orig, arg1, fl);
	return -EINVAL;
}

static ssize_t ksu_wrapper_splice_write(struct pipe_inode_info *pii, struct file *fp,
					loff_t *off, size_t sz, unsigned int arg1)
{
	struct ksu_file_wrapper *data = fp->private_data;
	struct file *orig = data->orig;
	if (orig->f_op->splice_write)
		return orig->f_op->splice_write(pii, orig, off, sz, arg1);
	return -EINVAL;
}

static ssize_t ksu_wrapper_splice_read(struct file *fp, loff_t *off,
				       struct pipe_inode_info *pii, size_t sz,
				       unsigned int arg1)
{
	struct ksu_file_wrapper *data = fp->private_data;
	struct file *orig = data->orig;
	if (orig->f_op->splice_read)
		return orig->f_op->splice_read(orig, off, pii, sz, arg1);
	return -EINVAL;
}

static int ksu_wrapper_setlease(struct file *fp, long arg1, struct file_lock **fl, void **p)
{
	struct ksu_file_wrapper *data = fp->private_data;
	struct file *orig = data->orig;
	if (orig->f_op->setlease)
		return orig->f_op->setlease(orig, arg1, fl, p);
	return -EINVAL;
}

static long ksu_wrapper_fallocate(struct file *fp, int mode, loff_t offset, loff_t len)
{
	struct ksu_file_wrapper *data = fp->private_data;
	struct file *orig = data->orig;
	if (orig->f_op->fallocate)
		return orig->f_op->fallocate(orig, mode, offset, len);
	return -EINVAL;
}

static void ksu_wrapper_show_fdinfo(struct seq_file *m, struct file *f)
{
	struct ksu_file_wrapper *data = f->private_data;
	struct file *orig = data->orig;
	if (orig->f_op->show_fdinfo)
		orig->f_op->show_fdinfo(m, orig);
}

static ssize_t ksu_wrapper_copy_file_range(struct file *file_in, loff_t pos_in,
					   struct file *file_out, loff_t pos_out,
					   size_t len, unsigned int flags)
{
	struct ksu_file_wrapper *data = file_out->private_data;
	struct file *orig = data->orig;
	if (!orig->f_op->copy_file_range)
		return -EINVAL;
	return orig->f_op->copy_file_range(file_in, pos_in, orig, pos_out, len, flags);
}

static int ksu_wrapper_release(struct inode *inode, struct file *filp)
{
	ksu_release_file_wrapper(filp->private_data);
	filp->private_data = NULL;
	return 0;
}

static struct ksu_file_wrapper *ksu_create_file_wrapper(struct file *fp)
{
	struct ksu_file_wrapper *p = kcalloc(1, sizeof(*p), GFP_KERNEL);
	struct file_operations *ops;

	if (!p)
		return ERR_PTR(-ENOMEM);

	get_file(fp);
	p->orig = fp;
	ops = &p->ops;
	ops->owner = THIS_MODULE;
	ops->llseek = fp->f_op->llseek ? ksu_wrapper_llseek : NULL;
	ops->read = fp->f_op->read ? ksu_wrapper_read : NULL;
	ops->write = fp->f_op->write ? ksu_wrapper_write : NULL;
	ops->read_iter = fp->f_op->read_iter ? ksu_wrapper_read_iter : NULL;
	ops->write_iter = fp->f_op->write_iter ? ksu_wrapper_write_iter : NULL;
	ops->iterate = fp->f_op->iterate ? ksu_wrapper_iterate : NULL;
	ops->iterate_shared = fp->f_op->iterate_shared ? ksu_wrapper_iterate_shared : NULL;
	ops->poll = fp->f_op->poll ? ksu_wrapper_poll : NULL;
	ops->unlocked_ioctl = fp->f_op->unlocked_ioctl ? ksu_wrapper_unlocked_ioctl : NULL;
	ops->compat_ioctl = fp->f_op->compat_ioctl ? ksu_wrapper_compat_ioctl : NULL;
	ops->mmap = fp->f_op->mmap ? ksu_wrapper_mmap : NULL;
	ops->open = fp->f_op->open ? ksu_wrapper_open : NULL;
	ops->flush = fp->f_op->flush ? ksu_wrapper_flush : NULL;
	ops->release = ksu_wrapper_release;
	ops->fsync = fp->f_op->fsync ? ksu_wrapper_fsync : NULL;
	ops->fasync = fp->f_op->fasync ? ksu_wrapper_fasync : NULL;
	ops->lock = fp->f_op->lock ? ksu_wrapper_lock : NULL;
	ops->sendpage = fp->f_op->sendpage ? ksu_wrapper_sendpage : NULL;
	ops->get_unmapped_area = fp->f_op->get_unmapped_area ? ksu_wrapper_get_unmapped_area : NULL;
	ops->check_flags = fp->f_op->check_flags;
	ops->flock = fp->f_op->flock ? ksu_wrapper_flock : NULL;
	ops->splice_write = fp->f_op->splice_write ? ksu_wrapper_splice_write : NULL;
	ops->splice_read = fp->f_op->splice_read ? ksu_wrapper_splice_read : NULL;
	ops->setlease = fp->f_op->setlease ? ksu_wrapper_setlease : NULL;
	ops->fallocate = fp->f_op->fallocate ? ksu_wrapper_fallocate : NULL;
	ops->show_fdinfo = fp->f_op->show_fdinfo ? ksu_wrapper_show_fdinfo : NULL;
	ops->copy_file_range = fp->f_op->copy_file_range ? ksu_wrapper_copy_file_range : NULL;

	return p;
}

static void ksu_release_file_wrapper(struct ksu_file_wrapper *data)
{
	if (!data)
		return;
	if (data->orig)
		fput(data->orig);
	kfree(data);
}

int ksu_install_file_wrapper(int fd)
{
	struct file *orig;
	struct file *wrapper_file;
	struct ksu_file_wrapper *data;
	int out_fd;

	orig = fget(fd);
	if (!orig)
		return -EBADF;

	out_fd = get_unused_fd_flags(O_CLOEXEC);
	if (out_fd < 0) {
		fput(orig);
		return out_fd;
	}

	data = ksu_create_file_wrapper(orig);
	if (IS_ERR(data)) {
		put_unused_fd(out_fd);
		fput(orig);
		return PTR_ERR(data);
	}

	wrapper_file = anon_inode_getfile(KSU_FILE_WRAPPER_NAME, &data->ops, data,
					  orig->f_flags & (O_ACCMODE | O_NONBLOCK));
	if (IS_ERR(wrapper_file)) {
		put_unused_fd(out_fd);
		ksu_release_file_wrapper(data);
		fput(orig);
		return PTR_ERR(wrapper_file);
	}

	fd_install(out_fd, wrapper_file);
	fput(orig);

	pr_info("ksu fd wrapper installed: fd %d -> %d\n", fd, out_fd);
	return out_fd;
}

void ksu_file_wrapper_init(void)
{
	/* nothing to initialise on 4.14 (no secure anon inode support) */
}
