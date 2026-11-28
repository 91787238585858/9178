#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "allowlist.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "throne_tracker.h"
#include "syscall_hook_manager.h"
#include "ksud.h"
#include "supercalls.h"

/* 4.14 diagnostic: each init step leaves a /proc marker behind, so a userland
 * shell can tell exactly how far kernelsu_init() got without dmesg access. */
static int ksu_step_show(struct seq_file *m, void *v)
{
	seq_printf(m, "ok\n");
	return 0;
}

static int ksu_step_open(struct inode *i, struct file *f)
{
	return single_open(f, ksu_step_show, NULL);
}

static const struct file_operations ksu_step_fops = {
	.open = ksu_step_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static void ksu_mark(const char *name)
{
	proc_create(name, 0444, NULL, &ksu_step_fops);
}

int __init kernelsu_init(void)
{
	ksu_mark("ksu_step0_enter");

#ifdef CONFIG_KSU_DEBUG
	pr_alert("*************************************************************");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("**                                                         **");
	pr_alert("**         You are running KernelSU in DEBUG mode          **");
	pr_alert("**                                                         **");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("*************************************************************");
#endif

	ksu_feature_init();
	ksu_mark("ksu_step1_feature");

	ksu_supercalls_init();
	ksu_mark("ksu_step2_supercalls");

	ksu_syscall_hook_manager_init();
	ksu_mark("ksu_step3_syscallhooks");

	ksu_allowlist_init();
	ksu_mark("ksu_step4_allowlist");

	ksu_throne_tracker_init();
	ksu_mark("ksu_step5_throne");

#ifdef CONFIG_KPROBES
	ksu_ksud_init();
	ksu_mark("ksu_step6_ksud");
#else
	pr_alert("KPROBES is disabled, KernelSU may not work, please check https://kernelsu.org/guide/how-to-integrate-for-non-gki.html");
#endif

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
	kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif

	ksu_mark("ksu_step7_done");
	return 0;
}

extern void ksu_observer_exit(void);
void kernelsu_exit(void)
{
	ksu_allowlist_exit();

	ksu_throne_tracker_exit();

	ksu_observer_exit();

#ifdef CONFIG_KPROBES
	ksu_ksud_exit();
#endif

	ksu_syscall_hook_manager_exit();

	ksu_supercalls_exit();

	ksu_feature_exit();
}

module_init(kernelsu_init);
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
