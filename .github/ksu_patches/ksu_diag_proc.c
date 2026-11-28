// 4.14 diagnostic: expose KernelSU's internal view to userland via /proc.
// SELinux blocks kernel writes to /data, but /proc nodes are visible to shell.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "manager.h"
#include "throne_tracker.h"

extern unsigned long kallsyms_lookup_name(const char *name);

static int ksu_diag_tries = 0;
static int ksu_track_runs = 0;

static void ksu_diag_work_fn(struct work_struct *w);
static DECLARE_DELAYED_WORK(ksu_diag_work, ksu_diag_work_fn);

static int ksu_diag_show(struct seq_file *m, void *v)
{
	seq_printf(m, "manager_uid=%d\n", ksu_get_manager_uid());
	seq_printf(m, "tries=%d\n", ksu_diag_tries);
	seq_printf(m, "kallsyms_sys_reboot=%lx\n", kallsyms_lookup_name("sys_reboot"));
	seq_printf(m, "kallsyms_arm64_reboot=%lx\n", kallsyms_lookup_name("__arm64_sys_reboot"));
	seq_printf(m, "kallsyms_sys_execve=%lx\n", kallsyms_lookup_name("sys_execve"));
	seq_printf(m, "kallsyms_sys_read=%lx\n", kallsyms_lookup_name("sys_read"));
	return 0;
}

static int ksu_diag_open(struct inode *i, struct file *f)
{
	return single_open(f, ksu_diag_show, NULL);
}

static const struct file_operations ksu_diag_fops = {
	.open = ksu_diag_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static void ksu_diag_work_fn(struct work_struct *w)
{
	ksu_diag_tries++;
	pr_info("ksu_diag tick %d manager_uid=%d\n", ksu_diag_tries,
		ksu_get_manager_uid());
	if (ksu_diag_tries < 20)
		schedule_delayed_work(&ksu_diag_work, 15 * HZ);
}

int __init ksu_diag_init(void)
{
	proc_create("ksu_diag", 0444, NULL, &ksu_diag_fops);
	proc_create("ksu_diag_alive", 0444, NULL, &ksu_diag_fops);
	schedule_delayed_work(&ksu_diag_work, 30 * HZ);
	return 0;
}

void ksu_diag_note_track(void)
{
	ksu_track_runs++;
}
