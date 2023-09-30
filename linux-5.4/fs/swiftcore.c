#include <linux/time.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#include "swiftcore.h"

int swiftcore_filesize_limit = 1; //in gb
static const char proc_dirname[] = "fs/swiftcore";
static struct proc_dir_entry *swiftcore_proc_root;

ssize_t swiftcore_filesize_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
  char *_buf;
	int retval = len;

	_buf = kmalloc(len, GFP_KERNEL);
	if (_buf == NULL)  {
		retval = -ENOMEM;
		goto out;
	}
	if (copy_from_user(_buf, buf, len)) {
		retval = -EFAULT;
		goto out;
	}
	_buf[len] = 0;
	sscanf(_buf, "%i", &swiftcore_filesize_limit);

out:
  return retval;
}

static int swiftcore_filesize_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "%i\n", swiftcore_filesize_limit);
	return 0;
}

static int swiftcore_filesize_open(struct inode *inode, struct file *file)
{
	return single_open(file, swiftcore_filesize_show, PDE_DATA(inode));
}

static const struct file_operations swiftcore_filesize_fops = {
	.owner		= THIS_MODULE,
	.open		= swiftcore_filesize_open,
	.read		= seq_read,
	.write		= swiftcore_filesize_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_swiftcore_init(void)
{
	swiftcore_proc_root = proc_mkdir(proc_dirname, NULL);
	proc_create_data("swiftcore_filesize_limit", 0664, swiftcore_proc_root, &swiftcore_filesize_fops, NULL);
	return 0;
}
fs_initcall(proc_swiftcore_init);
