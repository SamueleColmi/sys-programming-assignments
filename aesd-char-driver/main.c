/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("5am");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev *aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    // PDEBUG("open");

    struct aesd_dev *dev;

    /* Find the device */
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);

    /* Initialize file pointer */
    filp->private_data = dev;

    // PDEBUG("open complete");

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    // PDEBUG("release");

    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    ssize_t read = 0;
    ssize_t offset;

    do {
        entry = aesd_circular_buffer_find_entry_offset_for_fpos(&(dev->buffer), *f_pos, &offset);
        if (offset != 0)
            PDEBUG("WARNING: offset is not zero: %ld", offset);
        if (!entry)
            goto exit;

        // PDEBUG("Read: %s", entry->buffptr);

        if (copy_to_user(buf + (read), entry->buffptr, entry->size)) {
            PDEBUG("ERROR: copy_to_user() failed");
        }

        read += entry->size;
        *f_pos += entry->size;

    } while (read < count);

exit:
    return read;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);

    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry buf_entry;
    ssize_t retval = count;
    const char *ret_buf;
    char *buffer;

    buffer = kmalloc(count * sizeof(char), GFP_KERNEL);
    if (!buffer) {
        PDEBUG("ERROR: buffer kmalloc failed");
        retval = -ENOMEM;
        goto exit;
    }

    if (copy_from_user(buffer, buf, count)) {
        PDEBUG("ERROR: copy_from_user() failed");
        retval = -EFAULT;
        goto copy_err;
    }

    buf_entry.buffptr = buffer;
    buf_entry.size = count;
    ret_buf = aesd_circular_buffer_add_entry(&(dev->buffer), &buf_entry);
    if (ret_buf) {
        PDEBUG("buffer wrapped, freeing some memory");
        kfree(ret_buf);
    }

    return retval;

copy_err:
    kfree(buffer);
exit:
    return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err < 0) {
        PDEBUG("ERROR: can't add char device - errno: %d", err);
    } else {
        PDEBUG("device added");
    }

    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;

    PDEBUG("init module");

    /* Allocate major */
    result = alloc_chrdev_region(&dev, aesd_minor, 1,"aesdchar");
    if (result < 0) {
        PDEBUG("ERROR: can't get major number - errno: %d", result);
        return result;
    } else {
        PDEBUG("major allocated: %d", aesd_major);
        aesd_major = MAJOR(dev);
    }

    /* Initialize dev structure */
    aesd_device = kmalloc(sizeof(struct aesd_dev), GFP_KERNEL);
    if (!aesd_device) {
        PDEBUG("ERRROR: can't allocate memory for aesd device struct");
        result = -ENOMEM;
        goto alloc_err;
    } else {
        PDEBUG("aesd_device struct kmalloc success");
    }
    memset(aesd_device,0,sizeof(struct aesd_dev));
    // mutex_init

    /* Device setup */
    result = aesd_setup_cdev(aesd_device);
    if (result < 0) {
        PDEBUG("ERROR: setup failed");
        goto setup_err;
    }

    PDEBUG("init compelte");
    return 0;

setup_err:
    kfree(aesd_device);
alloc_err:
    unregister_chrdev_region(dev, 1);
    PDEBUG("ERROR: init failed");
    return result;
}

static void cleanup_buffer(void)
{
    int idx;

    for (int i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++) {
        idx = (aesd_device->buffer.out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

        if (aesd_device->buffer.entry[idx].buffptr)
            kfree(aesd_device->buffer.entry[idx].buffptr);
    }
}

void aesd_cleanup_module(void)
{
    dev_t devno;

    devno = MKDEV(aesd_major, aesd_minor);
    cdev_del(&aesd_device->cdev);

    cleanup_buffer();

    // mutex_destroy

    kfree(aesd_device);

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
