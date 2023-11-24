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
    struct aesd_dev *dev;

    /* Find the device */
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);

    /* Initialize file pointer */
    filp->private_data = dev;

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    bool read_again = true;
    ssize_t how_many = 0;
    ssize_t offset = 0;
    ssize_t read = 0;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    while (read_again) {
        entry = aesd_circular_buffer_find_entry_offset_for_fpos(&(dev->buffer), *f_pos, &offset);
        if (!entry)
            goto exit;

        if ((int)((count - (read + entry->size))) > 0) {
            how_many = entry->size;
        } else {
            how_many = (size_t)(count - read);
            read_again = false;
            if ((how_many + offset) > entry->size)
                how_many -= ((how_many + offset) - entry->size);
        }

        if (copy_to_user((buf + read), (entry->buffptr + offset), how_many))
                goto exit;

        read += how_many;
        *f_pos += how_many;
    }

exit:
    mutex_unlock(&dev->lock);
    return read;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{

    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry new_entry;
    ssize_t retval = count;
    const char *ret_buf;
    char *tmp_buf;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    tmp_buf = krealloc(dev->write_buffer.buffptr, (dev->write_buffer.size + count) * sizeof(char), GFP_KERNEL);
    if (!tmp_buf) {
        retval = -ENOMEM;
        goto exit;
    }

    if (copy_from_user(tmp_buf + dev->write_buffer.size, buf, count)) {
        retval = -EFAULT;
        goto err;
    }

    dev->write_buffer.buffptr = tmp_buf;
    dev->write_buffer.size += count;

    if (dev->write_buffer.buffptr[dev->write_buffer.size - 1] == '\n') {
        size_t alloc;
        char *tmp;

        alloc = (dev->write_buffer.size * sizeof(char)) + 1; /* +1 for '\0' */
        tmp = kmalloc(alloc, GFP_KERNEL);
        if (!tmp) {
            retval = -ENOMEM;
            goto err;
        }
        memset(tmp, 0, alloc);

        strncpy(tmp, dev->write_buffer.buffptr, dev->write_buffer.size);
        new_entry.buffptr = tmp;
        new_entry.size = dev->write_buffer.size;

        ret_buf = aesd_circular_buffer_add_entry(&(dev->buffer), &(new_entry));
        if (ret_buf)
            kfree(ret_buf);

        kfree(dev->write_buffer.buffptr);
        dev->write_buffer.buffptr = NULL;
        dev->write_buffer.size = 0;
    }

    *f_pos += count;
    mutex_unlock(&dev->lock);
    return retval;

err:
    kfree(dev->write_buffer.buffptr);
exit:
    mutex_unlock(&dev->lock);
    return retval;
}

loff_t aessd_llseek(struct file *filp, loff_t off, int whence)
{
    struct aesd_dev *dev = filp->private_data;
    loff_t new_pos;

    switch (whence) {
    case SEEK_SET:
        new_pos = off;
        break;
    case SEEK_CUR:
        new_pos = filp->f_pos + off;
        break;
    case SEEK_END:
        size_t total = 0;
        for (int i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++) {
            int idx = (i + dev->buffer.out_offs) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
            if (dev->buffer.entry[idx].buffptr)
                total += dev->buffer.entry[idx].size;
        }
        new_pos = total + off;
        break;
    default:
        return -EINVAL;
    }

    if (new_pos < 0)
        return -EINVAL;

    filp->f_pos = new_pos;

    return new_pos;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek = aessd_llseek,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err < 0)
        PDEBUG("ERROR: can't add char device - errno: %d", err);

    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;

    /* Allocate major */
    result = alloc_chrdev_region(&dev, aesd_minor, 1,"aesdchar");
    if (result < 0) {
        PDEBUG("ERROR: can't get major number - errno: %d", result);
        return result;
    } else {
        aesd_major = MAJOR(dev);
    }

    /* Initialize dev structure */
    aesd_device = kmalloc(sizeof(struct aesd_dev), GFP_KERNEL);
    if (!aesd_device) {
        PDEBUG("ERRROR: can't allocate memory for aesd device struct");
        result = -ENOMEM;
        goto alloc_err;
    }

    memset(aesd_device,0,sizeof(struct aesd_dev));
    aesd_device->write_buffer.buffptr = NULL;
    aesd_device->write_buffer.size = 0;
    mutex_init(&aesd_device->lock);

    /* Device setup */
    result = aesd_setup_cdev(aesd_device);
    if (result < 0)
        goto setup_err;

    return 0;

setup_err:
    mutex_destroy(&aesd_device->lock);
    kfree(aesd_device);
alloc_err:
    unregister_chrdev_region(dev, 1);
    PDEBUG("ERROR: init failed");
    return result;
}

static void cleanup_buffer(void)
{
    for (int i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++) {
        if (aesd_device->buffer.entry[i].buffptr)
            kfree(aesd_device->buffer.entry[i].buffptr);
    }
}

void aesd_cleanup_module(void)
{
    dev_t devno;

    devno = MKDEV(aesd_major, aesd_minor);
    cdev_del(&aesd_device->cdev);

    cleanup_buffer();

    if (aesd_device->write_buffer.buffptr)
        kfree(aesd_device->write_buffer.buffptr);

    mutex_destroy(&aesd_device->lock);

    kfree(aesd_device);

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
