/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/kernel.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"


#undef PDEBUG             /* undef it, just in case */
#ifdef __KERNEL__
     /* This one if debugging is on, and kernel space */
#define PDEBUG(fmt, args...) printk( KERN_DEBUG "aesdchar: " fmt, ## args)
#else
     /* This one for user space */
#define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
#endif

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    int rd_idx;

    PDEBUG("\tlooking for offset: %ld", char_offset);
    for (int i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++) {
        rd_idx = (buffer->out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        PDEBUG("\trd_idx = %d", rd_idx);

        if (buffer->entry[rd_idx].buffptr == NULL) {
            PDEBUG("\tbuffptr is null");
            break; //continue?
        }

        PDEBUG("\tentry[%d].size: %ld", rd_idx, buffer->entry[rd_idx].size);
        PDEBUG("\tdifference wrt offset is: %d", (int)(char_offset - buffer->entry[rd_idx].size));
        if ((int)(char_offset - buffer->entry[rd_idx].size) < 0) {
            PDEBUG("\tentry found: %d", rd_idx);
            *entry_offset_byte_rtn = char_offset;
            return &(buffer->entry[rd_idx]);
        } else {
            PDEBUG("\tnew iteration");
            char_offset = char_offset - (buffer->entry[rd_idx]).size;
        }
    }

    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
const char *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    const char *ret = NULL;

    if (!buffer->full) {
        (buffer->entry[buffer->in_offs]).buffptr = add_entry->buffptr;
        (buffer->entry[buffer->in_offs]).size = add_entry->size;

        buffer->in_offs++;
        if (buffer->in_offs == AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {
            buffer->in_offs = 0;
            buffer->full = true;
        }
    } else {
        ret = buffer->entry[buffer->out_offs].buffptr;
        (buffer->entry[buffer->out_offs]).buffptr = add_entry->buffptr;
        (buffer->entry[buffer->out_offs]).size = add_entry->size;

        buffer->out_offs++;
        if (buffer->out_offs == AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
            buffer->out_offs = 0;
        buffer->in_offs = buffer->out_offs;
    }

    return ret;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
