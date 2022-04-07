#ifndef device_driver_h
#define device_driver_h

#include <linux/device.h>
#include <linux/fs.h>

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char __user *, size_t,
                            loff_t *);

#define SUCCESS 0
#define DEVICE_NAME "wasm3"                /* Dev name as it appears in /proc/devices   */
#define DEVICE_BUFFER_SIZE 2 * 1024 * 1024 /* Max length of the message from the device */

int chardev_init(void);
void chardev_exit(void);

#endif
