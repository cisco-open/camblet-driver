#include <linux/uaccess.h>

#include "base64.h"
#include "device_driver.h"
#include "json.h"
#include "runtime.h"

/* Global variables are declared as static, so are global within the file. */

static int major; /* major number assigned to our device driver */

enum
{
    CDEV_NOT_USED = 0,
    CDEV_EXCLUSIVE_OPEN = 1,
};

/* Is device open? Used to prevent multiple access to device */
static atomic_t already_open = ATOMIC_INIT(CDEV_NOT_USED);

static char device_buffer[DEVICE_BUFFER_SIZE];
static unsigned int device_buffer_size = 0;

static struct class *cls;

static struct file_operations chardev_fops = {
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release,
};

int chardev_init(void)
{
    major = register_chrdev(0, DEVICE_NAME, &chardev_fops);

    if (major < 0)
    {
        pr_alert("wasm3: Registering char device failed with %d\n", major);
        return major;
    }

    pr_info("wasm3: I was assigned major number %d.\n", major);

    cls = class_create(THIS_MODULE, DEVICE_NAME);
    device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

    pr_info("wasm3: Device created on /dev/%s\n", DEVICE_NAME);

    return SUCCESS;
}

void chardev_exit(void)
{
    device_destroy(cls, MKDEV(major, 0));
    class_destroy(cls);

    /* Unregister the device */
    unregister_chrdev(major, DEVICE_NAME);
}

/* Methods */

/* Called when a process tries to open the device file, like
 * "sudo cat /dev/chardev"
 */
static int device_open(struct inode *inode, struct file *file)
{
    if (atomic_cmpxchg(&already_open, CDEV_NOT_USED, CDEV_EXCLUSIVE_OPEN))
        return -EBUSY;

    try_module_get(THIS_MODULE);

    return SUCCESS;
}

static wasm_vm_result reset_vms(void)
{
    wasm_vm_result result;
    result = wasm_vm_destroy_per_cpu();
    if (result.err)
    {
        FATAL("wasm_vm_destroy_per_cpu: %s", result.err);
        return result;
    }

    result = wasm_vm_new_per_cpu();
    if (result.err)
    {
        FATAL("wasm_vm_new_per_cpu: %s", result.err);
        return result;
    }

    return result;
}

static wasm_vm_result load_module(char *name, char *code, unsigned length, char *entrypoint)
{
    wasm_vm_result result;
    unsigned cpu;
    for_each_possible_cpu(cpu)
    {
        wasm_vm *vm = wasm_vm_for_cpu(cpu);
        wasm_vm_lock(vm);

        result = wasm_vm_load_module(vm, name, code, length);
        if (result.err)
        {
            FATAL("wasm_vm_load_module: %s", result.err);
            wasm_vm_unlock(vm);
            return result;
        }

        if (entrypoint)
        {
            printk("wasm3: calling module entrypoint: %s", entrypoint);

            result = wasm_vm_call(vm, entrypoint);
            if (result.err)
            {
                FATAL("wasm_vm_call: %s", result.err);
                wasm_vm_unlock(vm);
                return result;
            }
        }

        wasm_vm_unlock(vm);
        wasm_vm_dump_symbols(vm);
    }

    return result;
}

/* Called when a process closes the device file. */
static int device_release(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "wasm3: device has been released\n");

    int status = SUCCESS;
    JSON_Value *json = NULL;

    if (device_buffer_size)
    {
        json = json_parse_string(device_buffer);
        JSON_Object *root = json_value_get_object(json);
        char *command = json_object_get_string(root, "command");

        printk("wasm3: command %s\n", command);

        if (strcmp("load", command) == 0)
        {
            char *name = json_object_get_string(root, "name");
            printk("wasm3: loading module: %s\n", name);

            char *code = json_object_get_string(root, "code");
            int length = base64_decode(device_buffer, DEVICE_BUFFER_SIZE, code, strlen(code));
            if (length < 0)
            {
                FATAL("base64_decode failed");
                status = -1;
                goto cleanup;
            }

            char *entrypoint = json_object_get_string(root, "entrypoint");

            wasm_vm_result result = load_module(name, device_buffer, length, entrypoint);
            if (result.err)
            {
                FATAL("load_module: %s", result.err);
                status = -1;
                goto cleanup;
            }
        }
        else if (strcmp("reset", command) == 0)
        {
            printk("wasm3: reseting vm");

            wasm_vm_result result = reset_vms();
            if (result.err)
            {
                FATAL("reset_vms: %s", result.err);
                status = -1;
                goto cleanup;
            }
        }
        else
        {
            printk("wasm3: command not implemented: %s", command);
            status = -1;
            goto cleanup;
        }
    }

cleanup:
    if (json)
    {
        json_value_free(json);
    }

    device_buffer_size = 0;

    /* We're now ready for our next caller */
    atomic_set(&already_open, CDEV_NOT_USED);

    /* Decrement the usage count, or else once you opened the file, you will
     * never get rid of the module.
     */
    module_put(THIS_MODULE);

    return status;
}

/* Called when a process, which already opened the dev file, attempts to
 * read from it.
 */
static ssize_t device_read(struct file *file,   /* see include/linux/fs.h   */
                           char __user *buffer, /* buffer to fill with data */
                           size_t length,       /* length of the buffer     */
                           loff_t *offset)
{
    /* Number of bytes actually written to the buffer */
    int bytes_read = 0;
    const char *msg_ptr = device_buffer;

    printk("wasm3: device_read: length: %lu offset: %llu", length, *offset);

    if (!*(msg_ptr + *offset))
    {                /* we are at the end of message */
        *offset = 0; /* reset the offset */
        return 0;    /* signify end of file */
    }

    msg_ptr += *offset;

    /* Actually put the data into the buffer */
    while (length && *msg_ptr)
    {
        /* The buffer is in the user data segment, not the kernel
         * segment so "*" assignment won't work.  We have to use
         * put_user which copies data from the kernel data segment to
         * the user data segment.
         */
        put_user(*(msg_ptr++), buffer++);
        length--;
        bytes_read++;
    }

    *offset += bytes_read;

    /* Most read functions return the number of bytes put into the buffer. */
    return bytes_read;
}

/* called when somebody tries to write into our device file. */
static ssize_t device_write(struct file *file, const char *buffer, size_t length, loff_t *offset)
{
    int maxbytes;       /* maximum bytes that can be read from offset to DEVICE_BUFFER_SIZE*/
    int bytes_to_write; /* gives the number of bytes to write*/
    int bytes_writen;   /* number of bytes actually writen*/
    maxbytes = DEVICE_BUFFER_SIZE - *offset;
    if (maxbytes > length)
        bytes_to_write = length;
    else
        bytes_to_write = maxbytes;

    bytes_writen = bytes_to_write - copy_from_user(device_buffer + *offset, buffer, bytes_to_write);
    printk(KERN_INFO "wasm3: device has been written %d\n", bytes_writen);
    *offset += bytes_writen;
    device_buffer_size = *offset;
    return bytes_writen;
}
