/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include <linux/uaccess.h>
#include <linux/delay.h>

#include "base64.h"
#include "device_driver.h"
#include "json.h"
#include "opa.h"
#include "proxywasm.h"
#include "runtime.h"

/* Global variables are declared as static, so are global within the file. */

#define DEFAULT_MODULE_ENTRYPOINT "main"

static int major; /* major number assigned to our device driver */

enum
{
    CDEV_NOT_USED = 0,
    CDEV_EXCLUSIVE_OPEN = 1,
};

/* Is device open? Used to prevent multiple access to device */
static atomic_t already_open = ATOMIC_INIT(CDEV_NOT_USED);

// create a linked list for outgoing commands
typedef struct command
{
    struct list_head list;
    char *data;
    size_t size;
};

// protect the command list with a mutex
static DEFINE_SPINLOCK(command_list_lock);
static unsigned long command_list_lock_flags;
static LIST_HEAD(command_list);

// create a function to add a command to the list (called from the VM), locked with a spinlock
void add_command(char *data, size_t size)
{
    struct command *cmd = kmalloc(sizeof(struct command), GFP_KERNEL);
    cmd->data = kmalloc(size, GFP_KERNEL);
    memcpy(cmd->data, data, size);
    cmd->size = size;

    spin_lock_irqsave(&command_list_lock, command_list_lock_flags);
    list_add_tail(&cmd->list, &command_list);
    spin_unlock_irqrestore(&command_list_lock, command_list_lock_flags);
}

// create a function to get a command from the list (called from the driver), locked with a mutex
static struct command *get_command(void)
{
    struct command *cmd = NULL;

    spin_lock_irqsave(&command_list_lock, command_list_lock_flags);
    if (!list_empty(&command_list))
    {
        cmd = list_first_entry(&command_list, struct command, list);
        list_del(&cmd->list);
    }
    spin_unlock_irqrestore(&command_list_lock, command_list_lock_flags);

    return cmd;
}

static char device_buffer[DEVICE_BUFFER_SIZE];
static size_t device_buffer_size = 0;

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
        pr_alert("wasm: Registering char device failed with %d", major);
        return major;
    }

    pr_info("wasm: I was assigned major number %d.", major);

    cls = class_create(THIS_MODULE, DEVICE_NAME);
    device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

    pr_info("wasm: Device created on /dev/%s", DEVICE_NAME);

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

        wasm_vm_module *module = result.data->module;

        if (entrypoint)
        {
            printk("wasm: calling module entrypoint: %s", entrypoint);

            result = wasm_vm_call(vm, name, entrypoint);
            // if we can't find the implicit main entrypoint, that is not an issue
            if (result.err &&
                !(result.err == m3Err_functionLookupFailed && strcmp(entrypoint, DEFAULT_MODULE_ENTRYPOINT) == 0))
            {
                FATAL("wasm_vm_call: %s error: %s", result.err, wasm_vm_last_error(vm));
                wasm_vm_unlock(vm);
                return result;
            }

            printk("wasm: module entrypoint finished");

            result.err = NULL;
        }

        if (strcmp(name, OPA_MODULE) == 0)
        {
            result = init_opa_for(vm, module);
            if (result.err)
            {
                FATAL("init_opa_for: %s", result.err);
                wasm_vm_unlock(vm);
                return result;
            }
        }
        else if (strstr(name, "proxywasm") != NULL)
        {
            result = init_proxywasm_for(vm, module);
            if (result.err)
            {
                FATAL("init_proxywasm_for: %s", result.err);
                wasm_vm_unlock(vm);
                return result;
            }
        }

        wasm_vm_unlock(vm);
        wasm_vm_dump_symbols(vm);
    }

    return result;
}

int parse_json_from_buffer(void)
{
    int status = SUCCESS;
    JSON_Value *json = NULL;

    if (device_buffer_size)
    {
        json = json_parse_string(device_buffer);
        JSON_Object *root = json_value_get_object(json);
        char *command = json_object_get_string(root, "command");

        printk("wasm: command %s", command);

        if (strcmp("load", command) == 0)
        {
            char *name = json_object_get_string(root, "name");
            printk("wasm: loading module: %s", name);

            char *code = json_object_get_string(root, "code");
            int length = base64_decode(device_buffer, DEVICE_BUFFER_SIZE, code, strlen(code));
            if (length < 0)
            {
                FATAL("base64_decode failed");
                status = -1;
                goto cleanup;
            }

            char *entrypoint = json_object_get_string(root, "entrypoint");
            if (entrypoint == NULL)
            {
                printk("wasm: setting default module entrypoint \"%s\"", DEFAULT_MODULE_ENTRYPOINT);
                entrypoint = DEFAULT_MODULE_ENTRYPOINT;
            }

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
            printk("wasm: reseting vm");

            wasm_vm_result result = reset_vms();
            if (result.err)
            {
                FATAL("reset_vms: %s", result.err);
                status = -1;
                goto cleanup;
            }
        }
        else if (strcmp("proxywasm_test", command) == 0)
        {
            // TODO test only
            // Create a new non-root context
            proxywasm *proxywasm = this_cpu_proxywasm();

            wasm_vm_result result = proxywasm_create_context(proxywasm);
            if (result.err)
            {
                FATAL("proxywasm_create_context for module failed: %s", result.err)
                goto cleanup;
            }

            printk("wasm: proxy_on_context_create result %d", result.data->i32);

            result = proxy_on_new_connection(proxywasm);
            if (result.err)
            {
                FATAL("proxy_on_new_connection for module failed: %s", result.err)
                goto cleanup;
            }

            printk("wasm: proxy_on_new_connection result %d", result.data->i32);

            result = proxy_on_downstream_data(proxywasm, 128, false);
            if (result.err)
            {
                FATAL("proxy_on_downstream_data for module failed: %s", result.err)
                goto cleanup;
            }
        }
        else
        {
            printk(KERN_ERR "wasm: command not implemented: %s", command);
            status = -1;
            goto cleanup;
        }
    }

cleanup:
    if (json)
    {
        json_value_free(json);
    }

    return status;
}

/* Called when a process closes the device file. */
static int device_release(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "wasm: device has been released");

    device_buffer_size = 0;

    /* We're now ready for our next caller */
    atomic_set(&already_open, CDEV_NOT_USED);

    /* Decrement the usage count, or else once you opened the file, you will
     * never get rid of the module.
     */
    module_put(THIS_MODULE);

    return 0;
}

/*
 * Called when a process, which already opened the dev file, attempts to
 * read from it.
 */
static ssize_t device_read(struct file *file,   /* see include/linux/fs.h   */
                           char __user *buffer, /* buffer to fill with data */
                           size_t length,       /* length of the buffer     */
                           loff_t *offset)
{
    printk("wasm: device_read: length: %lu offset: %llu", length, *offset);

    struct command *c = get_command();
    // wait until command is available
    while (c == NULL)
    {
        if (msleep_interruptible(1000) > 0)
        {
            return -EINTR;
        }
        c = get_command();
    }

    // copy the command to the buffer
    int bytes_read = 0;
    int bytes_to_read = c->size; //min(length, c->size - *offset);
    if (bytes_to_read > 0)
    {
        // if (copy_to_user(buffer, c->data + *offset, bytes_to_read))
        if (copy_to_user(buffer, c->data, bytes_to_read))
        {
            return -EFAULT;
        }

        put_user('\n', buffer + bytes_to_read);

        bytes_read = bytes_to_read + 1;
        // *offset += bytes_to_read;
    }

    // if (*offset >= c->size)
    {
        // free the command
        kfree(c->data);
        kfree(c);
    }

    return bytes_read;
}

/* called when somebody tries to write into our device file. */
static ssize_t device_write(struct file *file, const char *buffer, size_t length, loff_t *offset)
{
    int maxbytes;       /* maximum bytes that can be read from offset to DEVICE_BUFFER_SIZE */
    int bytes_to_write; /* gives the number of bytes to write */
    int bytes_writen;   /* number of bytes actually written */
    maxbytes = DEVICE_BUFFER_SIZE - *offset;
    if (maxbytes > length)
        bytes_to_write = length;
    else
        bytes_to_write = maxbytes;

    bytes_writen = bytes_to_write - copy_from_user(device_buffer + *offset, buffer, bytes_to_write);
    printk(KERN_INFO "wasm: device has been written %d", bytes_writen);
    *offset += bytes_writen;
    device_buffer_size = *offset;

    // search for the end of the string in device_buffer
    for (;;)
    {
        int i = 0;
        for (; i < device_buffer_size; i++)
        {
            if (device_buffer[i] == '\0')
            {
                break;
            }
        }

        if (i == device_buffer_size)
        {
            // no end of string found, we need to read more
            return bytes_writen;
        }

        // parse the json
        int status = parse_json_from_buffer();

        printk("parsed json: %d", status);

        // shift back device_buffer by length of the string parsed
        printk("shifting back: %d", i + 1);

        memmove(device_buffer, device_buffer + i, device_buffer_size - i);
        device_buffer_size -= i + 1;

        printk("device_buffer_size: %lu", device_buffer_size);
    }

    return bytes_writen;
}
