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
#include <linux/version.h>
#include <linux/wait.h>

#include "base64.h"
#include "device_driver.h"
#include "json.h"
#include "opa.h"
#include "proxywasm.h"
#include "csr.h"
#include "wasm.h"
#include "commands.h"

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

static char device_buffer[DEVICE_BUFFER_SIZE];
static size_t device_buffer_size = 0;

static char device_out_buffer[64 * 1024];

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char __user *, size_t, loff_t *);

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
        pr_alert("nasp: Registering char device failed with %d", major);
        return major;
    }

    pr_info("nasp: I was assigned major number %d.", major);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
    cls = class_create(THIS_MODULE, DEVICE_NAME);
#else
    cls = class_create(DEVICE_NAME);
#endif

    device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

    pr_info("nasp: Device created on /dev/%s", DEVICE_NAME);

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
 * "sudo cat /dev/nasp"
 */
static int device_open(struct inode *inode, struct file *file)
{
    if (atomic_cmpxchg(&already_open, CDEV_NOT_USED, CDEV_EXCLUSIVE_OPEN))
        return -EBUSY;

    try_module_get(THIS_MODULE);

    printk("nasp: [%s] opened the communication device", current->comm);

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

wasm_vm_result load_module(char *name, char *code, unsigned length, char *entrypoint)
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
            printk("nasp: calling module entrypoint: %s", entrypoint);

            result = wasm_vm_call(vm, name, entrypoint);
            // if we can't find the implicit main entrypoint, that is not an issue
            if (result.err &&
                !(result.err == m3Err_functionLookupFailed && strcmp(entrypoint, DEFAULT_MODULE_ENTRYPOINT) == 0))
            {
                FATAL("wasm_vm_call: %s error: %s", result.err, wasm_vm_last_error(module));
                wasm_vm_unlock(vm);
                return result;
            }

            printk("nasp: module entrypoint finished");

            result.err = NULL;
        }

        if (strstr(name, OPA_MODULE) != NULL)
        {
            printk("nasp: initializing opa for %s", name);
            result = init_opa_for(vm, module);
            if (result.err)
            {
                FATAL("init_opa_for: %s", result.err);
                wasm_vm_unlock(vm);
                return result;
            }
        }
        else if (strstr(name, PROXY_WASM) != NULL)
        {
            printk("nasp: initializing proxywasm for %s", name);
            result = init_proxywasm_for(vm, module);
            if (result.err)
            {
                FATAL("init_proxywasm_for: %s", result.err);
                wasm_vm_unlock(vm);
                return result;
            }
        }
        else if (strstr(name, CSR_MODULE) != NULL)
        {
            printk("nasp: initializing csr module for %s", name);
            result = init_csr_for(vm, module);
            if (result.err)
            {
                FATAL("init_csr_for: %s", result.err);
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

        printk("nasp: command %s", command);

        if (strcmp("load", command) == 0)
        {
            char *name = json_object_get_string(root, "name");
            printk("nasp: loading module: %s", name);

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
                printk("nasp: setting default module entrypoint \"%s\"", DEFAULT_MODULE_ENTRYPOINT);
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
            printk("nasp: reseting vm");

            wasm_vm_result result = reset_vms();
            if (result.err)
            {
                FATAL("reset_vms: %s", result.err);
                status = -1;
                goto cleanup;
            }
        }
        else if (strcmp("answer", command) == 0)
        {
            char *base64_id = json_object_get_string(root, "id");

            printk("nasp: command answer parsing, id: %s", base64_id);

            char command_id[UUID_SIZE * 2];
            int length = base64_decode(command_id, UUID_SIZE * 2, base64_id, strlen(base64_id));
            if (length < 0)
            {
                FATAL("base64_decode of id failed");
                status = -1;
                goto cleanup;
            }

            struct command *cmd = lookup_in_flight_command(command_id);

            if (cmd == NULL)
            {
                printk(KERN_ERR "nasp: command %d not found", command_id);
                status = -1;
                goto cleanup;
            }

            struct command_answer *cmd_answer = kmalloc(sizeof(struct command_answer), GFP_KERNEL);
            char *answer = json_object_get_string(root, "answer");
            char *error = json_object_get_string(root, "error");

            if (error)
            {
                cmd_answer->error = kmalloc(strlen(error) + 1, GFP_KERNEL);
                strcpy(cmd_answer->error, error);
            }
            else
            {
                cmd_answer->error = NULL;
            }

            if (answer)
            {
                cmd_answer->answer = kmalloc(strlen(answer) + 1, GFP_KERNEL);
                strcpy(cmd_answer->answer, answer);
            }
            else
            {
                cmd_answer->answer = NULL;
            }

            cmd->answer = cmd_answer;

            wake_up_interruptible(&cmd->wait_queue);
        }
        else
        {
            printk(KERN_ERR "nasp: command not implemented: %s", command);
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
    printk(KERN_INFO "nasp: [%s] closed the communcation device", current->comm);

    device_buffer_size = 0;

    /* We're now ready for our next caller */
    atomic_set(&already_open, CDEV_NOT_USED);

    /* Decrement the usage count, or else once you opened the file, you will
     * never get rid of the module.
     */
    module_put(THIS_MODULE);

    return 0;
}

static int write_command_to_buffer(char *buffer, size_t buffer_size, struct command *cmd)
{
    char uuid[UUID_SIZE * 2];
    int length = base64_encode(uuid, UUID_SIZE * 2, cmd->uuid.b, UUID_SIZE);
    if (length < 0)
    {
        FATAL("base64_encode of id failed");
        goto cleanup;
    }

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    if (cmd->context)
    {
        JSON_Value *context_value = json_value_init_object();
        JSON_Object *context_object = json_value_get_object(context_value);
        json_object_set_number(context_object, "uid", cmd->context->uid.val);
        json_object_set_number(context_object, "gid", cmd->context->gid.val);
        json_object_set_string(context_object, "command_path", cmd->context->command_path);
        json_object_set_string(context_object, "command_name", cmd->context->command_name);
        json_object_set_value(root_object, "context", context_value);
    }

    json_object_set_string(root_object, "id", uuid);
    json_object_set_string(root_object, "command", cmd->name);
    json_object_set_string(root_object, "data", cmd->data);

    char *serialized_string = json_serialize_to_string(root_value);

    length = strlen(serialized_string);
    if (length > buffer_size)
    {
        printk(KERN_ERR "nasp: command buffer too small: %d", length);
        length = -1;
        goto cleanup;
    }

    strcpy(buffer, serialized_string);

cleanup:
    json_free_serialized_string(serialized_string);
    json_value_free(root_value);

    return length;
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
    printk("nasp: device_read: length: %lu offset: %llu", length, *offset);

    struct command *c = get_command();
    // wait until command is available
    while (c == NULL)
    {
        if (msleep_interruptible(25) > 0)
        {
            return -EINTR;
        }
        c = get_command();
    }

    int json_length = write_command_to_buffer(device_out_buffer, sizeof device_out_buffer, c);
    if (json_length < 0)
    {
        return -EFAULT;
    }

    printk("nasp: the command json is done: %s", device_out_buffer);

    int bytes_read = 0;
    int bytes_to_read = json_length; // min(length, c->size - *offset);
    if (bytes_to_read > 0)
    {
        // if (copy_to_user(buffer, c->data + *offset, bytes_to_read))
        if (copy_to_user(buffer, device_out_buffer, bytes_to_read))
        {
            return -EFAULT;
        }

        put_user('\n', buffer + bytes_to_read);

        bytes_read = bytes_to_read + 1;
        // *offset += bytes_to_read;
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

    bytes_writen = bytes_to_write - copy_from_user(device_buffer + device_buffer_size, buffer, bytes_to_write);
    printk(KERN_INFO "nasp: device has been written %d", bytes_writen);
    *offset += bytes_writen;
    device_buffer_size += bytes_writen;

    // search for the end of the string in device_buffer
    for (;;)
    {
        int i = 0;
        for (; i < device_buffer_size; i++)
        {
            if (device_buffer[i] == '\n')
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
        if (status != 0)
        {
            printk(KERN_ERR "nasp: parse_json_from_buffer failed: %d", status);
            return -1;
        }

        memmove(device_buffer, device_buffer + i, device_buffer_size - i);
        device_buffer_size -= i + 1;
    }

    return bytes_writen;
}
