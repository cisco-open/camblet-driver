/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#define pr_fmt(fmt) "%s: " fmt, KBUILD_MODNAME

#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <linux/uuid.h>

#include "base64.h"
#include "device_driver.h"
#include "json.h"
#include "opa.h"
#include "proxywasm.h"
#include "csr.h"
#include "wasm.h"
#include "commands.h"
#include "string.h"
#include "config.h"
#include "sd.h"
#include "trace.h"

/* Global variables are declared as static, so are global within the file. */

#define DEFAULT_MODULE_ENTRYPOINT "main"

static int major; /* major number assigned to our device driver */

/* Is device open? Used to prevent multiple access to device */
atomic_t already_open = ATOMIC_INIT(CDEV_NOT_USED);

static char device_buffer[DEVICE_BUFFER_SIZE];
static size_t device_buffer_size = 0;

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
        pr_alert("could not register char device # err[%d]", major);
        return major;
    }

    pr_info("char device registered # major[%d]", major);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
    cls = class_create(THIS_MODULE, DEVICE_NAME);
#else
    cls = class_create(DEVICE_NAME);
#endif

    device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

    pr_info("device created # device[/dev/%s]", DEVICE_NAME);

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
 * "sudo cat /dev/camblet"
 */
static int device_open(struct inode *inode, struct file *file)
{
    if (atomic_cmpxchg(&already_open, CDEV_NOT_USED, CDEV_EXCLUSIVE_OPEN))
        return -EBUSY;

    try_module_get(THIS_MODULE);

    pr_info("communication device opened # command[%s]", current->comm);

    return SUCCESS;
}

static wasm_vm_result reset_vms(void)
{
    wasm_vm_result result;
    result = wasm_vm_destroy_per_cpu();
    if (result.err)
    {
        pr_crit("could not destroy wasm vm # err[%s]", result.err);
        return result;
    }

    result = wasm_vm_new_per_cpu();
    if (result.err)
    {
        pr_crit("could not create wasm vm # err[%s]", result.err);
        return result;
    }

    return result;
}

wasm_vm_result load_module(const char *name, const char *code, unsigned length, const char *entrypoint)
{
    wasm_vm_result result;
    unsigned cpu;
    for_each_online_cpu(cpu)
    {
        wasm_vm *vm = wasm_vm_for_cpu(cpu);
        wasm_vm_lock(vm);

        result = wasm_vm_load_module(vm, name, code, length);
        if (result.err)
        {
            pr_crit("could not load wasm module # err[%s]", result.err);
            wasm_vm_unlock(vm);
            return result;
        }

        wasm_vm_module *module = result.data->module;

        if (entrypoint)
        {
            pr_debug("call module entrypoint # entrypoint[%s]", entrypoint);

            result = wasm_vm_call(vm, name, entrypoint);
            // if we can't find the implicit main entrypoint, that is not an issue
            if (result.err &&
                !(result.err == m3Err_functionLookupFailed && strcmp(entrypoint, DEFAULT_MODULE_ENTRYPOINT) == 0))
            {
                pr_crit("wasm vm call failed # err[%s] wasm_last_error[%s]", result.err, wasm_vm_last_error(module));
                wasm_vm_unlock(vm);
                return result;
            }

            pr_debug("module entrypoint finished # entrypoint[%s]", entrypoint);

            result.err = NULL;
        }

        if (strstr(name, OPA_MODULE) != NULL)
        {
            pr_info("initializing opa # name[%s]", name);
            result = init_opa_for(vm, module);
            if (result.err)
            {
                pr_crit("could not init opa module # err[%s: %s]", result.err, wasm_vm_last_error(module));
                wasm_vm_unlock(vm);
                return result;
            }
        }
        else if (strstr(name, PROXY_WASM) != NULL)
        {
            pr_info("initializing proxywasm # name[%s]", name);
            result = init_proxywasm_for(vm, module);
            if (result.err)
            {
                pr_crit("could not init proxywasm module # err[%s: %s]", result.err, wasm_vm_last_error(module));
                wasm_vm_unlock(vm);
                return result;
            }
        }
        else if (strstr(name, CSR_MODULE) != NULL)
        {
            pr_info("initializing csr module # name[%s]", name);
            result = init_csr_for(vm, module);
            if (result.err)
            {
                pr_crit("could not init csr module # err[%s]", result.err);
                wasm_vm_unlock(vm);
                return result;
            }
        }

        wasm_vm_unlock(vm);
        wasm_vm_dump_symbols(vm);
    }

    return result;
}

static int load_sd_info(const char *data)
{
    int retval = 0;
    JSON_Value *json;

    if (!data)
    {
        retval = -EINVAL;
        goto ret;
    }

    pr_info("load service discovery info # data[%s]", data);

    json = json_parse_string(data);
    if (json == NULL)
    {
        pr_err("could not load sd info: invalid json");
        retval = -EINVAL;
        goto ret;
    }

    JSON_Object *root = json_value_get_object(json);
    if (root == NULL)
    {
        pr_err("could not load sd info: invalid json root");
        retval = -EINVAL;
        goto ret;
    }

    service_discovery_table *table = service_discovery_table_create();
    if (IS_ERR(table))
    {
        retval = PTR_ERR(table);
        goto ret;
    }
    service_discovery_entry *entry;

    size_t i, k;
    for (i = 0; i < json_object_get_count(root); i++)
    {
        const char *name = json_object_get_name(root, i);
        if (!name)
        {
            pr_err("could not load sd info: record[%d]: could not get object name", i);
            retval = -EINVAL;
            goto ret;
        }
        JSON_Object *json_entry = json_object_get_object(root, name);
        if (!json_entry)
        {
            pr_err("could not load sd info: record[%d]: could not get object", i);
            retval = -EINVAL;
            goto ret;
        }
        JSON_Array *labels = json_object_get_array(json_entry, "labels");
        if (!labels)
        {
            pr_err("could not load sd info: record[%d]: could not get labels", i);
            retval = -EINVAL;
            goto ret;
        }

        entry = kzalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry)
        {
            retval = -ENOMEM;
            goto ret;
        }
        entry->address = kstrdup(name, GFP_KERNEL);
        if (!entry->address)
        {
            service_discovery_entry_free(entry);
            retval = -ENOMEM;
            goto ret;
        }

        pr_debug("create sd entry # address[%s]", entry->address);

        entry->labels_len = json_array_get_count(labels);
        entry->labels = kmalloc(entry->labels_len * sizeof(char *), GFP_KERNEL);
        if (!entry->labels)
        {
            service_discovery_entry_free(entry);
            retval = -ENOMEM;
            goto ret;
        }

        for (k = 0; k < entry->labels_len; k++)
        {
            const char *label = json_array_get_string(labels, k);
            entry->labels[k] = kstrdup(label, GFP_KERNEL);
            if (!entry->labels[k])
            {
                service_discovery_entry_free(entry);
                retval = -ENOMEM;
                goto ret;
            }
            pr_debug("set sd entry label # address[%s] label[%s]", entry->address, entry->labels[k]);
        }

        service_discovery_table_entry_add(table, entry);
    }

    sd_table_replace(table);

ret:
    json_value_free(json);

    return retval;
}

static void load_camblet_config(const char *data)
{
    if (!data)
    {
        return;
    }

    JSON_Value *json = json_parse_string(data);
    if (json == NULL)
    {
        pr_err("could not load camblet config: invalid json");
    }

    JSON_Object *root = json_value_get_object(json);
    if (root == NULL)
    {
        pr_err("could not load camblet config: invalid json root");
    }

    const char *trust_domain = json_object_get_string(root, "trust_domain");
    if (trust_domain)
    {
        camblet_config_lock();
        camblet_config *config = camblet_config_get_locked();
        if (strcmp(config->trust_domain, trust_domain) != 0)
        {
            pr_info("change trust domain # old[%s] new[%s]", config->trust_domain, trust_domain);
            strlcpy(config->trust_domain, trust_domain, MAX_TRUST_DOMAIN_LEN);
        }
        camblet_config_unlock();
    }

    json_value_free(json);
}

static int parse_command(const char *data)
{
    int status = SUCCESS;
    JSON_Value *json = NULL;

    if (data)
    {
        json = json_parse_string(data);
        JSON_Object *root = json_value_get_object(json);
        const char *command = json_object_get_string(root, "command");

        pr_debug("incoming command # command[%s]", command);

        if (strcmp("load", command) == 0)
        {
            const char *name = json_object_get_string(root, "name");
            pr_info("load module # name[%s]", name);

            const char *code = json_object_get_string(root, "code");
            char *decoded = kzalloc(strlen(code) * 2, GFP_KERNEL);
            int length = base64_decode(decoded, strlen(code) * 2, code, strlen(code));
            if (length < 0)
            {
                pr_crit("base64 decode failed");
                status = -1;
                kfree(decoded);
                goto cleanup;
            }

            const char *entrypoint = json_object_get_string(root, "entrypoint");
            if (entrypoint == NULL)
            {
                pr_info("setting default module entrypoint # entrypoint[%s]", DEFAULT_MODULE_ENTRYPOINT);
                entrypoint = DEFAULT_MODULE_ENTRYPOINT;
            }

            wasm_vm_result result = load_module(name, decoded, length, entrypoint);
            if (result.err)
            {
                pr_crit("could not load module # err[%s]", result.err);
                status = -1;
                kfree(decoded);
                goto cleanup;
            }

            kfree(decoded);
        }
        if (strcmp("reset", command) == 0)
        {
            pr_info("reseting vm");

            wasm_vm_result result = reset_vms();
            if (result.err)
            {
                pr_crit("could not reset vm # err[%s]", result.err);
                status = -1;
                goto cleanup;
            }
        }
        else if (strcmp("load_policies", command) == 0)
        {
            pr_info("load policies");

            const char *code = json_object_get_string(root, "code");
            char *decoded = kzalloc(strlen(code) * 2, GFP_KERNEL);
            int length = base64_decode(decoded, strlen(code) * 2, code, strlen(code));
            if (length < 0)
            {
                pr_crit("base64 decode failed");
                status = -1;
                kfree(decoded);
                goto cleanup;
            }

            load_opa_data(decoded);
            kfree(decoded);
        }
        else if (strcmp("load_config", command) == 0)
        {
            pr_info("load config");

            const char *code = json_object_get_string(root, "code");
            char *decoded = kzalloc(strlen(code) * 2, GFP_KERNEL);
            int length = base64_decode(decoded, strlen(code) * 2, code, strlen(code));
            if (length < 0)
            {
                pr_crit("base64 decode failed");
                status = -1;
                kfree(decoded);
                goto cleanup;
            }

            if (decoded)
            {
                load_camblet_config(decoded);
                kfree(decoded);
            }
        }
        else if (strcmp("load_sd_info", command) == 0)
        {
            pr_info("load sd info");

            const char *code = json_object_get_string(root, "code");
            char *decoded = kzalloc(strlen(code) * 2, GFP_KERNEL);
            int length = base64_decode(decoded, strlen(code) * 2, code, strlen(code));
            if (length < 0)
            {
                pr_crit("base64 decode failed");
                status = -1;
                kfree(decoded);
                goto cleanup;
            }

            if (decoded)
            {
                load_sd_info(decoded);
                kfree(decoded);
            }
        }
        else if (strcmp("manage_trace_requests", command) == 0)
        {
            const char *data = json_object_get_string(root, "data");
            if (data == NULL)
            {
                pr_debug("could not find data # command[%s]", command);

                goto cleanup;
            }

            JSON_Value *data_json = json_parse_string(data);
            if (data_json == NULL)
            {
                pr_debug("could not parse json # command[%s]", command);

                goto cleanup;
            }

            JSON_Object *data_root = json_value_get_object(data_json);
            if (data_root == NULL)
            {
                pr_debug("invalid json format # command[%s]", command);

                goto request_trace_out;
            }

            const char *action = json_object_get_string(data_root, "action");
            if (action == NULL)
            {
                pr_debug("could not find action # command[%s]", command);

                goto request_trace_out;
            }

            int pid = -1;
            if (json_object_has_value(data_root, "pid") == 1)
            {
                pid = json_object_get_number(data_root, "pid");
            }

            int uid = -1;
            if (json_object_has_value(data_root, "uid") == 1)
            {
                uid = json_object_get_number(data_root, "uid");
            }

            const char *command_name = json_object_get_string(data_root, "command_name");

            pr_debug("manage trace # command[%s] action[%s] pid[%d] uid[%d] command_name[%s]", command, action, pid, uid, command_name);

            if (strcmp(action, "add") == 0)
            {
                pr_debug("add trace # command[%s] pid[%d] uid[%d] command_name[%s]", command, pid, uid, command_name);
                add_trace_request(pid, uid, command_name);
            }
            else if (strcmp(action, "remove") == 0)
            {
                pr_debug("disable trace # command[%s] pid[%d] uid[%d] command_name[%s]", command, pid, uid, command_name);
                trace_request *tr = get_trace_request(pid, uid, command_name);
                if (tr)
                {
                    remove_trace_request(tr);
                }
                else
                {
                    pr_debug("trace not exists # command[%s] pid[%d] uid[%d] command_name[%s]", command, pid, uid, command_name);
                }
            }
            else if (strcmp(action, "clear") == 0)
            {
                pr_debug("clear trace requests");

                clear_trace_requests();
            }

        request_trace_out:
            json_value_free(data_json);

            goto cleanup;
        }
        else if (strcmp("answer", command) == 0)
        {
            const char *command_id = json_object_get_string(root, "id");

            pr_debug("command answer # uuid[%s]", command_id);

            uuid_t uuid;
            uuid_parse(command_id, &uuid);
            struct command *cmd = lookup_in_flight_command(uuid.b);

            if (cmd == NULL)
            {
                pr_err("command not found # uuid[%s]", command_id);
                status = -1;
                goto cleanup;
            }

            struct command_answer *cmd_answer = kzalloc(sizeof(struct command_answer), GFP_KERNEL);
            const char *answer = json_object_get_string(root, "answer");
            const char *error = json_object_get_string(root, "error");

            if (error)
            {
                cmd_answer->error = strdup(error);
            }

            if (answer)
            {
                cmd_answer->answer = strdup(answer);
            }

            cmd->answer = cmd_answer;

            wake_up_interruptible(&cmd->wait_queue);
        }
        else
        {
            pr_err("invalid command # command[%s]", command);
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
    pr_info("communcation device closed # command[%s]", current->comm);

    device_buffer_size = 0;

    /* We're now ready for our next caller */
    atomic_set(&already_open, CDEV_NOT_USED);

    /* Decrement the usage count, or else once you opened the file, you will
     * never get rid of the module.
     */
    module_put(THIS_MODULE);

    return 0;
}

static char *serialize_command(struct command *cmd)
{
    char *serialized_string = NULL;
    char uuid[UUID_STRING_LEN + 1];
    int length = snprintf(uuid, UUID_STRING_LEN + 1, "%pUB", cmd->uuid.b);
    if (length < 0)
    {
        pr_crit("could not stringify uuid");
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
        json_object_set_number(context_object, "pid", cmd->context->pid);
        json_object_set_string(context_object, "command_path", cmd->context->command_path);
        json_object_set_string(context_object, "command_name", cmd->context->command_name);
        json_object_set_string(context_object, "cgroup_path", cmd->context->cgroup_path);

        JSON_Value *namespace_ids_value = json_value_init_object();
        JSON_Object *namespace_ids_object = json_value_get_object(namespace_ids_value);
        json_object_set_number(namespace_ids_object, "uts", cmd->context->namespace_ids.uts);
        json_object_set_number(namespace_ids_object, "ipc", cmd->context->namespace_ids.ipc);
        json_object_set_number(namespace_ids_object, "mnt", cmd->context->namespace_ids.mnt);
        json_object_set_number(namespace_ids_object, "pid", cmd->context->namespace_ids.pid);
        json_object_set_number(namespace_ids_object, "net", cmd->context->namespace_ids.net);
        json_object_set_number(namespace_ids_object, "time", cmd->context->namespace_ids.time);
        json_object_set_number(namespace_ids_object, "cgroup", cmd->context->namespace_ids.cgroup);

        json_object_set_value(context_object, "namespace_ids", namespace_ids_value);
        json_object_set_value(root_object, "task_context", context_value);
    }

    json_object_set_string(root_object, "id", uuid);
    json_object_set_string(root_object, "command", cmd->name);
    json_object_set_string(root_object, "data", cmd->data);
    json_object_set_boolean(root_object, "is_message", cmd->is_message);

    serialized_string = json_serialize_to_string(root_value);

cleanup:
    json_value_free(root_value);

    return serialized_string;
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
    pr_debug("read from userspace # length[%lu] offset[%llu]", length, *offset);

    command *c = get_next_command();
    if (c == NULL)
    {
        return -EINTR;
    }

    char *command_json = serialize_command(c);
    if (c->is_message)
    {
        free_command(c);
    }
    if (command_json == NULL)
    {
        return -EFAULT;
    }

    pr_debug("sent command # command[%s]", command_json);

    int bytes_read = 0;
    int bytes_to_read = strlen(command_json);

    if (bytes_to_read >= length)
    {
        pr_err("read buffer too small # bytes_to_read[%d]", bytes_to_read);
    }

    if (bytes_to_read > 0)
    {
        if (copy_to_user(buffer, command_json, bytes_to_read))
        {
            kfree(command_json);
            return -EFAULT;
        }

        put_user('\n', buffer + bytes_to_read);

        bytes_read = bytes_to_read + 1;
        *offset = 0;
    }

    kfree(command_json);
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
    pr_debug("write from userspace # bytes[%d]", bytes_writen);
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
        int status = parse_command(device_buffer);
        if (status != 0)
        {
            pr_err("could not parse command # err[%d]", status);
        }

        memmove(device_buffer, device_buffer + i, device_buffer_size - i);
        device_buffer_size -= i + 1;
    }

    return bytes_writen;
}
