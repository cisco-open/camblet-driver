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

    if (IS_ERR(cls))
        return PTR_ERR(cls);

    struct device *dev = device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(dev))
        return PTR_ERR(dev);

    pr_info("device created # device[/dev/%s]", DEVICE_NAME);

    return SUCCESS;
}

void chardev_exit(void)
{
    if (!IS_ERR(cls))
    {
        device_destroy(cls, MKDEV(major, 0));
        class_destroy(cls);
        pr_info("device destroyed # device[/dev/%s]", DEVICE_NAME);
    }

    /* Unregister the device */
    if (major > 0)
    {
        unregister_chrdev(major, DEVICE_NAME);
        pr_info("char device unregistered # major[%d]", major);
    }
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

        result = wasm_vm_compile_module(module);

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
    if (!json)
    {
        pr_err("could not load sd info: invalid json");
        retval = -EINVAL;
        goto ret;
    }

    JSON_Object *root = json_value_get_object(json);
    if (!root)
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
        entry->labels = kzalloc(entry->labels_len * sizeof(char *), GFP_KERNEL);
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

static int load_camblet_config(const char *data)
{
    int status = SUCCESS;

    if (!data)
        return -EINVAL;

    JSON_Value *json = json_parse_string(data);
    if (!json)
    {
        pr_err("could not load camblet config: invalid json");
        status = -EINVAL;
        goto out;
    }

    JSON_Object *root = json_value_get_object(json);
    if (!root)
    {
        pr_err("could not load camblet config: invalid json root");
        status = -EINVAL;
        goto out;
    }

    const char *trust_domain = json_object_get_string(root, "trust_domain");
    if (trust_domain)
    {
        camblet_config_lock();
        camblet_config *config = camblet_config_get_locked();
        if (strcmp(config->trust_domain, trust_domain) != 0)
        {
            pr_info("change trust domain # old[%s] new[%s]", config->trust_domain, trust_domain);
            strscpy(config->trust_domain, trust_domain, MAX_TRUST_DOMAIN_LEN);
        }
        camblet_config_unlock();
    }

out:
    json_value_free(json);
    return status;
}

static char *base64_decode_data(const char *src, int *decoded_length)
{
    char *decoded = kzalloc(strlen(src) * 2, GFP_KERNEL);
    if (!decoded)
        return ERR_PTR(-ENOMEM);

    int length = base64_decode(decoded, strlen(src) * 2, src, strlen(src));
    if (length < 0)
    {
        kfree(decoded);
        return ERR_PTR(-EINVAL);
    }

    *decoded_length = length;

    return decoded;
}

static int parse_command(const char *data)
{
    int status = SUCCESS;
    JSON_Value *json = NULL;
    const char *command = NULL;

    if (!data)
        return -EINVAL;

    json = json_parse_string(data);
    if (!json)
    {
        pr_err("parse_command: could not parse data");
        status = -EINVAL;
        goto out;
    }

    JSON_Object *root = json_value_get_object(json);
    if (!root)
    {
        pr_err("parse_command: invalid JSON root object");
        status = -EINVAL;
        goto out;
    }

    command = json_object_get_string(root, "command");
    if (!command)
    {
        pr_err("parse_command: missing 'command' property");
        status = -EINVAL;
        goto out;
    }

    pr_debug("incoming command # command[%s]", command);

    if (strcmp("load", command) == 0)
    {
        const char *name = json_object_get_string(root, "name");
        if (!name)
        {
            pr_err("load: missing 'name' property");
            status = -EINVAL;
            goto out;
        }

        pr_info("load module # name[%s]", name);

        const char *code = json_object_get_string(root, "code");
        if (!code)
        {
            pr_err("load: missing 'code' property");
            status = -EINVAL;
            goto out;
        }
        int length = 0;
        char *decoded = base64_decode_data(code, &length);
        if (IS_ERR(decoded))
        {
            pr_err("could not decode data: err[%ld]", PTR_ERR(decoded));
            goto out;
        }

        const char *entrypoint = json_object_get_string(root, "entrypoint");
        if (!entrypoint)
        {
            pr_info("setting default module entrypoint # entrypoint[%s]", DEFAULT_MODULE_ENTRYPOINT);
            entrypoint = DEFAULT_MODULE_ENTRYPOINT;
        }

        wasm_vm_result result = load_module(name, decoded, length, entrypoint);
        kfree(decoded);
        if (result.err)
        {
            pr_crit("could not load module # err[%s]", result.err);
            status = FAILURE;
            goto out;
        }
    }
    else if (strcmp("reset", command) == 0)
    {
        pr_info("reseting vm");

        wasm_vm_result result = reset_vms();
        if (result.err)
        {
            pr_crit("could not reset vm # err[%s]", result.err);
            status = FAILURE;
            goto out;
        }
    }
    else if (strcmp("load_policies", command) == 0)
    {
        pr_info("load policies");
        const char *code = json_object_get_string(root, "code");
        if (!code)
        {
            pr_err("load_policies: missing 'code' property");
            status = -EINVAL;
            goto out;
        }
        int length = 0;
        char *decoded = base64_decode_data(code, &length);
        if (IS_ERR(decoded))
        {
            status = PTR_ERR(decoded);
            pr_err("load_policies: could not decode data: err[%d]", status);
            goto out;
        }
        load_opa_data(decoded);
        kfree(decoded);
        goto out;
    }
    else if (strcmp("load_config", command) == 0)
    {
        const char *code = json_object_get_string(root, "code");
        if (!code)
        {
            pr_err("load_config: missing 'code' property");
            status = -EINVAL;
            goto out;
        }
        int length = 0;
        char *decoded = base64_decode_data(code, &length);
        if (IS_ERR(decoded))
        {
            pr_err("could not decode data: err[%ld]", PTR_ERR(decoded));
            goto out;
        }
        int ret = load_camblet_config(decoded);
        if (ret < 0)
            pr_err("could not load camblet config # error_code[%d]", ret);
        kfree(decoded);
        goto out;
    }
    else if (strcmp("load_sd_info", command) == 0)
    {
        pr_info("load sd info");

        const char *code = json_object_get_string(root, "code");
        if (!code)
        {
            pr_err("load_sd_info: missing 'code' property");
            status = -EINVAL;
            goto out;
        }
        int length = 0;
        char *decoded = base64_decode_data(code, &length);
        if (IS_ERR(decoded))
        {
            pr_err("could not decode data: err[%ld]", PTR_ERR(decoded));
            goto out;
        }
        pr_info("sd info arrived # length[%d]", length);
        int ret = load_sd_info(decoded);
        if (ret < 0)
            pr_err("could not load sd info # error_code[%d]", ret);
        kfree(decoded);
        goto out;
    }
    else if (strcmp("manage_trace_requests", command) == 0)
    {
        const char *data = json_object_get_string(root, "data");
        if (!data)
        {
            pr_err("missing 'data' property # command[%s]", command);
            status = -EINVAL;
            goto out;
        }

        JSON_Value *data_json = json_parse_string(data);
        if (!data_json)
        {
            pr_err("could not parse json # command[%s]", command);
            status = -EINVAL;
            goto out;
        }

        JSON_Object *data_root = json_value_get_object(data_json);
        if (!data_root)
        {
            pr_err("invalid JSON root object # command[%s]", command);
            status = -EINVAL;
            goto request_trace_out;
        }

        const char *action = json_object_get_string(data_root, "action");
        if (!action)
        {
            pr_err("missing 'action' property # command[%s]", command);
            status = -EINVAL;
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
        if (!command_name)
        {
            command_name = "";
        }

        pr_debug("manage trace # command[%s] action[%s] pid[%d] uid[%d] command_name[%s]", command, action, pid, uid, command_name);

        if (strcmp(action, "add") == 0)
        {
            pr_debug("add trace # command[%s] pid[%d] uid[%d] command_name[%s]", command, pid, uid, command_name);
            int ret = add_trace_request(pid, uid, command_name);
            if (ret < 0)
            {
                pr_err("could not add trace request # command[%s] error_code[%d]", command, ret);
            }
        }
        else if (strcmp(action, "remove") == 0)
        {
            pr_debug("disable trace # command[%s] pid[%d] uid[%d] command_name[%s]", command, pid, uid, command_name);
            trace_request *tr = get_trace_request(pid, uid, command_name);
            if (tr)
                remove_trace_request(tr);
            else
                pr_debug("trace not exists # command[%s] pid[%d] uid[%d] command_name[%s]", command, pid, uid, command_name);
        }
        else if (strcmp(action, "clear") == 0)
        {
            pr_debug("clear trace requests");

            clear_trace_requests();
        }

    request_trace_out:
        json_value_free(data_json);

        goto out;
    }
    else if (strcmp("answer", command) == 0)
    {
        const char *command_id = json_object_get_string(root, "id");
        if (!command_id)
        {
            pr_err("answer: missing 'id' property");
            status = -EINVAL;
            goto out;
        }

        pr_debug("command answer # id[%s]", command_id);

        uuid_t uuid;
        int ret = uuid_parse(command_id, &uuid);
        if (ret < 0)
        {
            pr_err("answer: invalid command id # id[%s]", command_id);
            status = ret;
            goto out;
        }

        struct command *cmd = lookup_in_flight_command(uuid.b);
        if (!cmd)
        {
            pr_err("command not found # id[%s]", command_id);
            status = -ENOENT;
            goto out;
        }

        struct command_answer *cmd_answer = kzalloc(sizeof(struct command_answer), GFP_KERNEL);
        if (!cmd_answer)
        {
            status = -ENOMEM;
            goto out;
        }

        const char *error = json_object_get_string(root, "error");
        if (error)
        {
            cmd_answer->error = kstrdup(error, GFP_KERNEL);
            if (!cmd_answer->error)
            {
                kfree(cmd_answer);
                status = -ENOMEM;
                goto out;
            }
        }

        const char *answer = json_object_get_string(root, "answer");
        if (answer)
        {
            cmd_answer->answer = kstrdup(answer, GFP_KERNEL);
            if (!cmd_answer->answer)
            {
                kfree(cmd_answer);
                status = -ENOMEM;
                goto out;
            }
        }

        cmd->answer = cmd_answer;

        wake_up_interruptible(&cmd->wait_queue);
    }
    else
    {
        pr_err("invalid command # command[%s]", command);
        status = -EINVAL;
        goto out;
    }

out:
    json_value_free(json);

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
    char *error = NULL;
    char uuid[UUID_STRING_LEN + 1];

    int length = snprintf(uuid, UUID_STRING_LEN + 1, "%pUB", cmd->uuid.b);
    if (length < 0)
    {
        pr_err("serialize_command: could not stringify uuid");
        return ERR_PTR(-EINVAL);
    }

    JSON_Value *root_value = json_value_init_object();
    if (!root_value)
    {
        pr_err("serialize_command: could not init root json value");
        return ERR_PTR(-ENOMEM);
    }
    JSON_Object *root_object = json_value_get_object(root_value);
    if (!root_object)
    {
        pr_err("serialize_command: could not get root object");
        error = ERR_PTR(-EINVAL);
        goto cleanup;
    }

    JSON_Value *context_value = NULL;
    bool context_value_free = false;
    JSON_Value *namespace_ids_value = NULL;
    bool namespace_ids_value_free = false;

    if (cmd->context)
    {
        context_value = json_value_init_object();
        if (!context_value)
        {
            pr_err("serialize_command: could not init context json value");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }
        else
            context_value_free = true;
        JSON_Object *context_object = json_value_get_object(context_value);
        if (!context_object)
        {
            pr_err("serialize_command: could not get context object");
            error = ERR_PTR(-EINVAL);
            goto cleanup;
        }
        if (json_object_set_number(context_object, "uid", cmd->context->uid.val) < 0)
        {
            pr_err("serialize_command: could not set 'uid' property");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }
        if (json_object_set_number(context_object, "gid", cmd->context->gid.val) < 0)
        {
            pr_err("serialize_command: could not set 'gid' property");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }
        if (json_object_set_number(context_object, "pid", cmd->context->pid) < 0)
        {
            pr_err("serialize_command: could not set 'pid' property");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }
        if (json_object_set_string(context_object, "command_path", cmd->context->command_path) < 0)
        {
            pr_err("serialize_command: could not set 'command_path' property");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }
        if (json_object_set_string(context_object, "command_name", cmd->context->command_name) < 0)
        {
            pr_err("serialize_command: could not set 'command_name' property");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }
        if (json_object_set_string(context_object, "cgroup_path", cmd->context->cgroup_path) < 0)
        {
            pr_err("serialize_command: could not set 'cgroup_path' property");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }

        if (json_object_set_value(root_object, "task_context", context_value) < 0)
        {
            pr_err("serialize_command: could not set 'task_context' property");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }
        else
            context_value_free = false;

        namespace_ids_value = json_value_init_object();
        if (!namespace_ids_value)
        {
            pr_err("serialize_command: could not init namespace ids json value");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }
        else
            namespace_ids_value_free = true;
        JSON_Object *namespace_ids_object = json_value_get_object(namespace_ids_value);
        if (!namespace_ids_object)
        {
            pr_err("serialize_command: could not get namespace ids object");
            error = ERR_PTR(-EINVAL);
            goto cleanup;
        }

        if (json_object_set_number(namespace_ids_object, "uts", cmd->context->namespace_ids.uts) < 0)
        {
            pr_err("serialize_command: could not set 'uts' property");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }
        if (json_object_set_number(namespace_ids_object, "ipc", cmd->context->namespace_ids.ipc) < 0)
        {
            pr_err("serialize_command: could not set 'ipc' property");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }
        if (json_object_set_number(namespace_ids_object, "mnt", cmd->context->namespace_ids.mnt) < 0)
        {
            pr_err("serialize_command: could not set 'mnt' property");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }
        if (json_object_set_number(namespace_ids_object, "pid", cmd->context->namespace_ids.pid) < 0)
        {
            pr_err("serialize_command: could not set 'pid' property");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }
        if (json_object_set_number(namespace_ids_object, "net", cmd->context->namespace_ids.net) < 0)
        {
            pr_err("serialize_command: could not set 'net' property");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }
        if (json_object_set_number(namespace_ids_object, "time", cmd->context->namespace_ids.time) < 0)
        {
            pr_err("serialize_command: could not set 'time' property");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }
        if (json_object_set_number(namespace_ids_object, "cgroup", cmd->context->namespace_ids.cgroup) < 0)
        {
            pr_err("serialize_command: could not set 'cgroup' property");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }

        if (json_object_set_value(context_object, "namespace_ids", namespace_ids_value) < 0)
        {
            pr_err("serialize_command: could not set 'namespace_ids' property");
            error = ERR_PTR(-ENOMEM);
            goto cleanup;
        }
        else
            namespace_ids_value_free = false;
    }

    if (json_object_set_string(root_object, "id", uuid) < 0)
    {
        pr_err("serialize_command: could not set 'id' property");
        error = ERR_PTR(-ENOMEM);
        goto cleanup;
    }

    if (json_object_set_string(root_object, "command", cmd->name) < 0)
    {
        pr_err("serialize_command: could not set 'command' property");
        error = ERR_PTR(-ENOMEM);
        goto cleanup;
    }

    if (cmd->data && json_object_set_string(root_object, "data", cmd->data) < 0)
    {
        pr_err("serialize_command: could not set 'data' property");
        error = ERR_PTR(-ENOMEM);
        goto cleanup;
    }

    if (json_object_set_boolean(root_object, "is_message", cmd->is_message) < 0)
    {
        pr_err("serialize_command: could not set 'is_message' property");
        error = ERR_PTR(-ENOMEM);
        goto cleanup;
    }

    serialized_string = json_serialize_to_string(root_value);
    if (!serialized_string)
    {
        pr_err("serialize_command: could not serialize json");
        error = ERR_PTR(-ENOMEM);
    }

cleanup:
    json_value_free(root_value);
    if (context_value_free)
        json_value_free(context_value);
    if (namespace_ids_value_free)
        json_value_free(namespace_ids_value);

    if (IS_ERR(error))
        return error;

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
    if (IS_ERR(command_json))
    {
        pr_err("could not marshal command json # uuid[%pUB] error_code[%ld]", c->uuid.b, PTR_ERR(command_json));
        return -EINTR;
    }
    if (command_json == NULL)
    {
        pr_err("could not marshal command json # uuid[%pUB]", c->uuid.b);
        return -EINTR;
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
