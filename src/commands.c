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

#include <linux/slab.h>
#include <linux/inet.h>
#include <linux/ipv6.h>

#include "commands.h"
#include "json.h"
#include "base64.h"
#include "string.h"
#include "socket.h"
#include "trace.h"

// commands that are waiting to be processed by the driver
static LIST_HEAD(command_list);

// lock for the above list to make it thread safe
static DEFINE_MUTEX(command_list_lock);

// wait queue for the driver to be woken up when a command is added to the list
static DECLARE_WAIT_QUEUE_HEAD(command_wait_queue);

// commands that are being processed by the driver
static LIST_HEAD(in_flight_command_list);

static command_answer *this_send_command(char *name, char *data, task_context *context, bool is_message)
{
    struct command *cmd = kzalloc(sizeof(struct command), GFP_KERNEL);
    if (!cmd)
        return ERR_PTR(-ENOMEM);

    uuid_gen(&cmd->uuid);
    cmd->name = name;
    cmd->data = data;
    cmd->context = context;
    cmd->is_message = is_message;

    mutex_lock(&command_list_lock);
    list_add_tail(&cmd->list, &command_list);
    mutex_unlock(&command_list_lock);

    // we can now wake up the driver to send out a command for processing
    wake_up_interruptible(&command_wait_queue);

    if (cmd->is_message)
    {
        return NULL;
    }

    init_waitqueue_head(&cmd->wait_queue);

    // wait until the command is processed
    pr_debug("waiting for command to be processed # name[%s] uuid[%pUB] ", name, cmd->uuid.b);

    // wait for the command to be processed
    DEFINE_WAIT(wait);
    prepare_to_wait(&cmd->wait_queue, &wait, TASK_INTERRUPTIBLE);
    // Sleep until the condition is true or the timeout expires
    unsigned long timeout = msecs_to_jiffies(COMMAND_TIMEOUT_SECONDS * 1000);
    schedule_timeout(timeout);

    finish_wait(&cmd->wait_queue, &wait);

    command_answer *cmd_answer = NULL;
    if (cmd->answer == NULL)
    {
        pr_err("command timeout # name[%s] uuid[%pUB] ", name, cmd->uuid.b);

        cmd->answer = answer_with_error("timeout");
        if (IS_ERR(cmd->answer))
        {
            cmd_answer = (void *)cmd->answer;
            goto out;
        }
    }

    cmd_answer = cmd->answer;

out:
    mutex_lock(&command_list_lock);
    list_del(&cmd->list);
    mutex_unlock(&command_list_lock);

    free_command(cmd);

    return cmd_answer;
}

// add a command to the list (to be processed by the driver)
// this is a blocking function, it will wait until the command is processed
command_answer *send_command(char *name, char *data, task_context *context)
{
    return this_send_command(name, data, context, false);
}

// add a message to the command list (to be processed by the driver)
// this is a non-blocking function
void send_message(char *name, char *data, task_context *context)
{
    this_send_command(name, data, context, true);
}

command_answer *send_augment_command()
{
    task_context *ctx = get_task_context();
    if (IS_ERR(ctx))
        return (void *)ctx;

    return send_command("augment", NULL, ctx);
}

command_answer *send_accept_command(u16 port)
{
    task_context *ctx = get_task_context();
    if (IS_ERR(ctx))
        return (void *)ctx;

    JSON_Value *root_value = json_value_init_object();
    if (!root_value)
        return ERR_PTR(-ENOMEM);

    JSON_Object *root_object = json_value_get_object(root_value);

    if (!root_object)
    {
        return answer_with_error("could not get root object");
    }

    command_answer *answer = NULL;
    if (json_object_set_number(root_object, "port", port) < 0)
        answer = answer_with_error("could not set port");
    else
        answer = send_command("accept", json_serialize_to_string(root_value), ctx);

    json_value_free(root_value);

    return answer;
}

command_answer *send_connect_command(u16 port)
{
    task_context *ctx = get_task_context();
    if (IS_ERR(ctx))
        return (void *)ctx;

    JSON_Value *root_value = json_value_init_object();
    if (!root_value)
        return ERR_PTR(-ENOMEM);

    JSON_Object *root_object = json_value_get_object(root_value);

    if (!root_object)
    {
        return answer_with_error("could not get root object");
    }

    command_answer *answer = NULL;
    if (json_object_set_number(root_object, "port", port) < 0)
        answer = answer_with_error("could not set port");
    else
        answer = send_command("connect", json_serialize_to_string(root_value), ctx);

    json_value_free(root_value);

    return answer;
}

void csr_sign_answer_free(csr_sign_answer *answer)
{
    if (IS_ERR_OR_NULL(answer))
        return;

    kfree(answer->error);
    kfree(answer);
}

static char *prepare_csr_json(const unsigned char *csr, const char *ttl)
{
    char *json = NULL;

    JSON_Value *root_value = json_value_init_object();
    if (!root_value)
        return ERR_PTR(-ENOMEM);

    JSON_Object *root_object = json_value_get_object(root_value);
    if (!root_object)
        goto out;

    if (json_object_set_string(root_object, "csr", csr) < 0)
        goto out;

    if (ttl)
        if (json_object_set_string(root_object, "ttl", ttl) < 0)
            goto out;

    json = json_serialize_to_string(root_value);

out:
    json_value_free(root_value);
    return json;
}

csr_sign_answer *send_csrsign_command(const unsigned char *csr, const char *ttl)
{
    csr_sign_answer *csr_sign_answer = NULL;
    command_answer *answer = NULL;
    JSON_Value *json = NULL;
    const char *errormsg = NULL;
    void *error = NULL;

    task_context *ctx = get_task_context();
    if (IS_ERR(ctx))
        return (void *)ctx;

    csr_sign_answer = kzalloc(sizeof(struct csr_sign_answer), GFP_KERNEL);
    if (!csr_sign_answer)
        return ERR_PTR(-ENOMEM);

    if (!csr)
    {
        error = ERR_PTR(-EINVAL);
        goto error;
    }

    char *csr_json = prepare_csr_json(csr, ttl);
    if (!csr_json)
    {
        errormsg = "could not prepare csr json";
        goto error;
    }
    if (IS_ERR(csr_json))
    {
        error = csr_json;
        goto error;
    }

    answer = send_command("csr_sign", csr_json, ctx);
    if (answer->error)
    {
        errormsg = answer->error;
        goto error;
    }

    if (answer->answer)
    {
        json = json_parse_string(answer->answer);
        if (json == NULL)
        {
            errormsg = "could not parse answer JSON data";
            goto error;
        }

        JSON_Object *root = json_value_get_object(json);
        if (root == NULL)
        {
            errormsg = "could not get root object from parsed JSON";
            goto error;
        }

        JSON_Array *trust_anchors = json_object_get_array(root, "trust_anchors");
        if (trust_anchors == NULL)
        {
            errormsg = "could not find trust anchors";
            goto error;
        }

        csr_sign_answer->cert = x509_certificate_init();
        if (IS_ERR(csr_sign_answer->cert))
        {
            error = csr_sign_answer->cert;
            goto error;
        }

        csr_sign_answer->cert->trust_anchors_len = json_array_get_count(trust_anchors);
        size_t srclen;

        if (csr_sign_answer->cert->trust_anchors_len > 0)
        {
            csr_sign_answer->cert->trust_anchors = kzalloc(csr_sign_answer->cert->trust_anchors_len * sizeof *csr_sign_answer->cert->trust_anchors, GFP_KERNEL);
            if (!csr_sign_answer->cert->trust_anchors)
            {
                error = ERR_PTR(-ENOMEM);
                goto error;
            }

            size_t u;
            for (u = 0; u < csr_sign_answer->cert->trust_anchors_len; u++)
            {
                JSON_Object *ta = json_array_get_object(trust_anchors, u);

                csr_sign_answer->cert->trust_anchors[u].flags = BR_X509_TA_CA;
                csr_sign_answer->cert->trust_anchors[u].pkey.key_type = BR_KEYTYPE_RSA;

                // RAW (DN)
                const char *raw_subject = json_object_get_string(ta, "rawSubject");
                if (raw_subject != NULL)
                {
                    srclen = strlen(raw_subject);
                    csr_sign_answer->cert->trust_anchors[u].dn.data = kzalloc(srclen, GFP_KERNEL);
                    if (!csr_sign_answer->cert->trust_anchors[u].dn.data)
                    {
                        error = ERR_PTR(-ENOMEM);
                        goto error;
                    }
                    csr_sign_answer->cert->trust_anchors[u].dn.len = base64_decode(csr_sign_answer->cert->trust_anchors[u].dn.data, srclen, raw_subject, srclen);
                }

                // RSA_N
                const char *rsa_n = json_object_dotget_string(ta, "publicKey.RSA_N");
                if (rsa_n != NULL)
                {
                    srclen = strlen(rsa_n);
                    csr_sign_answer->cert->trust_anchors[u].pkey.key.rsa.n = kzalloc(srclen, GFP_KERNEL);
                    if (!csr_sign_answer->cert->trust_anchors[u].pkey.key.rsa.n)
                    {
                        error = ERR_PTR(-ENOMEM);
                        goto error;
                    }
                    csr_sign_answer->cert->trust_anchors[u].pkey.key.rsa.nlen = base64_decode(csr_sign_answer->cert->trust_anchors[u].pkey.key.rsa.n, srclen, rsa_n, srclen);
                }

                // RSA_E
                const char *rsa_e = json_object_dotget_string(ta, "publicKey.RSA_E");
                if (rsa_e != NULL)
                {
                    srclen = strlen(rsa_e);
                    csr_sign_answer->cert->trust_anchors[u].pkey.key.rsa.e = kzalloc(srclen, GFP_KERNEL);
                    if (!csr_sign_answer->cert->trust_anchors[u].pkey.key.rsa.e)
                    {
                        error = ERR_PTR(-ENOMEM);
                        goto error;
                    }
                    csr_sign_answer->cert->trust_anchors[u].pkey.key.rsa.elen = base64_decode(csr_sign_answer->cert->trust_anchors[u].pkey.key.rsa.e, srclen, rsa_e, srclen);
                }
            }
        }

        JSON_Array *chain = json_object_get_array(root, "chain");
        if (chain == NULL)
        {
            errormsg = "could not find chain";
            goto error;
        }

        const char *raw = json_object_dotget_string(root, "certificate.raw");
        if (raw == NULL)
        {
            errormsg = "could not find certificate in response";
            goto error;
        }

        csr_sign_answer->cert->chain_len = json_array_get_count(chain);
        csr_sign_answer->cert->chain_len++;
        csr_sign_answer->cert->chain = kzalloc(csr_sign_answer->cert->chain_len * sizeof *csr_sign_answer->cert->chain, GFP_KERNEL);
        if (!csr_sign_answer->cert->chain)
        {
            error = ERR_PTR(-ENOMEM);
            goto error;
        }

        srclen = strlen(raw);
        csr_sign_answer->cert->chain[0].data = kzalloc(srclen, GFP_KERNEL);
        if (!csr_sign_answer->cert->chain[0].data)
        {
            error = ERR_PTR(-ENOMEM);
            goto error;
        }
        csr_sign_answer->cert->chain[0].data_len = base64_decode(csr_sign_answer->cert->chain[0].data, srclen, raw, srclen);

        int k;
        int j = 1;
        for (k = 0; k < csr_sign_answer->cert->chain_len - 1; k++)
        {
            JSON_Object *chain_entry = json_array_get_object(chain, k);
            if (chain_entry)
            {
                raw = json_object_get_string(chain_entry, "raw");
                if (raw)
                {
                    srclen = strlen(raw);
                    csr_sign_answer->cert->chain[j].data = kzalloc(srclen, GFP_KERNEL);
                    if (!csr_sign_answer->cert->chain[j].data)
                    {
                        error = ERR_PTR(-ENOMEM);
                        goto error;
                    }
                    csr_sign_answer->cert->chain[j].data_len = base64_decode(csr_sign_answer->cert->chain[j].data, srclen, raw, srclen);

                    j++;
                }
            }
        }

        int result = set_cert_validity(csr_sign_answer->cert);
        if (result < 0)
        {
            errormsg = "could not decode generated certificate";
            goto error;
        }
    }

    return csr_sign_answer;

error:
    if (errormsg)
    {
        csr_sign_answer->error = kstrdup(errormsg, GFP_KERNEL);
        if (!csr_sign_answer->error)
        {
            error = ERR_PTR(-ENOMEM);
        }
        error = ERR_PTR(-ENOMEM);
    }

    json_value_free(json);
    free_command_answer(answer);

    if (IS_ERR(error))
    {
        x509_certificate_put(csr_sign_answer->cert);
        csr_sign_answer_free(csr_sign_answer);
        return error;
    }

    return csr_sign_answer;
}

command *lookup_in_flight_command(char *id)
{
    mutex_lock(&command_list_lock);

    command *cmd = NULL;
    command *tmp;
    list_for_each_entry(tmp, &in_flight_command_list, list)
    {
        if (strncmp(tmp->uuid.b, id, UUID_SIZE) == 0)
        {
            cmd = tmp;
            break;
        }
    }

    mutex_unlock(&command_list_lock);

    return cmd;
}

// get a command from the list (called from the driver),
// this is a blocking function, it will wait until a command is available
command *get_next_command(void)
{
    if (list_empty(&command_list))
    {
        DEFINE_WAIT(wait);
        prepare_to_wait(&command_wait_queue, &wait, TASK_INTERRUPTIBLE);

        schedule();
        finish_wait(&command_wait_queue, &wait);
    }

    // if the list is still empty, return NULL (most probably a the process is being killed)
    if (list_empty(&command_list))
    {
        return NULL;
    }

    mutex_lock(&command_list_lock);
    command *cmd = list_first_entry(&command_list, struct command, list);
    list_del(&cmd->list);
    if (!cmd->is_message)
    {
        list_add_tail(&cmd->list, &in_flight_command_list);
    }
    mutex_unlock(&command_list_lock);

    return cmd;
}

command_answer *answer_with_error(char *error_message)
{
    command_answer *answer = kzalloc(sizeof(struct command_answer), GFP_KERNEL);
    if (!answer)
        return ERR_PTR(-ENOMEM);

    answer->error = kstrdup(error_message, GFP_KERNEL);
    if (!answer->error)
        return ERR_PTR(-ENOMEM);

    return answer;
}

void free_command_answer(command_answer *cmd_answer)
{
    if (IS_ERR_OR_NULL(cmd_answer))
        return;

    kfree(cmd_answer->error);
    kfree(cmd_answer->answer);
    kfree(cmd_answer);
}

void free_command(command *cmd)
{
    if (!cmd)
    {
        return;
    }

    if (cmd->context)
    {
        free_task_context(cmd->context);
    }

    kfree(cmd->data);
    kfree(cmd);
}
