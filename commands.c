/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */
#include <linux/slab.h>
#include <linux/uuid.h>

#include "commands.h"
#include "json.h"

// create a function to add a command to the list (called from the VM), locked with a spinlock
command_answer *send_command(char *name, char *data, task_context *context)
{
    struct command *cmd = kmalloc(sizeof(struct command), GFP_KERNEL);

    uuid_gen(&cmd->uuid);
    cmd->name = name;
    cmd->data = data;
    cmd->context = context;
    init_waitqueue_head(&cmd->wait_queue);

    spin_lock_irqsave(&command_list_lock, command_list_lock_flags);
    list_add_tail(&cmd->list, &command_list);
    spin_unlock_irqrestore(&command_list_lock, command_list_lock_flags);

    DEFINE_WAIT(wait);

    // wait until the command is processed
    printk("wasm: waiting for command to be processed");

    // wait for the command to be processed
    prepare_to_wait(&cmd->wait_queue, &wait, TASK_INTERRUPTIBLE);
    // Sleep until the condition is true or the timeout expires
    unsigned long timeout = msecs_to_jiffies(COMMAND_TIMEOUT_SECONDS * 1000);
    schedule_timeout(timeout);

    finish_wait(&cmd->wait_queue, &wait);

    if (cmd->answer == NULL)
    {
        printk(KERN_ERR "wasm: command answer timeout");

        cmd->answer = kmalloc(sizeof(struct command_answer), GFP_KERNEL);
        cmd->answer->error = kmalloc(strlen("timeout") + 1, GFP_KERNEL);
        strcpy(cmd->answer->error, "timeout");
    }

    spin_lock_irqsave(&command_list_lock, command_list_lock_flags);
    list_del(&cmd->list);
    spin_unlock_irqrestore(&command_list_lock, command_list_lock_flags);

    command_answer *cmd_answer = cmd->answer;
    if (cmd->context)
    {
        free_task_context(cmd->context);
    }
    kfree(cmd);

    return cmd_answer;
}

command_answer *send_accept_command(u16 port)
{
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    json_object_set_number(root_object, "port", port);

    command_answer *answer = send_command("accept", json_serialize_to_string(root_value), get_task_context());

    return answer;
}

command_answer *send_connect_command(u16 port)
{
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    json_object_set_number(root_object, "port", port);

    command_answer *answer = send_command("connect", json_serialize_to_string(root_value), get_task_context());

    return answer;
}

struct command *lookup_in_flight_command(char *id)
{
    spin_lock_irqsave(&command_list_lock, command_list_lock_flags);

    struct command *cmd = NULL;
    struct command *tmp;
    list_for_each_entry(tmp, &in_flight_command_list, list)
    {
        if (strncmp(tmp->uuid.b, id, UUID_SIZE) == 0)
        {
            cmd = tmp;
            break;
        }
    }

    spin_unlock_irqrestore(&command_list_lock, command_list_lock_flags);

    return cmd;
}

// create a function to get a command from the list (called from the driver), locked with a mutex
struct command *get_command(void)
{
    struct command *cmd = NULL;

    spin_lock_irqsave(&command_list_lock, command_list_lock_flags);
    if (!list_empty(&command_list))
    {
        cmd = list_first_entry(&command_list, struct command, list);
        list_del(&cmd->list);
        list_add_tail(&cmd->list, &in_flight_command_list);
    }
    spin_unlock_irqrestore(&command_list_lock, command_list_lock_flags);

    return cmd;
}

void free_command_answer(struct command_answer *cmd_answer)
{
    if (cmd_answer->error)
    {
        kfree(cmd_answer->error);
    }

    if (cmd_answer->answer)
    {
        kfree(cmd_answer->answer);
    }

    kfree(cmd_answer);
}
