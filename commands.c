/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include "commands.h"
#include "json.h"

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
