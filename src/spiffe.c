/*
 * Copyright (c) 2024 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include "spiffe.h"

#include <linux/string.h>
#include <linux/printk.h>

static bool path_boundary_invalid(const char *path)
{
    return strcmp(path, "/") == 0 || strcmp(path, "/.") == 0 || strcmp(path, "/..") == 0;
}

bool is_spiffe_id_valid(const char *id)
{
    if (strncmp(id, "spiffe://", 9) != 0)
        return false;

    id = id + 8;

    if (strlen(id) == 0 || id[0] != '/')
        return false;

    // segment checks
    char *segment = id;
    int end = 0;
    for (; end < strlen(id); end++)
    {
        char c = segment[0];
        if (c == '/')
        {
            if (path_boundary_invalid(segment))
                return false;

            segment = id + end;
            continue;
        }
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              (c == '-' || c == '.' || c == '_')))
            return false;
    }

    if (path_boundary_invalid(segment))
        return false;

    return true;
}
