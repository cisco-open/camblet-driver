/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 * 
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied, 
 * modified, or distributed except according to those terms.
 */

#pragma once

void add_to_module_hashtable(i32, void *, i32);
void get_from_module_hashtable(const char *module, i32, void **, i32 *);
void delete_from_module_hashtable(i32);
void keys_from_module_hashtable(const char *module, void **data, i32 *data_length);
