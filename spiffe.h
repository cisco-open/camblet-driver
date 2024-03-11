/*
 * Copyright (c) 2024 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef spiffe_h
#define spiffe_h

#include <linux/types.h>

// Check validity according to https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
bool is_spiffe_id_valid(const char *id);

#endif
