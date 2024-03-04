/*
 * Copyright (c) 2024 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef jwt_h
#define jwt_h

#include "jwt.h"

typedef struct jwt
{
    char *alg;
    char *typ;

    char *iss;
    char *sub;
    char *aud;
    u64 exp;

} jwt_t;

jwt_t *jwt_parse(const char *jwt, const char *secret);
void jwt_free(jwt_t *jwt);

#endif
