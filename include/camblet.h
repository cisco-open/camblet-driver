/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef camblet_h
#define camblet_h

#define SOL_CAMBLET 7891
#define CAMBLET_HOSTNAME 1
#define CAMBLET_TLS_INFO 2
#define CAMBLET "camblet"

#define CAMBLET_EINVALIDSPIFFEID 1001

typedef struct
{
    bool camblet_enabled;
    bool mtls_enabled;
    char spiffe_id[256];
    char peer_spiffe_id[256];
    char alpn[256];
} camblet_tls_info;

#endif /* camblet_h */
