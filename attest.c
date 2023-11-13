/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include <linux/list.h>
#include <linux/slab.h>

#include "attest.h"
#include "commands.h"
#include "string.h"
#include "cert_tools.h"

// Define the maximum number of elements inside the cache
#define MAX_CACHE_LENGTH 64

// workload attest responses
static LIST_HEAD(attest_cache);

// lock for the above list to make it thread safe
static DEFINE_MUTEX(attests_cache_lock);

static void attest_cache_lock(void)
{
    mutex_lock(&attests_cache_lock);
}

static void attest_cache_unlock(void)
{
    mutex_unlock(&attests_cache_lock);
}

static void attest_response_cache_remove_locked(attest_response_cache_entry *entry)
{
    if (entry)
    {
        list_del(&entry->list);
        attest_response_put(entry->response);
        kfree(entry->key);
        kfree(entry);
    }
}

static void attest_response_cache_remove(attest_response_cache_entry *entry)
{
    if (entry)
    {
        attest_cache_lock();
        attest_response_cache_remove_locked(entry);
        attest_cache_unlock();
    }
}

static void housekeep_cache_locked(void)
{
    if (linkedlist_length(&attest_cache) >= MAX_CACHE_LENGTH)
    {
        pr_warn("nasp: attests cache is full removing the oldest element");
        attest_response_cache_entry *last_entry = list_last_entry(&attest_cache, attest_response_cache_entry, list);
        pr_warn("nasp: removing key[%s] from the cache", last_entry->key);
        attest_response_cache_remove_locked(last_entry);
    }
}

static attest_response *attest_response_init(void)
{
    attest_response *response = kzalloc(sizeof(attest_response), GFP_KERNEL);

    kref_init(&response->kref);

    return response;
}

static void attest_response_free(attest_response *response)
{
    if (!response)
    {
        return;
    }

    kfree(response->error);
    kfree(response->response);
    kfree(response);
}

static void attest_response_release(struct kref *kref)
{
    attest_response *response = container_of(kref, attest_response, kref);

    pr_info("nasp: release attest response");

    attest_response_free(response);
}

void attest_response_get(attest_response *response)
{
    if (!response)
    {
        return;
    }

    kref_get(&response->kref);
}

void attest_response_put(attest_response *response)
{
    if (!response)
    {
        return;
    }

    kref_put(&response->kref, attest_response_release);
}

static char *get_task_context_key(task_context *ctx)
{
    int keylen = snprintf(NULL, 0, "%s %d %d %u %s", ctx->cgroup_path, ctx->uid.val, ctx->gid.val, ctx->namespace_ids.mnt, ctx->command_path);
    char *key = kzalloc(keylen + 1, GFP_KERNEL);
    snprintf(key, keylen + 1, "%s %d %d %u %s", ctx->cgroup_path, ctx->uid.val, ctx->gid.val, ctx->namespace_ids.mnt, ctx->command_path);

    return key;
}

static void attest_response_cache_set_locked(char *key, attest_response *response)
{
    if (!key)
    {
        pr_err("nasp: attest response cache: provided key is null");
        return;
    }

    housekeep_cache_locked();

    attest_response_cache_entry *new_entry = kzalloc(sizeof(attest_response_cache_entry), GFP_KERNEL);
    if (!new_entry)
    {
        pr_err("nasp: attest response cache: memory allocation error");
        return;
    }

    new_entry->key = strdup(key);
    new_entry->response = response;

    pr_info("nasp: attest response cache set: key[%s]", new_entry->key);
    list_add(&new_entry->list, &attest_cache);
}

static attest_response *attest_response_cache_get_locked(char *key)
{
    if (!key)
    {
        return NULL;
    }

    attest_response_cache_entry *entry;

    list_for_each_entry(entry, &attest_cache, list)
    {
        if (strncmp(entry->key, key, strlen(key)) == 0)
        {
            pr_info("nasp: attest response cache hit: key[%s]", key);
            return entry->response;
        }
    }

    return NULL;
}

attest_response *attest_workload()
{
    attest_response *response;

    attest_cache_lock();

    char *key = get_task_context_key(get_task_context());
    response = attest_response_cache_get_locked(key);
    if (response)
    {
        attest_response_get(response);
        goto ret;
    }

    response = attest_response_init();
    command_answer *answer = send_attest_command();
    if (answer->error)
        response->error = strdup(answer->error);
    else
    {
        response->response = strdup(answer->answer);
        attest_response_cache_set_locked(key, response);
        attest_response_get(response);
    }

    free_command_answer(answer);

ret:
    kfree(key);

    attest_cache_unlock();

    return response;
}
