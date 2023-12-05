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

#include <linux/list.h>
#include <linux/slab.h>

#include "attest.h"
#include "commands.h"
#include "string.h"
#include "cert_tools.h"

// Define the maximum number of elements inside the cache
#define MAX_CACHE_LENGTH 64

// process augmentation responses
static LIST_HEAD(augmentation_response_cache);

// lock for the above list to make it thread safe
static DEFINE_MUTEX(augment_response_cache_lock);

static void augmentation_response_cache_lock(void)
{
    mutex_lock(&augment_response_cache_lock);
}

static void augmentation_response_cache_unlock(void)
{
    mutex_unlock(&augment_response_cache_lock);
}

static void augmentation_response_cache_remove_locked(augmentation_response_cache_entry *entry)
{
    if (entry)
    {
        list_del(&entry->list);
        augmentation_response_put(entry->response);
        kfree(entry->key);
        kfree(entry);
    }
}

static void augmentation_response_cache_remove(augmentation_response_cache_entry *entry)
{
    if (entry)
    {
        augmentation_response_cache_lock();
        augmentation_response_cache_remove_locked(entry);
        augmentation_response_cache_unlock();
    }
}

static void housekeep_augment_cache_locked(void)
{
    if (linkedlist_length(&augmentation_response_cache) >= MAX_CACHE_LENGTH)
    {
        pr_debug("cache is full: remove the oldest element");
        augmentation_response_cache_entry *last_entry = list_last_entry(&augmentation_response_cache, augmentation_response_cache_entry, list);
        pr_debug("remove cache entry # key=[%s]", last_entry->key);
        augmentation_response_cache_remove_locked(last_entry);
    }
}

static augmentation_response *augmentation_response_init(void)
{
    augmentation_response *response = kzalloc(sizeof(augmentation_response), GFP_KERNEL);

    kref_init(&response->kref);

    return response;
}

static void augmentation_response_free(augmentation_response *response)
{
    if (!response)
    {
        return;
    }

    kfree(response->error);
    kfree(response->response);
    kfree(response);
}

static void augmentation_response_release(struct kref *kref)
{
    augmentation_response *response = container_of(kref, augmentation_response, kref);

    augmentation_response_free(response);
}

void augmentation_response_get(augmentation_response *response)
{
    if (!response)
    {
        return;
    }

    kref_get(&response->kref);
}

void augmentation_response_put(augmentation_response *response)
{
    if (!response)
    {
        return;
    }

    kref_put(&response->kref, augmentation_response_release);
}

static char *get_task_context_key(task_context *ctx)
{
    int keylen = snprintf(NULL, 0, "%s %d %d %u %s", ctx->cgroup_path, ctx->uid.val, ctx->gid.val, ctx->namespace_ids.mnt, ctx->command_path);
    char *key = kzalloc(keylen + 1, GFP_KERNEL);
    snprintf(key, keylen + 1, "%s %d %d %u %s", ctx->cgroup_path, ctx->uid.val, ctx->gid.val, ctx->namespace_ids.mnt, ctx->command_path);

    return key;
}

static void augmentation_response_cache_set_locked(char *key, augmentation_response *response)
{
    if (!key)
    {
        pr_err("invalid key");
        return;
    }

    housekeep_augment_cache_locked();

    augmentation_response_cache_entry *new_entry = kzalloc(sizeof(augmentation_response_cache_entry), GFP_KERNEL);
    if (!new_entry)
    {
        pr_err("memory allocation error");
        return;
    }

    new_entry->key = strdup(key);
    new_entry->response = response;

    pr_debug("add entry # key[%s]", new_entry->key);
    list_add(&new_entry->list, &augmentation_response_cache);
}

static augmentation_response *augmentation_response_cache_get_locked(char *key)
{
    if (!key)
    {
        return NULL;
    }

    augmentation_response_cache_entry *entry;

    list_for_each_entry(entry, &augmentation_response_cache, list)
    {
        if (strncmp(entry->key, key, strlen(key)) == 0)
        {
            pr_debug("cache hit # key[%s]", key);
            return entry->response;
        }
    }

    return NULL;
}

augmentation_response *augment_workload()
{
    augmentation_response *response;

    augmentation_response_cache_lock();

    char *key = get_task_context_key(get_task_context());
    response = augmentation_response_cache_get_locked(key);
    if (response)
    {
        augmentation_response_get(response);
        goto ret;
    }

    response = augmentation_response_init();
    command_answer *answer = send_augment_command();
    if (answer->error)
        response->error = strdup(answer->error);
    else
    {
        response->response = strdup(answer->answer);
        augmentation_response_cache_set_locked(key, response);
        augmentation_response_get(response);
    }

    free_command_answer(answer);

ret:
    kfree(key);

    augmentation_response_cache_unlock();

    return response;
}
