/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 * 
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied, 
 * modified, or distributed except according to those terms.
 */

#include <linux/hashtable.h>

#include "wasm.h"

#define MODULE_HASH_BITS 10

struct h_node
{
    int key;
    void *data;
    int data_length;
    struct hlist_node node;
};

static DEFINE_HASHTABLE(module_table, MODULE_HASH_BITS);
static unsigned HASH_TABLE_ELEMENTS = 0;

// add_to_module_hashtable function is not thread safe
void add_to_module_hashtable(i32 id, void *data, i32 data_length)
{
    // Since linux hashtable always appends the new element to the bucket ignoring key collision altogether
    // we have to check whether an item with the key is already present in the map.
    // If it does we must handle that with raising an error.
    bool update = false;
    struct h_node *cur = NULL;
    struct h_node *bucket = NULL;

    hash_for_each_possible(module_table, cur, node, id)
    {
        bucket = cur;
    }

    if (bucket)
    {
        printk("nasp: duplicate key (%d) found in hashmap, overwriting", id);
        kfree(bucket->data);
        update = true;
    }
    else
    {
        bucket = kzalloc(sizeof(struct h_node), GFP_ATOMIC);
    }

    bucket->data_length = data_length;
    bucket->key = id;
    bucket->data = (void *)kmalloc(data_length, GFP_ATOMIC);
    memcpy(bucket->data, data, data_length);

    if (!update)
    {
        hash_add(module_table, &bucket->node, id);
        // Since linux hashtable always appends the new element to the bucket ignoring key collision altogether
        // so it is safe to increase our element tracker as well once the add function succeeds.
        HASH_TABLE_ELEMENTS++;
    }
}

// keys_from_module_hashtable function is not thread safe
void keys_from_module_hashtable(const char *module, void **data, i32 *data_length, void *mem)
{
    int keys[HASH_TABLE_ELEMENTS];
    struct h_node *cur;
    unsigned i;
    unsigned j = 0;
    hash_for_each(module_table, i, cur, node)
    {
        keys[j++] = cur->key;
    }

    wasm_vm_result result = wasm_vm_malloc(this_cpu_wasm_vm(), module, HASH_TABLE_ELEMENTS);
    if (result.err)
    {
        pr_err("nasp: hashtable keys allocation failed");
        return;
    }

    i32 wasm_mem_ptr = result.data[0].i32;
    void *hashmapKeys = mem + wasm_mem_ptr;
    memcpy(hashmapKeys, keys, sizeof(int) * HASH_TABLE_ELEMENTS);

    *data = wasm_mem_ptr;
    *data_length = HASH_TABLE_ELEMENTS;
}

// get_from_module_hashtable function is not thread safe
void get_from_module_hashtable(const char *module, i32 id, void **data, i32 *data_length, void *mem)
{
    struct h_node *cur = NULL;
    struct h_node *temp = NULL;

    hash_for_each_possible(module_table, cur, node, id)
    {
        temp = cur;
    }

    if (!temp)
    {
        return;
    }

    wasm_vm_result result = wasm_vm_malloc(this_cpu_wasm_vm(), module, temp->data_length);
    if (result.err)
    {
        pr_err("nasp: hashtable get allocation failed");
        return;
    }

    i32 wasm_mem_ptr = result.data[0].i32;

    void *lookedUpData = mem + wasm_mem_ptr;
    memcpy(lookedUpData, temp->data, temp->data_length);

    *data = wasm_mem_ptr;
    *data_length = temp->data_length;
}

// delete_from_module_hashtable function is not thread safe
void delete_from_module_hashtable(i32 id)
{
    // Look up the h_node for the given id
    struct h_node *cur = NULL;
    struct h_node *temp = NULL;
    hash_for_each_possible(module_table, cur, node, id)
    {
        temp = cur;
    }

    if (!temp)
    {
        return;
    }

    hash_del(&temp->node);
    HASH_TABLE_ELEMENTS--;

    kfree(temp->data);
    kfree(temp);
}
