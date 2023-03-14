/*
 * The MIT License (MIT)
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <linux/hashtable.h>

#include "runtime.h"

#define MODULE_HASH_BITS 10

struct h_node
{
    void *data;
    int key;
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
        printk("wasm: duplicate key (%d) found in hashmap, overwriting", id);
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
void keys_from_module_hashtable(const char *module, void **data, i32 *data_length)
{
    int keys[HASH_TABLE_ELEMENTS];
    struct h_node *cur;
    unsigned i;
    unsigned j = 0;
    hash_for_each(module_table, i, cur, node)
    {
        keys[j++] = cur->key;
    }

    uint8_t *mem = wasm_vm_memory(this_cpu_wasm_vm()); // TODO don't call current_wasm_vm here again, it might be different

    wasm_vm_result result = wasm_vm_malloc(this_cpu_wasm_vm(), module, HASH_TABLE_ELEMENTS);
    if (result.err)
    {
        pr_err("wasm: hashtable keys allocation failed");
        return;
    }

    i32 wasm_mem_ptr = result.data[0].i32;
    void *hashmapKeys = mem + wasm_mem_ptr;
    memcpy(hashmapKeys, keys, sizeof(int) * HASH_TABLE_ELEMENTS);

    *data = wasm_mem_ptr;
    *data_length = HASH_TABLE_ELEMENTS;
}

// get_from_module_hashtable function is not thread safe
void get_from_module_hashtable(const char *module, i32 id, void **data, i32 *data_length)
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

    uint8_t *mem = wasm_vm_memory(this_cpu_wasm_vm()); // TODO don't call current_wasm_vm here again, it might be different

    wasm_vm_result result = wasm_vm_malloc(this_cpu_wasm_vm(), module, temp->data_length);
    if (result.err)
    {
        pr_err("wasm: hashtable get allocation failed");
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
