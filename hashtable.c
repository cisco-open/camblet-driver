#include<linux/slab.h>
#include <linux/hashtable.h>
#include <linux/types.h>

#include "runtime.h"

#define MODULE_HASH_BITS   10

struct h_node {
    void* data;
    int key;
    int data_length;
    struct hlist_node node;
};

static DEFINE_HASHTABLE(module_table, MODULE_HASH_BITS);
static int HASH_TABLE_ELEMENTS = 0;

// add_to_module_hashtable function is not thread safe
void add_to_module_hashtable(i32 id, void* data, i32 data_length) {
    // Since linux hashtable always appends the new element to the bucket ignoring key collision altogether
    // we have to check whether an item with the key is already present in the map.
    // If it does we must handle that with raising an error.
    struct h_node *cur;

    struct h_node *possible_duplicate_data;

    hash_for_each_possible(module_table, cur, node, id) {
        possible_duplicate_data = cur;
    }
    if (!possible_duplicate_data) {
        printk("ERROR: Duplicate key found in hashmap, ignoring");
        return;
    }

    struct h_node *bucket = kmalloc(sizeof(struct h_node), GFP_KERNEL);

    void *stored_data = (void *)kmalloc(data_length, GFP_KERNEL);

    memcpy(stored_data, data, data_length);

    bucket->data = stored_data;
    bucket->data_length = data_length;
    bucket->key = id;

    hash_add(module_table, &bucket->node, id);
    //Since linux hashtable always appends the new element to the bucket ignoring key collision altogether
    // so it is safe to increase our element tracker as well once the add function succeeds.
    HASH_TABLE_ELEMENTS++;
}

// keys_from_module_hashtable function is not thread safe
void keys_from_module_hashtable(void** data, i32* data_length) {

    int keys[HASH_TABLE_ELEMENTS];
    struct h_node *cur;
    unsigned i;
    unsigned j = 0;
    hash_for_each(module_table, i, cur, node) {
        keys[j] = cur->key;
        j++;
    }

    // Get the Runtime memory
    uint8_t *mem = repl_get_memory();

    i32 wasm_mem_ptr = wasm_malloc(HASH_TABLE_ELEMENTS);
    void* hashmapKeys = mem + wasm_mem_ptr;
    memcpy(hashmapKeys, keys, HASH_TABLE_ELEMENTS);

    *data = wasm_mem_ptr;
    *data_length = HASH_TABLE_ELEMENTS;
}

// get_from_module_hashtable function is not thread safe
void get_from_module_hashtable(i32 id, void** data, i32* data_length) {
    struct h_node *cur;
    struct h_node *temp;

    hash_for_each_possible(module_table, cur, node, id) {
        temp = cur;
    }

    // Get the Runtime memory
    uint8_t *mem = repl_get_memory();

    i32 wasm_mem_ptr = wasm_malloc(temp->data_length);

    void* lookedUpData = mem + wasm_mem_ptr;
    memcpy(lookedUpData, temp->data, temp->data_length);

    *data = wasm_mem_ptr;
    *data_length = temp->data_length;
}

// delete_from_module_hashtable function is not thread safe
void delete_from_module_hashtable(i32 id) {
    // Look up the h_node for the given id
    struct h_node *cur;
    struct h_node *temp;
    hash_for_each_possible(module_table, cur, node, id) {
        temp = cur;
    }
    hash_del(&temp->node);
    HASH_TABLE_ELEMENTS--;

    kfree(temp->data);
    kfree(temp);
}





