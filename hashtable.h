#pragma once

void add_to_module_hashtable(i32, void *, i32);
void get_from_module_hashtable(const char *module, i32, void **, i32 *);
void delete_from_module_hashtable(i32);
void keys_from_module_hashtable(const char *module, void **data, i32 *data_length);
