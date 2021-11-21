//
// Created by ghost on 11/20/21.
//

#ifndef ZMAP_INTERNAL_EXTENSION_H
#define ZMAP_INTERNAL_EXTENSION_H

#include "api/modules.h"

void init_modules();

int load_library(const char* path);

void close_library();

void free_modules();

#define MODULE_FUNCTION_HDR(NAME) \
NAME##_t *get_##NAME##_by_name(const char *name); \
void print_##NAME##s(void);

MODULE_FUNCTION_HDR(probe_module)
MODULE_FUNCTION_HDR(output_module)

#endif //ZMAP_INTERNAL_EXTENSION_H
