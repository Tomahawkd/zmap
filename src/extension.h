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

probe_module_t *get_probe_module_by_name(const char *);
void print_probe_modules(void);

output_module_t *get_output_module_by_name(const char *);

void print_output_modules(void);



#endif //ZMAP_INTERNAL_EXTENSION_H
