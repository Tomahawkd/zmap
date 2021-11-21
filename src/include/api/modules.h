//
// Created by ghost on 11/20/21.
//

#ifndef ZMAP_MODULES_H
#define ZMAP_MODULES_H

#include "output_modules.h"
#include "probe_modules.h"

void add_probe_modules(probe_module_t **modules, int num);

void add_output_modules(output_module_t **modules, int num);

#define INIT_FUNCTION_NAME "load_extension"
#define DEINIT_FUNCTION_NAME "unload_extension"
#define INIT_FUNCTION void load_extension
#define DEINIT_FUNCTION void unload_extension

#endif //ZMAP_MODULES_H
