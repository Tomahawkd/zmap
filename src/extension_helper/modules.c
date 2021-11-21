//
// Created by ghost on 11/20/21.
//

#include "api/modules.h"
#include "extension.h"
#include "xalloc.h"
#include "logger.h"
#include "array.h"
#include "output_modules/module_list.h"
#include "probe_modules/module_list.h"

#include <dlfcn.h>

static void *lib_pointer = NULL;
static void (*load_ext)(void);
static void (*unload_ext)(void);
static ARRAY *probe_modules = NULL;
static ARRAY* output_modules = NULL;

void init_modules() {

	probe_module_t *internal_probe_modules[] = {
	    MODULE_TCP_SYNSCAN(), MODULE_TCP_SYNACKSCAN(), MODULE_ICMP_ECHO(),
	    MODULE_ICMP_ECHO_TIME(), MODULE_UDP(), MODULE_NTP(), MODULE_UPNP(), MODULE_DNS(),
	    MODULE_BACNET(),
	};

	output_module_t *internal_output_modules[] = {
	    MODULE_CSV(),
	    MODULE_JSON(),
	};

	probe_modules = new_array(sizeof(probe_module_t*), 16);
	output_modules = new_array(sizeof(output_module_t*), 8);

	add_probe_modules(internal_probe_modules, 9);
	add_output_modules(internal_output_modules, 2);
}

void add_probe_modules(probe_module_t **modules, int num) {
	int i;
	for (i = 0; i < num; ++i) {
		add_item(probe_modules, modules[i]);
	}
}

probe_module_t *get_probe_module_by_name(const char *name)
{
	int len = probe_modules->size;
	probe_module_t **arr = (probe_module_t **)probe_modules->content;
	for (int i = 0; i < len; i++) {
		if (!strcmp(arr[i]->name, name)) {
			return arr[i];
		}
	}
	return NULL;
}

void print_probe_modules(void)
{
	int len = probe_modules->size;
	probe_module_t **arr = (probe_module_t **)probe_modules->content;
	for (int i = 0; i < len; i++) {
		printf("%s\n", arr[i]->name);
	}
}

void add_output_modules(output_module_t **modules, int num) {
	int i;
	for (i = 0; i < num; ++i) {
		add_item(output_modules, modules[i]);
	}
}

output_module_t *get_output_module_by_name(const char *name)
{
	int num_modules = output_modules->size;
	output_module_t **arr = (output_module_t **)output_modules->content;
	for (int i = 0; i < num_modules; i++) {
		if (!strcmp(arr[i]->name, name)) {
			return arr[i];
		}
	}
	return NULL;
}

void print_output_modules(void)
{
	int num_modules = output_modules->size;
	output_module_t **arr = (output_module_t **)output_modules->content;
	for (int i = 0; i < num_modules; i++) {
		printf("%s\n", arr[i]->name);
	}
}

int load_library(const char* path) {

	FILE *lib;

	if (!path) {
		log_error("extension", "library path is null");
		return EXIT_FAILURE;
	}

	lib = fopen(path, "rb");
	if (!lib) {
		log_error("extension", "could not open library %s", path);
		return EXIT_FAILURE;
	}

	lib_pointer = dlopen(path, RTLD_NOW);
	if (!lib_pointer) {
		log_error("extension", "library open failed: %s", dlerror());
		return EXIT_FAILURE;
	}

	load_ext = (void(*)(void)) dlsym(lib_pointer, INIT_FUNCTION_NAME);
	unload_ext = (void(*)(void)) dlsym(lib_pointer, DEINIT_FUNCTION_NAME);

	if (load_ext == NULL || unload_ext == NULL) {
		log_error("extension", "cannot found enter and exit function");
		return EXIT_FAILURE;
	}

	load_ext();
	return EXIT_SUCCESS;
}

void close_library() {
	if (lib_pointer) {
		dlclose(lib_pointer);
		lib_pointer = NULL;
	}
}

void free_modules() {
	if (probe_modules) {
		free_array(probe_modules);
	}

	if (output_modules) {
		free_array(output_modules);
	}

	unload_ext();
}
