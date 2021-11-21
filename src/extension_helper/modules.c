//
// Created by ghost on 11/20/21.
//

#include "api/modules.h"
#include "extension.h"
#include "xalloc.h"
#include "logger.h"
#include "arraylist.h"
#include "output_modules/module_list.h"
#include "probe_modules/module_list.h"

#include <dlfcn.h>

static void *lib_pointer = NULL;
static void (*load_ext)(void);
static void (*unload_ext)(void);

// use json-c's arraylist
static array_list *probe_modules = NULL;
static array_list *output_modules = NULL;

// dont need to free modules
void fn_free_module(UNUSED void *data) {}

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

	probe_modules = array_list_new(fn_free_module);
	output_modules = array_list_new(fn_free_module);

	add_probe_modules(internal_probe_modules, 9);
	add_output_modules(internal_output_modules, 2);
}

#define MODULE_FUNCTION_IMPL(NAME) \
void add_##NAME##s(NAME##_t **modules, int num) { \
	int i; \
	for (i = 0; i < num; ++i) { \
		array_list_add(NAME##s, modules[i]); \
	} \
}                             \
NAME##_t *get_##NAME##_by_name(const char *name) { \
	array_list *arr = NAME##s; \
	size_t len = arr->length; \
        size_t i; \
	for (i = 0; i < len; i++) { \
		NAME##_t *m = (NAME##_t *) array_list_get_idx(arr, i); \
		if (!strcmp(m->name, name)) { \
			return m; \
		} \
	} \
	return NULL; \
}                             \
void print_##NAME##s(void) {  \
	array_list *arr = NAME##s; \
	size_t len = arr->length; \
	size_t i; \
	for (i = 0; i < len; i++) { \
		NAME##_t *m = (NAME##_t *) array_list_get_idx(arr, i); \
		printf("%s\n", m->name); \
	}\
}

MODULE_FUNCTION_IMPL(probe_module)
MODULE_FUNCTION_IMPL(output_module)

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
		array_list_free(probe_modules);
	}

	if (output_modules) {
		array_list_free(output_modules);
	}

	unload_ext();
}
