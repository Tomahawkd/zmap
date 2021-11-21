//
// Created by ghost on 11/20/21.
//

#include <string.h>
#include "array.h"

#include "xalloc.h"

ARRAY *create_array(int type_size, int capacity) {
	ARRAY *new_array = xmalloc(sizeof(ARRAY));
	new_array->content = xmalloc(type_size * capacity);
	new_array->type_size = type_size;
	new_array->capacity = capacity;
	new_array->size = 0;
	return new_array;
}

int add_item(ARRAY* array, void *item) {
	array->content[array->size] = item;
	array->size++;

	if (array->size == array->capacity) {
		array->content = xrealloc(array->content, array->type_size * array->capacity * 2);
		return -1;
	}

	return 0;
}

void free_array(ARRAY *array) {
	if (!array) return;
	if (array->content) {
		xfree(array->content);
		array->content = NULL;
	}
	xfree(array);
}
