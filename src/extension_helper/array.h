//
// Created by ghost on 11/20/21.
//

#ifndef ZMAP_ARRAY_H
#define ZMAP_ARRAY_H

typedef struct array_t {
	void **content;
	int type_size;
	int capacity;
	int size;
} ARRAY;

ARRAY *create_array(int type_size, int capacity);

int add_item(ARRAY*, void *);

void free_array(ARRAY *);

#endif //ZMAP_ARRAY_H
