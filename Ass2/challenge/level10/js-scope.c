#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "js-scope.h"

#define ALLOC(count, type) ((type *) alloc(count, sizeof(type), #type))

void *alloc(size_t count, size_t size, const char *name) {
	void *p = calloc(count, size);
	if (!p) {
		fprintf(stderr, "error: failed to allocate %zu instances "
			"of %s: %s\n", count, name, strerror(errno));
		exit(-1);
	}
	return p;
}

struct object *function_create(struct scope *s, const char *name) {
	struct object *function = ALLOC(1, struct object);
	strcpy(function->name, name);
	function->type = ot_function;
	function->next = s->object_first;
	s->object_first = function;
	return function;
}

struct object *object_find(
	const struct scope *s,
	const char *name,
	long *func_boundaries_p) {
	struct object *object;

	*func_boundaries_p = 0;
	while (s) {
		for (object = s->object_first; object; object = object->next) {
			if (strcmp(name, object->name) == 0) {
				return object;
			}
		}
		if (s->function) *func_boundaries_p += 1;
		s = s->parent;
	}
	return NULL;
}

static void objects_free(struct object *objects) {
	struct object *object;

	while ((object = objects)) {
		objects = object->next;
		free(object);
	}
}

void scope_cleanup(struct scope *s, struct codegen *cg) {
	if (s->parent && !s->function) {
		codegen_var_dealloc(cg, s->varcount - s->parent->varcount);
	}
	objects_free(s->object_first);
}

struct object *scope_get_function(const struct scope *s) {
	while (s) {
		if (s->function) return s->function;
		s = s->parent;
	}
	return NULL;
}

void scope_init(struct scope *s, struct scope *parent, struct object *function) {
	memset(s, 0, sizeof(*s));
	s->parent = parent;
	if (parent && !function) s->varcount = parent->varcount;
	s->function = function;
}

struct object *variable_create(struct scope *s, const char *name, long index) {
	struct object *variable = ALLOC(1, struct object);
	strcpy(variable->name, name);
	variable->type = ot_variable;
	variable->var_index = index;
	variable->next = s->object_first;
	s->object_first = variable;
	return variable;
}
