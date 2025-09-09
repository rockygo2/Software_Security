#ifndef JS_SCOPE_H
#define JS_SCOPE_H

#include "js-codegen.h"
#include "js-tokenizer.h"

#define ALLOC(count, type) ((type *) alloc(count, sizeof(type), #type))

void *alloc(size_t count, size_t size, const char *name);

enum object_type {
	ot_function,
	ot_variable,
};

struct object {
	struct object *next;
	char name[IDENTIFIER_LEN_MAX + 1];
	enum object_type type;
	long var_index; /* negative=param, positive=local var */
	size_t func_paramcount;
	codeptr_t func_code;
};

struct scope {
	struct object *object_first;
	const struct scope *parent;
	long varcount;
	struct object *function;
};

struct object *function_create(struct scope *s, const char *name);
struct object *object_find(const struct scope *s, const char *name, long *func_boundaries_p);
void scope_cleanup(struct scope *s, struct codegen *cg);
struct object *scope_get_function(const struct scope *s);
void scope_init(struct scope *s, struct scope *parent, struct object *function);
struct object *variable_create(struct scope *s, const char *name, long index);

#endif /* !defined(JS_SCOPE_H) */
