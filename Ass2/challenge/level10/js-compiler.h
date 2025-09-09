#include "js-codegen.h"
#include "js-scope.h"
#include "js-tokenizer.h"

void create_builtin_functions(struct codegen *cg, struct scope *s);
void parse_statement(struct tokenizer *t, struct codegen *cg, struct scope *s);
