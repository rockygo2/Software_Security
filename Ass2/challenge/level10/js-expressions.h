#include "js-codegen.h"
#include "js-scope.h"
#include "js-tokenizer.h"

void parse_expression(struct tokenizer *t, struct codegen *cg, const struct scope *s, int allow_comma);
