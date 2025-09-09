#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "js-expressions.h"

struct parse_expression_state {
	struct tokenizer *t;
	struct codegen *cg;
	const struct scope *s;
	int have_pointer;
};

static void parse_expression_level_assign(struct parse_expression_state *s);
static void parse_expression_level_comma(struct parse_expression_state *s);

static void load_if_needed(struct parse_expression_state *s) {
	if (s->have_pointer) {
		codegen_load(s->cg);
		s->have_pointer = 0;
	}
}

static void parse_expression_arguments_length(struct parse_expression_state *s, const struct object *function) {

	if (s->t->type != tt_dot) fail(s->t, "dot missing");
	tokenizer_read(s->t);

	if (s->t->type != tt_identifier) fail(s->t, "member specification missing");
	if (strcmp(s->t->text, "length") != 0) fail(s->t, "unknown member of arguments object");
	tokenizer_read(s->t);

	codegen_immediate(s->cg, function->func_paramcount);
	s->have_pointer = 0;
}

static void parse_expression_arguments(struct parse_expression_state *s) {
	const struct object *function;

	function = scope_get_function(s->s);
	if (!function) fail(s->t, "arguments not available outside function");

	if (s->t->type != tt_arguments) fail(s->t, "arguments keyword missing");
	tokenizer_read(s->t);

	if (s->t->type == tt_dot) {
		parse_expression_arguments_length(s, function);
		return;
	}

	if (s->t->type != tt_bracket_open) fail(s->t, "arguments index missing");
	tokenizer_read(s->t);

	parse_expression_level_assign(s);

	if (s->t->type != tt_bracket_close) fail(s->t, "closing bracket missing");
	tokenizer_read(s->t);

	load_if_needed(s);
	codegen_arg_get_ptr_by_index(s->cg, function->func_paramcount);
	s->have_pointer = 1;
}

static void parse_expression_call(struct parse_expression_state *s, const struct object *object) {
	size_t paramcount = 0;

	if (!object || object->type != ot_function) fail(s->t, "function not declared");

	if (s->t->type != tt_paren_open) fail(s->t, "open parenthesis missing");
	tokenizer_read(s->t);

	if (s->t->type != tt_paren_close) {
		for (;;) {
			parse_expression_level_assign(s);
			load_if_needed(s);
			codegen_push(s->cg);
			paramcount++;

			if (s->t->type != tt_comma) break;
			tokenizer_read(s->t);
		}
	}

	if (paramcount != object->func_paramcount) fail(s->t, "incorrect number of parameters");

	if (s->t->type != tt_paren_close) fail(s->t, "close parenthesis missing");
	tokenizer_read(s->t);

	codegen_call(s->cg, object->func_code, paramcount);
	s->have_pointer = 0;
}

static void parse_expression_identifier(struct parse_expression_state *s) {
	long func_boundaries;
	const struct object *object;

	if (s->t->type != tt_identifier) fail(s->t, "identifier missing");
	object = object_find(s->s, s->t->text, &func_boundaries);
	tokenizer_read(s->t);

	if (s->t->type == tt_paren_open) {
		parse_expression_call(s, object);
		return;
	}

	if (!object || object->type != ot_variable) fail(s->t, "variable not declared");

	codegen_var_get_ptr(s->cg, object->var_index, func_boundaries);
	s->have_pointer = 1;
}

static void parse_expression_number(struct parse_expression_state *s) {
	char *endptr;
	long value;

	if (s->t->type != tt_number) fail(s->t, "number missing");
	errno = 0;
	if (s->t->text[0] == '0' && (s->t->text[1] == 'b' || s->t->text[1] == 'B')) {
		value = strtol(s->t->text + 2, &endptr, 2);
	} else {
		value = strtol(s->t->text, &endptr, 0);
	}
	if (endptr != s->t->text + strlen(s->t->text)) fail(s->t, "bad numberic constant");
	if (errno) fail(s->t, "number out of range");
	tokenizer_read(s->t);

	codegen_immediate(s->cg, value);
	s->have_pointer = 0;
}

static void parse_expression_paren(struct parse_expression_state *s) {
	if (s->t->type != tt_paren_open) fail(s->t, "open parenthesis missing");
	tokenizer_read(s->t);

	parse_expression_level_comma(s);

	if (s->t->type != tt_paren_close) fail(s->t, "close parenthesis missing");
	tokenizer_read(s->t);
}

static void parse_expression_basic(struct parse_expression_state *s) {
	switch (s->t->type) {
	case tt_arguments:  parse_expression_arguments(s);  return;
	case tt_identifier: parse_expression_identifier(s); return;
	case tt_number:     parse_expression_number(s);     return;
	case tt_paren_open: parse_expression_paren(s);      return;
	default:            fail(s->t, "expression missing");         return;
	}
}

static void parse_expression_level_postfix(struct parse_expression_state *s) {
	long delta;

	parse_expression_basic(s);
	
	switch (s->t->type) {
	case tt_op_dec:     delta = -1; break;
	case tt_op_inc:     delta = 1;  break;
	default:                        return;
	}
	tokenizer_read(s->t);

	if (!s->have_pointer) fail(s->t, "increment/decrement of non-lvalue");

	codegen_load(s->cg);
	codegen_push(s->cg);
	codegen_push(s->cg);
	codegen_immediate(s->cg, delta);
	codegen_op_binary(s->cg, cob_add);
	codegen_store(s->cg);
	codegen_pop(s->cg);
	s->have_pointer = 0;
}

static void parse_expression_level_unary(struct parse_expression_state *s) {
	long delta = 0;
	enum codegen_op_unary op = cou_none;
	switch (s->t->type) {
	case tt_op_add:                                        break;
	case tt_op_bnot:    op = cou_bnot;                     break;
	case tt_op_dec:     delta = -1;                        break;
	case tt_op_inc:     delta = 1;                         break;
	case tt_op_not:     op = cou_not;                      break;
	case tt_op_sub:     op = cou_neg;                      break;
	default:            parse_expression_level_postfix(s); return;
	}
	tokenizer_read(s->t);
	parse_expression_level_unary(s);
	if (op != cou_none) {
		load_if_needed(s);
		codegen_op_unary(s->cg, op);
	}
	if (delta) {
		if (!s->have_pointer) fail(s->t, "increment/decrement of non-lvalue");

		codegen_load(s->cg);
		codegen_push(s->cg);
		codegen_immediate(s->cg, delta);
		codegen_op_binary(s->cg, cob_add);
		codegen_store(s->cg);
		s->have_pointer = 0;
	}
}

static void parse_expression_level_multiplicative(struct parse_expression_state *s) {
	enum codegen_op_binary op;

	parse_expression_level_unary(s);
	for (;;) {
		switch (s->t->type) {
		case tt_op_mul: op = cob_mul; break;
		case tt_op_mod: op = cob_mod; break;
		case tt_op_div: op = cob_div; break;
		default:                      return;
		}
		tokenizer_read(s->t);
		load_if_needed(s);
		codegen_push(s->cg);
		parse_expression_level_unary(s);
		load_if_needed(s);
		codegen_op_binary(s->cg, op);
	}
}

static void parse_expression_level_additive(struct parse_expression_state *s) {
	enum codegen_op_binary op;

	parse_expression_level_multiplicative(s);
	for (;;) {
		switch (s->t->type) {
		case tt_op_add: op = cob_add; break;
		case tt_op_sub: op = cob_sub; break;
		default:                      return;
		}
		tokenizer_read(s->t);
		load_if_needed(s);
		codegen_push(s->cg);
		parse_expression_level_multiplicative(s);
		load_if_needed(s);
		codegen_op_binary(s->cg, op);
	}
}

static void parse_expression_level_shift(struct parse_expression_state *s) {
	enum codegen_op_binary op;

	parse_expression_level_additive(s);
	for (;;) {
		switch (s->t->type) {
		case tt_op_shl: op = cob_shl; break;
		case tt_op_shr: op = cob_shr; break;
		default:                      return;
		}
		tokenizer_read(s->t);
		load_if_needed(s);
		codegen_push(s->cg);
		parse_expression_level_additive(s);
		load_if_needed(s);
		codegen_op_binary(s->cg, op);
	}
}

static void parse_expression_level_comparison(struct parse_expression_state *s) {
	enum codegen_condition condition;

	parse_expression_level_shift(s);
	for (;;) {
		switch (s->t->type) {
		case tt_cmp_ge: condition = cc_ge; break;
		case tt_cmp_gt: condition = cc_gt; break;
		case tt_cmp_le: condition = cc_le; break;
		case tt_cmp_lt: condition = cc_lt; break;
		default:                           return;
		}
		tokenizer_read(s->t);
		load_if_needed(s);
		codegen_push(s->cg);
		parse_expression_level_shift(s);
		load_if_needed(s);
		codegen_compare(s->cg, condition);
	}
}

static void parse_expression_level_equality(struct parse_expression_state *s) {
	enum codegen_condition condition;

	parse_expression_level_comparison(s);
	for (;;) {
		switch (s->t->type) {
		case tt_cmp_eq: condition = cc_eq; break;
		case tt_cmp_ne: condition = cc_ne; break;
		default:                           return;
		}
		tokenizer_read(s->t);
		load_if_needed(s);
		codegen_push(s->cg);
		parse_expression_level_comparison(s);
		load_if_needed(s);
		codegen_compare(s->cg, condition);
	}
}

static void parse_expression_level_band(struct parse_expression_state *s) {
	parse_expression_level_equality(s);
	while (s->t->type == tt_op_band) {
		tokenizer_read(s->t);
		load_if_needed(s);
		codegen_push(s->cg);
		parse_expression_level_equality(s);
		load_if_needed(s);
		codegen_op_binary(s->cg, cob_band);
	}
}

static void parse_expression_level_bxor(struct parse_expression_state *s) {
	parse_expression_level_band(s);
	while (s->t->type == tt_op_bxor) {
		tokenizer_read(s->t);
		load_if_needed(s);
		codegen_push(s->cg);
		parse_expression_level_band(s);
		load_if_needed(s);
		codegen_op_binary(s->cg, cob_bxor);
	}
}

static void parse_expression_level_bor(struct parse_expression_state *s) {
	parse_expression_level_bxor(s);
	while (s->t->type == tt_op_bor) {
		tokenizer_read(s->t);
		load_if_needed(s);
		codegen_push(s->cg);
		parse_expression_level_bxor(s);
		load_if_needed(s);
		codegen_op_binary(s->cg, cob_bor);
	}
}

static void parse_expression_level_and(struct parse_expression_state *s) {
	codeptr_t jump;

	parse_expression_level_bor(s);
	while (s->t->type == tt_op_and) {
		tokenizer_read(s->t);
		load_if_needed(s);
		jump = codegen_jump_cond(s->cg, cc_eq, NULL);
		parse_expression_level_bor(s);
		codegen_patch_jump_cond(s->cg, jump, s->cg->codeptr);
	}
}

static void parse_expression_level_or(struct parse_expression_state *s) {
	codeptr_t jump;

	parse_expression_level_and(s);
	while (s->t->type == tt_op_or) {
		tokenizer_read(s->t);
		load_if_needed(s);
		jump = codegen_jump_cond(s->cg, cc_ne, NULL);
		parse_expression_level_and(s);
		codegen_patch_jump_cond(s->cg, jump, s->cg->codeptr);
	}
}

static void parse_expression_level_conditional(struct parse_expression_state *s) {
	codeptr_t jump_else, jump_end;

	parse_expression_level_or(s);

	if (s->t->type != tt_op_cond) return;
	tokenizer_read(s->t);

	load_if_needed(s);
	jump_else = codegen_jump_cond(s->cg, cc_eq, NULL);
	parse_expression_level_conditional(s);
	jump_end = codegen_jump(s->cg, NULL);

	if (s->t->type != tt_colon) return;

	tokenizer_read(s->t);

	codegen_patch_jump_cond(s->cg, jump_else, s->cg->codeptr);
	parse_expression_level_conditional(s);
	codegen_patch_jump(s->cg, jump_end, s->cg->codeptr);
}

static int is_assignment(enum tokentype type, enum codegen_op_binary *op) {
	switch (type) {
	case tt_asg_add:  *op = cob_add;  return 1;
	case tt_asg_band: *op = cob_band; return 1;
	case tt_asg_bor:  *op = cob_bor;  return 1;
	case tt_asg_bxor: *op = cob_bxor; return 1;
	case tt_asg_div:  *op = cob_div;  return 1;
	case tt_asg_mod:  *op = cob_mod;  return 1;
	case tt_asg_mul:  *op = cob_mul;  return 1;
	case tt_asg_sub:  *op = cob_sub;  return 1;
	case tt_assign:   *op = cob_none; return 1;
	default:          *op = cob_none; return 0;
	}
}

static void parse_expression_level_assign(struct parse_expression_state *s) {
	enum codegen_op_binary op;

	parse_expression_level_conditional(s);

	if (!is_assignment(s->t->type, &op)) return;
	tokenizer_read(s->t);

	if (!s->have_pointer) fail(s->t, "assignment to non-lvalue");

	codegen_push_ptr(s->cg);
	if (op != cob_none) {
		codegen_load(s->cg);
		codegen_push(s->cg);
	}

	parse_expression_level_assign(s);

	if (op != cob_none) {
		load_if_needed(s);
		codegen_op_binary(s->cg, op);
	}

	load_if_needed(s);
	codegen_pop_ptr(s->cg);
	codegen_store(s->cg);
}

static void parse_expression_level_comma(struct parse_expression_state *s) {
	for (;;) {
		parse_expression_level_assign(s);
		if (s->t->type != tt_comma) break;
		tokenizer_read(s->t);
	}
}

void parse_expression(struct tokenizer *t, struct codegen *cg, const struct scope *s, int allow_comma) {
	struct parse_expression_state state = {
		.t = t,
		.cg = cg,
		.s = s,
	};

	/* see https://msdn.microsoft.com/en-us/library/z3ks45k7(v=vs.94).aspx for operator precedence */
	if (allow_comma) {
		parse_expression_level_comma(&state);
	} else {
		parse_expression_level_assign(&state);
	}
	load_if_needed(&state);
}
