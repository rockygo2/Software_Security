#ifndef JS_TOKENIZER_H
#define JS_TOKENIZER_H

#include <stdio.h>

#define IDENTIFIER_LEN_MAX 127
#define FUNCTION_PARAMS_MAX 8

enum tokentype {
	tt_eof,
	tt_arguments,
	tt_asg_add,
	tt_asg_band,
	tt_asg_bor,
	tt_asg_bxor,
	tt_asg_div,
	tt_asg_mod,
	tt_asg_mul,
	tt_asg_sub,
	tt_assign,
	tt_brace_close,
	tt_brace_open,
	tt_bracket_close,
	tt_bracket_open,
	tt_cmp_eq,
	tt_cmp_ge,
	tt_cmp_gt,
	tt_cmp_le,
	tt_cmp_lt,
	tt_cmp_ne,
	tt_colon,
	tt_comma,
	tt_debugger,
	tt_do,
	tt_dot,
	tt_else,
	tt_for,
	tt_function,
	tt_identifier,
	tt_if,
	tt_number,
	tt_op_add,
	tt_op_and,
	tt_op_band,
	tt_op_bnot,
	tt_op_bor,
	tt_op_bxor,
	tt_op_cond,
	tt_op_dec,
	tt_op_div,
	tt_op_inc,
	tt_op_mod,
	tt_op_mul,
	tt_op_not,
	tt_op_or,
	tt_op_shl,
	tt_op_shr,
	tt_op_sub,
	tt_paren_close,
	tt_paren_open,
	tt_return,
	tt_semicolon,
	tt_var,
	tt_while,
};

struct tokenizer {
	FILE *file;
	int c;
	int line;
	int col;
	enum tokentype type;
	char text[IDENTIFIER_LEN_MAX + 1];
};

void fail(const struct tokenizer *t, const char *description);
void tokenizer_init(struct tokenizer *t, FILE *file);
void tokenizer_read(struct tokenizer *t);

#endif /* !defined(JS_TOKENIZER_H) */
