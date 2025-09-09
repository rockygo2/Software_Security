#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "js-tokenizer.h"

void fail(const struct tokenizer *t, const char *description) {
	fprintf(stderr, "error: %s at \"%s\" (%d:%d)\n",
		description, t->text, t->line, t->col);
	exit(1);
}

static int char_read(struct tokenizer *t) {
	t->c = fgetc(t->file);
	if (t->c == '\n') {
		t->line++;
		t->col = 0;
	} else {
		t->col++;
	}
	return t->c;
}

void tokenizer_init(struct tokenizer *t, FILE *file) {
	memset(t, 0, sizeof(*t));
	t->file = file;
	t->line = 1;
	t->c = fgetc(file);
}

static void tokenizer_read_identifier(struct tokenizer *t) {
	size_t len = 0;
	do {
		if (len >= IDENTIFIER_LEN_MAX) {
			fprintf(stderr, "identifier too long "
				"at %d:%d\n", t->line, t->col);
			exit(1);
		}
		t->text[len++] = t->c;
		char_read(t);
	} while (isalnum(t->c) || t->c == '_');
	t->text[len] = 0;

	if (strcmp(t->text, "arguments") == 0) {
		t->type = tt_arguments;
	} else if (strcmp(t->text, "debugger") == 0) {
		t->type = tt_debugger;
	} else if (strcmp(t->text, "do") == 0) {
		t->type = tt_do;
	} else if (strcmp(t->text, "else") == 0) {
		t->type = tt_else;
	} else if (strcmp(t->text, "for") == 0) {
		t->type = tt_for;
	} else if (strcmp(t->text, "function") == 0) {
		t->type = tt_function;
	} else if (strcmp(t->text, "if") == 0) {
		t->type = tt_if;
	} else if (strcmp(t->text, "return") == 0) {
		t->type = tt_return;
	} else if (strcmp(t->text, "var") == 0) {
		t->type = tt_var;
	} else if (strcmp(t->text, "while") == 0) {
		t->type = tt_while;
	} else {
		t->type = tt_identifier;
	}
}

static int isdigitwithbase(int c, int base) {
	int value;

	if (c >= '0' && c <= '9') {
		value = c - '0';
	} else if (c >= 'a' && c <= 'f') {
		value = c - 'a' + 10;
	} else if (c >= 'A' && c <= 'F') {
		value = c - 'A' + 10;
	} else {
		return 0;
	}

	return value < base;
}

static void tokenizer_read_number(struct tokenizer *t) {
	int base = 10;
	size_t len = 0;

	while (isdigitwithbase(t->c, base)) {
		if (len >= IDENTIFIER_LEN_MAX) {
			fprintf(stderr, "number too long "
				"at %d:%d\n", t->line, t->col);
			exit(1);
		}
		t->text[len++] = t->c;
		char_read(t);

		if (len == 1 && t->text[0] == '0') {
			if (t->c == 'x' || t->c == 'X') {
				base = 16;
				t->text[len++] = t->c;
				char_read(t);
			} else if (t->c == 'b' || t->c == 'B') {
				base = 2;
				t->text[len++] = t->c;
				char_read(t);
			} else {
				base = 8;
			}
		}
	}
	if ((base == 2 || base == 16) && len < 3) {
		fail(t, "numeric constant with no digits");
	}
	t->text[len] = 0;
	t->type = tt_number;
}

static void read_op2(struct tokenizer *t, char c2, enum tokentype type1, enum tokentype type2) {
	if (t->c == c2) {
		t->type = type2;
		t->text[1] = t->c;
		t->text[2] = 0;
		char_read(t);
	} else {
		t->type = type1;
	}
}

static void read_op3(struct tokenizer *t, char c2, char c3, enum tokentype type1, enum tokentype type2, enum tokentype type3) {
	if (t->c == c2 || t->c == c3) {
		t->type = (t->c == c2) ? type2 : type3;
		t->text[1] = t->c;
		t->text[2] = 0;
		char_read(t);
	} else {
		t->type = type1;
	}
}

static void tokenizer_read_comment_single_line(struct tokenizer *t) {
	while (t->c != EOF && t->c != '\n') {
		char_read(t);
	};
	char_read(t);
}

static void tokenizer_read_comment_multi_line(struct tokenizer *t) {
	int c;
	do {
		c = t->c;
		char_read(t);
	} while (t->c != EOF && (c != '*' || t->c != '/'));
	char_read(t);
}

void tokenizer_read(struct tokenizer *t) {
	int c;

	for (;;) {
		/* handle whitespace */
		while (isspace(t->c)) char_read(t);

		/* some special cases */
		if (t->c == EOF) {
			t->text[0] = 0;
			t->type = tt_eof;
			return;
		}

		if (isalpha(t->c) || t->c == '_') {
			tokenizer_read_identifier(t);
			return;
		}

		if (isdigit(t->c)) {
			tokenizer_read_number(t);
			return;
		}

		/* single/double character tokens */
		t->text[0] = c = t->c;
		t->text[1] = 0;
		char_read(t);
		switch (c) {
		case '=': read_op2(t, '=',      tt_assign,  tt_cmp_eq);              return;
		case '{': t->type =             tt_brace_open;                       return;
		case '}': t->type =             tt_brace_close;                      return;
		case '[': t->type =             tt_bracket_open;                     return;
		case ']': t->type =             tt_bracket_close;                    return;
		case '>': read_op3(t, '=', '>', tt_cmp_gt,  tt_cmp_ge, tt_op_shr);   return;
		case '<': read_op3(t, '=', '<', tt_cmp_lt,  tt_cmp_le, tt_op_shl);   return;
		case ':': t->type =             tt_colon;                            return;
		case ',': t->type =             tt_comma;                            return;
		case '.': t->type =             tt_dot;                              return;
		case '+': read_op3(t, '+', '=', tt_op_add,  tt_op_inc, tt_asg_add);  return;
		case '&': read_op3(t, '&', '=', tt_op_band, tt_op_and, tt_asg_band); return;
		case '~': t->type =             tt_op_bnot;                          return;
		case '|': read_op3(t, '|', '=', tt_op_bor,  tt_op_or,  tt_asg_bor);  return;
		case '^': read_op2(t, '=',      tt_op_bxor, tt_asg_bxor);            return;
		case '?': t->type =             tt_op_cond;                          return;
		case '%': read_op2(t, '=',      tt_op_mod,  tt_asg_mod);             return;
		case '*': read_op2(t, '=',      tt_op_mul,  tt_asg_mul);             return;
		case '!': read_op2(t, '=',      tt_op_not,  tt_cmp_ne);              return;
		case '-': read_op3(t, '-', '=', tt_op_sub,  tt_op_dec, tt_asg_sub);  return;
		case '(': t->type =             tt_paren_open;                       return;
		case ')': t->type =             tt_paren_close;                      return;
		case ';': t->type =             tt_semicolon;                        return;
		case '/':
			if (t->c == '/') {
				char_read(t);
				tokenizer_read_comment_single_line(t);
				continue;
			} else if (t->c == '*') {
				char_read(t);
				tokenizer_read_comment_multi_line(t);
				continue;
			} else {
				read_op2(t, '=', tt_op_div, tt_asg_div);
				return;
			}
		default:
			fprintf(stderr, "unexpected character #%d at %d:%d\n",
				t->c, t->line, t->col);
			exit(1);
		}
	}
}
