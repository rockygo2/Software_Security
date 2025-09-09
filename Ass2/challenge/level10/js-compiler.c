#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "js-compiler.h"
#include "js-expressions.h"

static void parse_scope(struct tokenizer *t, struct codegen *cg, struct scope *s);
static void parse_var(struct tokenizer *t, struct codegen *cg, struct scope *s);

static void parse_debugger(struct tokenizer *t, struct codegen *cg, struct scope *s) {
	if (t->type != tt_debugger) fail(t, "debugger keyword missing");
	tokenizer_read(t);

	codegen_breakpoint(cg);

	if (t->type != tt_semicolon) fail(t, "semicolon missing after debugger statement");
	tokenizer_read(t);
}

static void parse_do_while(struct tokenizer *t, struct codegen *cg, struct scope *s) {
	codeptr_t body;
	struct scope scope;

	if (t->type != tt_do) fail(t, "do keyword missing");
	tokenizer_read(t);

	body = cg->codeptr;
	scope_init(&scope, s, NULL/*function*/);
	parse_statement(t, cg, &scope);
	scope_cleanup(&scope, cg);

	if (t->type != tt_while) fail(t, "while keyword missing after do...while");
	tokenizer_read(t);

	if (t->type != tt_paren_open) fail(t, "open parenthesis missing");
	tokenizer_read(t);

	parse_expression(t, cg, s, 1/*allow_comma*/);
	codegen_jump_cond(cg, cc_ne, body);

	if (t->type != tt_paren_close) fail(t, "close parenthesis missing");
	tokenizer_read(t);
}

static void parse_for(struct tokenizer *t, struct codegen *cg, struct scope *s) {
	codeptr_t controller, increment, jump_body, jump_end;
	struct scope scope;

	scope_init(&scope, s, NULL/*function*/);

	if (t->type != tt_for) fail(t, "for keyword missing");
	tokenizer_read(t);

	if (t->type != tt_paren_open) fail(t, "open parenthesis missing");
	tokenizer_read(t);

	if (t->type == tt_var) {
		parse_var(t, cg, &scope);
	} else {
		if (t->type != tt_semicolon) {
			parse_expression(t, cg, &scope, 1/*allow_comma*/);
		}
		if (t->type != tt_semicolon) fail(t, "semicolon missing");
		tokenizer_read(t);
	}

	controller = cg->codeptr;
	if (t->type == tt_semicolon) {
		jump_end = NULL;
	} else {
		parse_expression(t, cg, &scope, 1/*allow_comma*/);
		jump_end = codegen_jump_cond(cg, cc_eq, NULL);
	}
	jump_body = codegen_jump(cg, NULL);

	if (t->type != tt_semicolon) fail(t, "semicolon missing");
	tokenizer_read(t);

	increment = cg->codeptr;
	if (t->type != tt_paren_close) {
		parse_expression(t, cg, &scope, 1/*allow_comma*/);
	}
	codegen_jump(cg, controller);
	
	if (t->type != tt_paren_close) fail(t, "close parenthesis missing");
	tokenizer_read(t);

	codegen_patch_jump(cg, jump_body, cg->codeptr);
	parse_statement(t, cg, &scope);

	codegen_jump(cg, increment);
	if (jump_end) codegen_patch_jump_cond(cg, jump_end, cg->codeptr);

	scope_cleanup(&scope, cg);
}

static void parse_function(struct tokenizer *t, struct codegen *cg, struct scope *s) {
	struct object *function;
	codeptr_t jump;
	struct scope scope;
	size_t paramcount = 0;
	struct object *variable;

	/* parse function declaration */
	if (t->type != tt_function) fail(t, "function keyword not specified");
	tokenizer_read(t);

	if (t->type != tt_identifier) fail(t, "function name not specified");
	function = function_create(s, t->text);
	tokenizer_read(t);

	if (t->type != tt_paren_open) fail(t, "function parameter list not specified");
	tokenizer_read(t);

	scope_init(&scope, s, function);
	if (t->type == tt_identifier) {
		for (;;) {
			variable_create(&scope, t->text, paramcount++);
			tokenizer_read(t);

			if (paramcount > PARAMCOUNT_MAX) fail(t, "too many parameters");

			if (t->type != tt_comma) break;
			tokenizer_read(t);
		}
	}
	if (t->type != tt_paren_close) fail(t, "function parameter list not terminated");
	tokenizer_read(t);

	function->func_paramcount = paramcount;

	/* params are pushed from left to right */ 
	for (variable = scope.object_first; variable; variable = variable->next) {
		assert(variable->type == ot_variable);
		variable->var_index -= paramcount;
	}

	/* jump over function code */
	jump = codegen_jump(cg, NULL);

	/* generate code for function */
	function->func_code = cg->codeptr;
	codegen_func_prologue(cg);
	parse_scope(t, cg, &scope);
	codegen_func_epilogue(cg);

	/* patch jump over function code */
	codegen_patch_jump(cg, jump, cg->codeptr);

	scope_cleanup(&scope, cg);
}

static void parse_if(struct tokenizer *t, struct codegen *cg, struct scope *s) {
	codeptr_t jump_else, jump_end;
	struct scope scope;

	if (t->type != tt_if) fail(t, "if keyword missing");
	tokenizer_read(t);

	if (t->type != tt_paren_open) fail(t, "open parenthesis missing");
	tokenizer_read(t);

	parse_expression(t, cg, s, 1/*allow_comma*/);
	jump_else = codegen_jump_cond(cg, cc_eq, NULL);

	if (t->type != tt_paren_close) fail(t, "close parenthesis missing");
	tokenizer_read(t);

	scope_init(&scope, s, NULL/*function*/);
	parse_statement(t, cg, &scope);
	scope_cleanup(&scope, cg);
	if (t->type == tt_else) {
		tokenizer_read(t);

		jump_end = codegen_jump(cg, NULL);
		codegen_patch_jump_cond(cg, jump_else, cg->codeptr);
		scope_init(&scope, s, NULL/*function*/);
		parse_statement(t, cg, &scope);
		scope_cleanup(&scope, cg);
		codegen_patch_jump(cg, jump_end, cg->codeptr);
	} else {
		codegen_patch_jump_cond(cg, jump_else, cg->codeptr);
	}
}

static void parse_return(struct tokenizer *t, struct codegen *cg, struct scope *s) {

	if (!scope_get_function(s)) fail(t, "return outside function");

	if (t->type != tt_return) fail(t, "return keyword missing");
	tokenizer_read(t);

	if (t->type == tt_semicolon) {
		codegen_immediate(cg, 0);
	} else {
		parse_expression(t, cg, s, 1/*allow_comma*/);
	}
	codegen_func_epilogue(cg);
}

static void parse_scope(struct tokenizer *t, struct codegen *cg, struct scope *s) {
	struct scope scope;

	scope_init(&scope, s, NULL/*function*/);

	if (t->type != tt_brace_open) fail(t, "opening brace missing");
	tokenizer_read(t);

	while (t->type != tt_brace_close) {
		parse_statement(t, cg, &scope);
	}

	if (t->type != tt_brace_close) fail(t, "closing brace missing");
	tokenizer_read(t);

	scope_cleanup(&scope, cg);
}

static void parse_statement_expression(struct tokenizer *t, struct codegen *cg, const struct scope *s) {
	parse_expression(t, cg, s, 1/*allow_comma*/);

	if (t->type != tt_semicolon) fail(t, "semicolon missing after expression statement");
	tokenizer_read(t);
}

static void parse_var(struct tokenizer *t, struct codegen *cg, struct scope *s) {
	char name[IDENTIFIER_LEN_MAX + 1];
	struct object *variable;

	if (t->type != tt_var) fail(t, "var keyword missing");
	tokenizer_read(t);

	for (;;) {
		if (s->varcount >= VARCOUNT_MAX) fail(t, "too many variables");

		if (t->type != tt_identifier) fail(t, "variable name missing");
		strcpy(name, t->text);
		tokenizer_read(t);

		if (t->type == tt_assign) {
			tokenizer_read(t);
			parse_expression(t, cg, s, 0/*allow_comma*/);
		} else {
			codegen_immediate(cg, 0);
		}

		variable = variable_create(s, name, s->varcount++);
		codegen_var_alloc(cg);
		codegen_var_get_ptr(cg, variable->var_index, 0 /*func_boundaries*/);
		codegen_store(cg);

		if (t->type != tt_comma) break;
		tokenizer_read(t);
	}

	if (t->type != tt_semicolon) fail(t, "semicolon missing after variable declaration");
	tokenizer_read(t);
}

static void parse_while(struct tokenizer *t, struct codegen *cg, struct scope *s) {
	codeptr_t controller, jump;
	struct scope scope;

	if (t->type != tt_while) fail(t, "while keyword missing");
	tokenizer_read(t);

	if (t->type != tt_paren_open) fail(t, "open parenthesis missing");
	tokenizer_read(t);

	controller = cg->codeptr;
	parse_expression(t, cg, s, 1/*allow_comma*/);
	jump = codegen_jump_cond(cg, cc_eq, NULL);

	if (t->type != tt_paren_close) fail(t, "close parenthesis missing");
	tokenizer_read(t);

	scope_init(&scope, s, NULL/*function*/);
	parse_statement(t, cg, &scope);
	scope_cleanup(&scope, cg);

	codegen_jump(cg, controller);
	codegen_patch_jump_cond(cg, jump, cg->codeptr);
}

void parse_statement(struct tokenizer *t, struct codegen *cg, struct scope *s) {

	switch (t->type) {
	case tt_brace_open: parse_scope(t, cg, s);                break;
	case tt_debugger:   parse_debugger(t, cg, s);             break;
	case tt_do:         parse_do_while(t, cg, s);             break;
	case tt_for:        parse_for(t, cg, s);                  break;
	case tt_function:   parse_function(t, cg, s);             break;
	case tt_if:         parse_if(t, cg, s);                   break;
	case tt_return:     parse_return(t, cg, s);               break;
	case tt_semicolon:  tokenizer_read(t);                    break;
	case tt_var:        parse_var(t, cg, s);                  break;
	case tt_while:      parse_while(t, cg, s);                break;
	default:            parse_statement_expression(t, cg, s); break;
	}
}

static long alert(long value) {
	printf("%ld\n", value);
	fflush(stdout);
	return 0;
}

static void create_builtin_function_alert(struct codegen *cg, struct scope *s) {
	struct object *function = function_create(s, "alert");
	function->func_paramcount = 1;
	function->func_code = cg->codeptr;

	codegen_func_prologue(cg);

	/* load parameter */
	codegen_var_get_ptr(cg, -1/*var_index*/, 0/*codegen_op_binary*/);
	codegen_load(cg);
	codegen_push(cg);

	/* call our alert function */
	codegen_native_call(cg, alert, 1);

	codegen_func_epilogue(cg);
}

void create_builtin_functions(struct codegen *cg, struct scope *s) {
	create_builtin_function_alert(cg, s);
}
