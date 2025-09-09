/*
 * We implement a subset of JavaScript. In particular:
 * - variables must always be declared before use
 * - the only supported data type is 64-bit integers
 * - break and continue are not supported
 * - exception handling is not supported
 * - switch is not supported
 *
 * To communicate with the outside world, call the alert(value) function.
 *
 * See js-example.js for an example input file.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "js-codegen.h"
#include "js-compiler.h"
#include "js-scope.h"
#include "js-tokenizer.h"

#define STACK_SIZE		(4096 * 1024)
#define STACK_GUARD_SIZE	(4096)

static void run_statement(
	struct tokenizer *t,
	struct codegen *cg,
	struct scope *s,
	struct codegen_wrapper_state *state) {
	codegen_wrapper_t wrapper;

	/* compile statement with a wrapper to invoke it */
	wrapper = codegen_wrapper_prologue(cg);
	parse_statement(t, cg, s);
	codegen_wrapper_epilogue(cg);

	/* invoke the code */
	codegen_set_executable(cg, 1);
	wrapper(state);
}

static void stack_alloc(struct codegen_wrapper_state *state) {

	/* allocate stack surrounded by inaccessible guard pages */
	state->stack = mmap(get_random_ptr(), STACK_SIZE + 2*STACK_GUARD_SIZE,
		PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (state->stack == MAP_FAILED) {
		perror("failed to allocate stack");
		exit(-1);
	}
	if (mprotect(state->stack + STACK_GUARD_SIZE, STACK_SIZE,
		PROT_READ|PROT_WRITE) != 0) {
		perror("failed to make stack accessibe");
		exit(-1);
	}
	state->rbp = state->rsp = state->stack + STACK_GUARD_SIZE + STACK_SIZE;
}

static void stack_free(struct codegen_wrapper_state *state) {
	if (munmap(state->stack, STACK_SIZE + STACK_GUARD_SIZE) != 0) {
		perror("failed to deallocate stack");
		exit(-1);
	}
}

static void run_program(FILE *file) {
	struct codegen codegen = { };
	struct scope scope = { };
	struct codegen_wrapper_state state = { };
	struct tokenizer tokenizer = { };

	codegen_init(&codegen);

	scope_init(&scope, NULL, NULL/*function*/);
	stack_alloc(&state);

	create_builtin_functions(&codegen, &scope);

	tokenizer_init(&tokenizer, file);
	tokenizer_read(&tokenizer);
	while (tokenizer.type != tt_eof) {
		run_statement(&tokenizer, &codegen, &scope, &state);
	}

	stack_free(&state);
	scope_cleanup(&scope, &codegen);
}

int main(int argc, char **argv) {
	FILE *file;
	int i;

	if (argc >= 2) {
		for (i = 1; i < argc; i++) {
			file = fopen(argv[i], "r");
			if (!file) {
				fprintf(stderr, "error: cannot open %s: %s\n",
					argv[i], strerror(errno));
				return 1;
			}
			run_program(file);
			fclose(file);
		}
	} else {
		setlinebuf(stdin);
		run_program(stdin);
	}
}
