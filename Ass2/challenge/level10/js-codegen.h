#ifndef JS_CODEGEN_H
#define JS_CODEGEN_H

#define PARAMCOUNT_MAX 0x10000000
#define VARCOUNT_MAX   0x10000000

typedef void *codeptr_t;

/*
 * codegen register allocation:
 * - rax: temporary, not preserved between code fragments
 * - rbx: pointer to struct codegen_wrapper_state
 * - rcx: temporary, not preserved between code fragments
 * - rdx: result from previous operation (including function result)
 * - rsp: stack pointer (separate stack from main code)
 * - rbp: frame pointer
 * - rsi: pointer for load/store
 */

struct codegenblock {
	struct codegenblock *prev;
	codeptr_t base;
	size_t size;
	int executable;
};

struct codegen {
	struct codegenblock *block;
	codeptr_t codeptr;
};

struct codegen_wrapper_state {
	void *rbx, *rsp, *rbp;
	void *stack;
};

enum codegen_condition {
	cc_eq = 0x4,
	cc_ne = 0x5,
	cc_lt = 0xc,
	cc_ge = 0xd,
	cc_le = 0xe,
	cc_gt = 0xf,
};

enum codegen_op_unary {
	cou_none,
	cou_bnot,
	cou_neg,
	cou_not,
};

enum codegen_op_binary {
	cob_none,
	cob_add,
	cob_band,
	cob_bor,
	cob_bxor,
	cob_div,
	cob_mod,
	cob_mul,
	cob_shl,
	cob_shr,
	cob_sub,
};

typedef void (*codegen_wrapper_t)(struct codegen_wrapper_state *);

void codegen_init(struct codegen *cg);

void codegen_arg_get_ptr_by_index(struct codegen *cg, size_t paramcount);                            /* in: %rdx;       out: %rsi      */
void codegen_breakpoint(struct codegen *cg);
void codegen_call(struct codegen *cg, codeptr_t func, size_t paramcount);                            /* in: stack;      out: %rdx      */
void codegen_compare(struct codegen *cg, enum codegen_condition condition);                          /* in: %rdx+stack; out: %rdx      */
void codegen_func_prologue(struct codegen *cg);
void codegen_func_epilogue(struct codegen *cg);
void codegen_immediate(struct codegen *cg, long value);                                              /*                 out: %rdx      */
codeptr_t codegen_jump(struct codegen *cg, codeptr_t target);
codeptr_t codegen_jump_cond(struct codegen *cg, enum codegen_condition condition, codeptr_t target); /* in: %rdx                       */
void codegen_load(struct codegen *cg);                                                               /* in: %rsi;       out: %rdx      */
void codegen_native_call(struct codegen *cg, void *func, long paramcount);                           /* in: stack;      out: %rdx      */
void codegen_op_binary(struct codegen *cg, enum codegen_op_binary op);                               /* in: %rdx+stack; out: %rdx      */
void codegen_op_unary(struct codegen *cg, enum codegen_op_unary op);                                 /* in: %rdx;       out: %rdx      */
void codegen_patch_jump(struct codegen *cg, codeptr_t jump, codeptr_t target);
void codegen_patch_jump_cond(struct codegen *cg, codeptr_t jump, codeptr_t target);
void codegen_pop(struct codegen *cg);                                                                /* in: stack;      out: %rdx      */
void codegen_pop_ptr(struct codegen *cg);                                                            /* in: stack;      out: %rsi      */
void codegen_push(struct codegen *cg);                                                               /* in: %rdx;       out: stack     */
void codegen_push_ptr(struct codegen *cg);                                                           /* in: %rsi;       out: stack     */
void codegen_set_executable(struct codegen *cg, int executable);
void codegen_store(struct codegen *cg);                                                              /* in: %rdx+%rsi                  */
void codegen_var_alloc(struct codegen *cg);
void codegen_var_dealloc(struct codegen *cg, size_t count);
void codegen_var_get_ptr(struct codegen *cg, long var_index, long func_boundaries);                  /*                 out: %rsi      */
codegen_wrapper_t codegen_wrapper_prologue(struct codegen *cg);                                      /*                 out: %rdx+%rsi */
void codegen_wrapper_epilogue(struct codegen *cg);

void *get_random_ptr(void);

#endif /* !defined(JS_CODEGEN_H) */
