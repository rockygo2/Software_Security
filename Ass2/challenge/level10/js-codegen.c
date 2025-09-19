#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "js-codegen.h"
#include "js-scope.h"

#define BLOCK_SIZE 4096
#define JUMP_SIZE 12

static void block_set_executable(struct codegenblock *block, int executable);

static void alloc_block(struct codegen *cg) {
	char jump[] = {
		0x48, 0xb8, 0x00, 0x00, 0x00, /* movabs 0, %rax */
		0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xe0,                   /* jmpq *%rax */
	};
	struct codegenblock *block;

	assert(sizeof(jump) == JUMP_SIZE);

	/* allocate new block */
	block = ALLOC(1, struct codegenblock);
	block->size = BLOCK_SIZE;
	block->base = (codeptr_t) mmap(get_random_ptr(), block->size,
		PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (block->base == MAP_FAILED) {
		fprintf(stderr, "error: cannot allocate new code block: %s\n",
			strerror(errno));
		exit(-1);
	}

	if (cg->block) {
		/* add jump to the new block at end of current block */
		block_set_executable(cg->block, 0);
		memcpy(jump + 2, &block->base, sizeof(block->base));
		memcpy(cg->codeptr, jump, sizeof(jump));
		cg->codeptr += sizeof(jump);

		/* allow old block to be executed (there will be no more writing) */
		block_set_executable(cg->block, 1);
	}

	/* point to the new block */
	block->prev = cg->block;
	cg->block = block;
	cg->codeptr = block->base;
}

static void write_code(struct codegen *cg, char *code, size_t codelen) {
	size_t freespace;

	/* allocate a new block if there is not enough space */
	freespace = (char *) cg->block->base + cg->block->size - (char *) cg->codeptr;
	if (freespace < codelen + JUMP_SIZE) alloc_block(cg);

	/* write the instructions */
	assert(codelen + JUMP_SIZE < cg->block->size);
	codegen_set_executable(cg, 0);
	memcpy(cg->codeptr, code, codelen);
	cg->codeptr = (char *) cg->codeptr + codelen;
}

void codegen_arg_get_ptr_by_index(struct codegen *cg, size_t paramcount) {
	char code[] = {
		0xb8, 0x00, 0x00, 0x00, 0x00, /* mov $0, %eax */
		0x29, 0xd0,                   /* sub %edx, %eax */
		0x48, 0x8d, 0x74, 0xc5, 0x08, /* lea 0x8(%rbp,%rax,8), %rsi */
	};
	uint32_t paramcount32;

	assert(paramcount < 0x10000000);

	paramcount32 = paramcount;
	memcpy(code + 1, &paramcount32, sizeof(paramcount32));
	write_code(cg, code, sizeof(code));
}

void codegen_breakpoint(struct codegen *cg) {
	char code[] = {
		0xcc, /* int3 */
	};
	write_code(cg, code, sizeof(code));
}

void codegen_call(struct codegen *cg, codeptr_t func, size_t paramcount) {
	char code[] = {
		0x48, 0xb8, 0x00, 0x00, 0x00, /* movabs $0, %rax */
		0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xd0,                   /* callq  *%rax */
		0x48, 0x81, 0xc4, 0x00, 0x00, /* add    $0, %rsp */
		0x00, 0x00,
	};
	int32_t paramsize;

	assert(paramcount < 0x10000000);

	paramsize = paramcount * 8;
	memcpy(code + 2, &func, sizeof(func));
	memcpy(code + 15, &paramsize, sizeof(paramsize));
	write_code(cg, code, sizeof(code));
}

void codegen_compare(struct codegen *cg, enum codegen_condition condition) {
	char code[] = {
		0x58,                   /* pop    %rax */
		0x48, 0x39, 0xd0,       /* cmp    %rdx, %rax */
		0x0f, 0x90, 0xc2,       /* setCC  %dl */
		0x48, 0x83, 0xe2, 0x01, /* and    $1, %rdx */
	};
	code[5] |= condition;
	write_code(cg, code, sizeof(code));
}

void codegen_func_prologue(struct codegen *cg) {
	char code[] = {
		0x55,             /* push %rbp */
		0x48, 0x89, 0xe5, /* mov %rsp, %rbp */
	};
	write_code(cg, code, sizeof(code));
}

void codegen_func_epilogue(struct codegen *cg) {
	char code[] = {
		0x48, 0x89, 0xec, /* mov %rbp, %rsp */
		0x5d,             /* pop %rbp */
		0xc3,             /* ret */
	};
	write_code(cg, code, sizeof(code));
}

void codegen_immediate(struct codegen *cg, long value) {
	char code1[] = {
		0xba, 0x00, 0x00, 0x00, 0x00, /* mov $0, %edx */
	};
	char code2[] = {
		0xb8, 0x00, 0x00, 0x00, 0x00, /* mov $0,    %eax */
		0x48, 0xc1, 0xe0, 0x20,       /* shl $0x20, %rax */
		0x48, 0x09, 0xc2,             /* or  %rax,  %rdx */
	};
	uint32_t value32;

	/* low-order 32 bits */
	value32 = value;
	memcpy(code1 + 1, &value32, sizeof(value32));
	write_code(cg, code1, sizeof(code1));

	/* high-order 32 bits only if needed */
	value32 = value >> 32;
	if (value32) {
		memcpy(code2 + 1, &value32, sizeof(value32));
		write_code(cg, code2, sizeof(code2));
	}
}

void codegen_init(struct codegen *cg) {
	memset(cg, 0, sizeof(*cg));
	alloc_block(cg);
}

codeptr_t codegen_jump(struct codegen *cg, codeptr_t target) {
	char code[] = {
		0x48, 0xb8, 0x00, 0x00, 0x00, /* movabs 0, %rax */
		0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xe0,                   /* jmpq *%rax */
	};
	codeptr_t jumpptr = cg->codeptr;
	memcpy(code + 2, &target, sizeof(target));
	write_code(cg, code, sizeof(code));
	return jumpptr;
}

codeptr_t codegen_jump_cond(struct codegen *cg, enum codegen_condition condition, codeptr_t target) {
	char code[] = {
		0x48, 0x85, 0xd2,             /* test   %rdx, %rdx */
		0x70, 0x0c,                   /* je     %rip+0x0c */
		0x48, 0xb8, 0x00, 0x00, 0x00, /* movabs 0, %rax */
		0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xe0,                   /* jmpq *%rax */
	};
	codeptr_t jumpptr = cg->codeptr;
	code[3] |= (condition ^ 1);
	memcpy(code + 7, &target, sizeof(target));
	write_code(cg, code, sizeof(code));
	return jumpptr;
}

void codegen_load(struct codegen *cg) {
	char code[] = {
		0x48, 0x8b, 0x16, /* mov (%rsi), %rdx */
	};
	write_code(cg, code, sizeof(code));
}

void codegen_native_call(struct codegen *cg, void *func, long paramcount) {
	char code_param1[] = { 0x5f,       /* pop %rdi */ };
	char code_param2[] = { 0x5e,       /* pop %rsi */ };
	char code_param3[] = { 0x5a,       /* pop %rdx */ };
	char code_param4[] = { 0x59,       /* pop %rcx */ };
	char code_param5[] = { 0x41, 0x58, /* pop %r8  */ };
	char code_param6[] = { 0x41, 0x59, /* pop %r9  */ };
	char code_switch_stack[] = {
		0x48, 0x87, 0x63, 0x08, /* xchg %rsp, 0x8(%rbx) */
	};
	char code_call[] = {
		0x48, 0xb8, 0x00, 0x00, 0x00, /* movabs $0, %rax */
		0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xd0,                   /* callq  *%rax */
		0x48, 0x89, 0xc2,             /* mov    %rax, %rdx */
	};

	assert(paramcount >= 0);
	assert(paramcount <= 6);
	if (paramcount >= 1) write_code(cg, code_param1, sizeof(code_param1));
	if (paramcount >= 2) write_code(cg, code_param2, sizeof(code_param2));
	if (paramcount >= 3) write_code(cg, code_param3, sizeof(code_param3));
	if (paramcount >= 4) write_code(cg, code_param4, sizeof(code_param4));
	if (paramcount >= 5) write_code(cg, code_param5, sizeof(code_param5));
	if (paramcount >= 6) write_code(cg, code_param6, sizeof(code_param6));

	memcpy(code_call + 2, &func, sizeof(func));

	write_code(cg, code_switch_stack, sizeof(code_switch_stack));
	write_code(cg, code_call,         sizeof(code_call));
	write_code(cg, code_switch_stack, sizeof(code_switch_stack));
}

static void codegen_op_binary_add(struct codegen *cg) {
	char code[] = {
		0x58,             /* pop %rax */
		0x48, 0x01, 0xc2, /* add %rax, %rdx */
	};
	write_code(cg, code, sizeof(code));
}

static void codegen_op_binary_band(struct codegen *cg) {
	char code[] = {
		0x58,             /* pop %rax */
		0x48, 0x21, 0xc2, /* and %rax, %rdx */
	};
	write_code(cg, code, sizeof(code));
}

static void codegen_op_binary_bor(struct codegen *cg) {
	char code[] = {
		0x58,             /* pop %rax */
		0x48, 0x09, 0xc2, /* or  %rax, %rdx */
	};
	write_code(cg, code, sizeof(code));
}

static void codegen_op_binary_bxor(struct codegen *cg) {
	char code[] = {
		0x58,             /* pop %rax */
		0x48, 0x31, 0xc2, /* xor %rax, %rdx */
	};
	write_code(cg, code, sizeof(code));
}

static void codegen_op_binary_div(struct codegen *cg) {
	char code[] = {
		0x48, 0x89, 0xd1, /* mov  %rdx, %rcx */
		0x58,             /* pop  %rax */
		0x48, 0x99,       /* cqto */
		0x48, 0xf7, 0xf9, /* idiv %rcx */
		0x48, 0x89, 0xc2, /* mov  %rax, %rdx */
	};
	write_code(cg, code, sizeof(code));
}

static void codegen_op_binary_mod(struct codegen *cg) {
	char code[] = {
		0x48, 0x89, 0xd1, /* mov  %rdx, %rcx */
		0x58,             /* pop  %rax */
		0x48, 0x99,       /* cqto */
		0x48, 0xf7, 0xf9, /* idiv %rcx */
	};
	write_code(cg, code, sizeof(code));
}

static void codegen_op_binary_mul(struct codegen *cg) {
	char code[] = {
		0x58,                   /* pop %rax */
		0x48, 0x0f, 0xaf, 0xd0, /* imul %rax, %rdx */
	};
	write_code(cg, code, sizeof(code));
}

static void codegen_op_binary_shl(struct codegen *cg) {
	char code[] = {
		0x48, 0x89, 0xd1, /* mov %rdx, %rcx */
		0x5a,             /* pop %rdx */
		0x48, 0xd3, 0xe2, /* shl %cl, %rdx */
	};
	write_code(cg, code, sizeof(code));
}

static void codegen_op_binary_shr(struct codegen *cg) {
	char code[] = {
		0x48, 0x89, 0xd1, /* mov %rdx, %rcx */
		0x5a,             /* pop %rdx */
		0x48, 0xd3, 0xea, /* shr %cl, %rdx */
	};
	write_code(cg, code, sizeof(code));
}

static void codegen_op_binary_sub(struct codegen *cg) {
	char code[] = {
		0x48, 0x89, 0xd0, /* mov %rdx, %rax */
		0x5a,             /* pop %rdx */
		0x48, 0x29, 0xc2, /* sub %rax, %rdx */
	};
	write_code(cg, code, sizeof(code));
}

void codegen_op_binary(struct codegen *cg, enum codegen_op_binary op) {
	switch (op) {
	case cob_add:  codegen_op_binary_add(cg);  break;
	case cob_band: codegen_op_binary_band(cg); break;
	case cob_bor:  codegen_op_binary_bor(cg);  break;
	case cob_bxor: codegen_op_binary_bxor(cg); break;
	case cob_div:  codegen_op_binary_div(cg);  break;
	case cob_mod:  codegen_op_binary_mod(cg);  break;
	case cob_mul:  codegen_op_binary_mul(cg);  break;
	case cob_shl:  codegen_op_binary_shl(cg);  break;
	case cob_shr:  codegen_op_binary_shr(cg);  break;
	case cob_sub:  codegen_op_binary_sub(cg);  break;
	default:       abort();                    break;
	}
}

static void codegen_op_unary_bnot(struct codegen *cg) {
	char code[] = {
		0x48, 0xf7, 0xd2, /* not %rdx */
	};
	write_code(cg, code, sizeof(code));
}

static void codegen_op_unary_neg(struct codegen *cg) {
	char code[] = {
		0x48, 0xf7, 0xda, /* neg %rdx */
	};
	write_code(cg, code, sizeof(code));
}

static void codegen_op_unary_not(struct codegen *cg) {
	char code[] = {
		0x48, 0x85, 0xd2,       /* test  %rdx, %rdx */
		0x0f, 0x94, 0xc2,       /* sete  %dl */
		0x48, 0x83, 0xe2, 0x01, /* and   $0x1, %rdx */
	};
	write_code(cg, code, sizeof(code));
}

void codegen_op_unary(struct codegen *cg, enum codegen_op_unary op) {
	switch (op) {
	case cou_bnot: codegen_op_unary_bnot(cg); break;
	case cou_neg:  codegen_op_unary_neg(cg);  break;
	case cou_not:  codegen_op_unary_not(cg);  break;
	default:       abort();                   break;
	}
}

static int block_contains_ptr(struct codegenblock *block, codeptr_t ptr) {
	return ((char *) ptr >= (char *) block->base) &&
		((char *) ptr < (char *) block->base + block->size);
}

static struct codegenblock *codeptr_get_block(struct codegen *cg, codeptr_t ptr) {
	struct codegenblock *block;

	block = cg->block;
	while (block && !block_contains_ptr(block, ptr)) {
		block = block->prev;
	}
	return block;
}

static void codegen_patch_address(struct codegen *cg, codeptr_t address, codeptr_t target) {
	struct codegenblock *block;
	int old_executable;

	block = codeptr_get_block(cg, address);
	if (!block) abort();

	old_executable = block->executable;
	block_set_executable(block, 0);

	memcpy(address, &target, sizeof(target));

	block_set_executable(block, old_executable);
}

void codegen_patch_jump(struct codegen *cg, codeptr_t jump, codeptr_t target) {
	codegen_patch_address(cg, (char *) jump + 2, target);
}

void codegen_patch_jump_cond(struct codegen *cg, codeptr_t jump, codeptr_t target) {
	codegen_patch_address(cg, (char *) jump + 7, target);
}

void codegen_pop(struct codegen *cg) {
	char code[] = {
		0x5a, /* pop %rdx */
	};
	write_code(cg, code, sizeof(code));
}

void codegen_pop_ptr(struct codegen *cg) {
	char code[] = {
		0x5e, /* pop %rsi */
	};
	write_code(cg, code, sizeof(code));
}

void codegen_push(struct codegen *cg) {
	char code[] = {
		0x52, /* push %rdx */
	};
	write_code(cg, code, sizeof(code));
}

void codegen_push_ptr(struct codegen *cg) {
	char code[] = {
		0x56, /* push %rsi */
	};
	write_code(cg, code, sizeof(code));
}

static void block_set_executable(struct codegenblock *block, int executable) {
	if (!block) return;
	if (block->executable == executable) return;

	if (mprotect(block->base, block->size,
		executable ? PROT_EXEC : PROT_WRITE) != 0) {
		fprintf(stderr, "error: cannot alter code block "
			"memory protection: %s\n", strerror(errno));
		exit(-1);
	}
	block->executable = executable;
}

void codegen_set_executable(struct codegen *cg, int executable) {
	block_set_executable(cg->block, executable);
}

void codegen_store(struct codegen *cg) {
	char code[] = {
		0x48, 0x89, 0x16, /* mov %rdx, (%rsi) */
	};
	write_code(cg, code, sizeof(code));
}

void codegen_var_alloc(struct codegen *cg) {
	char code[] = {
		0x48, 0x83, 0xec, 0x08, /* sub $8, %rsp */
	};
	write_code(cg, code, sizeof(code));
}

void codegen_var_dealloc(struct codegen *cg, size_t count) {
	char code[] = {
		0x48, 0x81, 0xc4, 0x00, 0x00, 0x00, 0x00, /* add 0, %rsp */
	};
	int32_t size;

	assert(count < 0x10000000);

	if (count < 1) return;

	size = 8 * count;
	memcpy(code + 3, &size, sizeof(size));
	write_code(cg, code, sizeof(code));
}

void codegen_var_get_ptr(struct codegen *cg, long var_index, long func_boundaries) {
	char code_load_rbp[] = {
		0x48, 0x89, 0xee, /* mov %rbp, %rsi */
	};
	char code_parent_func[] = {
		0x48, 0x8b, 0x36 , /* mov (%rsi), %rsi */
	};
	char code_add[] = {
		0x48, 0x81, 0xc6, 0x00, 0x00, 0x00, 0x00 /* add 0, %rsi */
	};
	long i;
	int32_t offset;

	assert(var_index < 0x10000000);
	assert(var_index > -0x10000000);

	/* load the frame pointer for the relevant function into %rsi */
	write_code(cg, code_load_rbp, sizeof(code_load_rbp));
	for (i = 0; i < func_boundaries; i++) {
		write_code(cg, code_parent_func, sizeof(code_parent_func));
	}

	if (var_index < 0) {
		/* parameter */
		offset = 8 * (-var_index + 1);
	} else {
		/* local var */
		offset = 8 * (-var_index - 1);
	}
	memcpy(code_add + 3, &offset, sizeof(offset));
	write_code(cg, code_add, sizeof(code_add));
}

codegen_wrapper_t codegen_wrapper_prologue(struct codegen *cg) {
	char code[] = {
		0x48, 0x89, 0x1f,       /* mov  %rbx, (%rdi) */
		0x48, 0x87, 0x67, 0x08, /* xchg %rsp, 0x8(%rdi) */
		0x48, 0x87, 0x6f, 0x10, /* xchg %rbp, 0x10(%rdi) */
		0x48, 0x89, 0xfb,       /* mov  %rdi, %rbx */
		0x48, 0x31, 0xd2,       /* xor  %rdx, %rdx */
		0x48, 0x31, 0xf6,       /* xor  %rsi, %rsi */
	};
	codegen_wrapper_t func = (codegen_wrapper_t) cg->codeptr;
	write_code(cg, code, sizeof(code));
	return func;
}

void codegen_wrapper_epilogue(struct codegen *cg) {
	char code[] = {
		0x48, 0x89, 0xd8,       /* mov  %rbx,  %rax */
		0x48, 0x8b, 0x18,       /* mov  (%rax),%rbx */
		0x48, 0x87, 0x60, 0x08, /* xchg %rsp,  0x8(%rax) */
		0x48, 0x87, 0x68, 0x10, /* xchg %rbp,  0x10(%rax) */
		0xc3,                   /* ret */
	};
	write_code(cg, code, sizeof(code));
}

void *get_random_ptr(void) {
	static int fd = -1;
	long ptr;

	if (fd < 0) {
		fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0) {
			perror("error: cannot open /dev/urandom");
			exit(-1);
		}
	}
	if (read(fd, &ptr, sizeof(ptr)) != sizeof(ptr)) {
		perror("error: cannot read from /dev/urandom");
		exit(-1);
	}
	ptr &= 0x7ffffffff000;
	return (void *) ptr;
}
