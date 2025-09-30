#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

uint64_t canary_copy;

void admin() {
    // I don't like it when my stack pointer is misaligned
    // especially when people hijack my control flow
    uintptr_t rsp = 0;
    asm volatile("mov %%rsp, %0" : "=r"(rsp));
    if (rsp & 0x8) { // not 16-byte aligned
        asm volatile("push %%rax" ::: "rsp", "memory"); // push +8
    }

    if (system("/bin/sh") == -1) {
        perror("system");
        exit(1);
    }
}

uint64_t get_random() {
    uint64_t res = 0;
    for (int i = 0; i < 4; i++)
        res = res | ((uint64_t)rand() << (i * 16));
    res = res & ((1LL << 56) - 1);
    return res;
}

int read_buffer(char buffer[]) {
    int i = 0;
    buffer[i] = fgetc(stdin);
    while (buffer[i] != '\n') {
        i++;
        buffer[i] = fgetc(stdin);
    }
    buffer[i] = '\0';

    return i;
}

int main(int argc, char** argv, char** envp) {
    if (setregid(getegid(), -1) == -1) {
        perror("setregid");
        exit(1);
    }

    srand(time(NULL) / 120);
    volatile uint64_t canary = get_random();
    char buffer[16];
    canary_copy = canary;

    int n = read_buffer(buffer);

    for (int i = 0; i < n; i++) {   
        char chr = buffer[i];
        fputc(chr, stdout);
        if (chr == 'a' || chr == 'e' || chr == 'i' || chr == 'o' || chr == 'u') {
            fputc('p', stdout);
            fputc(chr, stdout);
        } else if (chr == 'A' || chr == 'E' || chr == 'I' || chr == 'O' || chr == 'U') {
            fputc('P', stdout);
            fputc(chr, stdout);
        }
    }
    fputc('\n', stdout);

    if (canary_copy != canary) {
        printf("stack smashing detected. Got: %p. Expected: %p\nAborting\n",
                canary, canary_copy);
        exit(-1);
    }

    return 0;
}
