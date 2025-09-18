#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// This function is in 10.c (your main driver)
extern int run_jit_from_file(const char *filename);

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Write fuzzed input to a temporary file
    char tmp_filename[] = "/tmp/fuzzXXXXXX.js";
    int fd = mkstemps(tmp_filename, 3); // keep ".js" extension
    if (fd < 0) return 0;
    write(fd, data, size);
    close(fd);

    // Run your JIT on the temp file
    run_jit_from_file(tmp_filename);

    // Remove temp file
    unlink(tmp_filename);
    return 0;
}
