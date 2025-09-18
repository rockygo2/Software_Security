#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

int main() {
    int32_t size;
    uint32_t counts[] = {0xFFFFFFF, 0x10000000}; // safe and overflow
    size_t n = sizeof(counts) / sizeof(counts[0]);

    for (size_t i = 0; i < n; i++) {
        uint32_t count = counts[i];
        size = 8 * count; // int32_t multiplication
        printf("count = %" PRIu32 "\n", count);
        printf("8 * count = %" PRId32 "\n", size);
        printf("8 * count (as uint64_t) = %" PRIu64 "\n\n", (uint64_t)count * 8);
    }

    return 0;
}
