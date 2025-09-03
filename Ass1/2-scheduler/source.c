#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WORKERS 40
#define TOLERANCE 8
#define BUFFER 16

int room = -1;
int contention;
int order = 0;
size_t len;

void flag() {
    // REDACTED
    printf("flag{...}\n");
}

int my_rand() {
    return (rand() | (rand() << 16)) & ((1 << 30) - 1);
}

int main(int argc, char** argv) {
    char buffer[BUFFER + 1];

    int seed;
    if (argc != 2)
        seed = time(NULL);
    else {
        seed = atoi(argv[1]);
    }

    srand(seed);

    while (order < 10000) {
        room = my_rand();
        contention = 0;

        for (int i = 2; i <= WORKERS + 1; i++)
            if (room % i == 0)
                contention++;

        printf("Please introduce additional notes on this order: ");
        fgets(buffer, 1000, stdin);
        len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n')
            buffer[len - 1] = '\0';

        if (contention <= TOLERANCE) {
            if (len > BUFFER) {
                printf("Invalid note detected. Shutting down factory.\n");
                exit(1);
            }

            printf("Report on order %d:\n", order);
            printf("A new job was released in room %d\n", room);
            printf("Robots assigned on the job:");

            for (int i = 2; i <= WORKERS + 1; i++)
                if (room % i == 0)
                    printf("%d ", i);
            printf("\n");

            printf("Additional notes to order: %s\n\n", buffer);
        } else {
            printf("Incident report for order %d:\n", order);
            printf("A new job was released in room %d.\n", room);
            printf("Too many robots were assigned to the same room. Aborting order.\n\n");
        }

        order++;
    }

    return 0;
}

