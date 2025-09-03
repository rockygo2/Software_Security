#include <stdio.h>
#include <string.h>


char encoded[] = {
    // REDACTED
};

char decode(char byte) {
    // REDACTED
    return byte;
}

int main(int argc, char *argv[])
{
    if (argc <= 1) {
        goto wrong;
    }

    if (strlen(argv[1]) != sizeof(encoded)) {
        goto wrong;
    }

    char *pw = argv[1];
    int i = 0;
    while (pw[i] != 0) {
        if (pw[i] != decode(encoded[i]))
            goto wrong;
        i += 1;
    }

    printf("You found the flag!\n");
    return 0;
    
    wrong:
    printf("Wrong password, too bad!\n");
    return 1;
}
