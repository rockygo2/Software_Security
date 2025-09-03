#include <stdio.h>
#include <string.h>
#include <stdlib.h>


void save_note(const char *note) {
    char success = 1;
    char buffer[64] = { 0 };

    strcat(buffer, "NOTE: ");
    strcat(buffer, note);

    FILE *f = fopen("notes.txt", "w");
    if (f == NULL) {
        success = 0;
    }

    if (success != 1) {
        printf("Failed to open notes.txt\n");
        exit(1);
    }

    fprintf(f, "%s\n", buffer);
    fclose(f);

    printf("Note saved to notes.txt\n");
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <your note>\n", argv[0]);
        return 1;
    }

    save_note(argv[1]);

    printf("Goodbye!\n");
    return 0;
}