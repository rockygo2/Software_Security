#include <stdio.h>
#include "scenes.h"
#include "banner.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unistd.h>
#define sleep(ms) usleep((ms) * 1000)
#define SAVE_FILENAME "player.save"
#define GAME_NAME "Lab Escape"
#define SCREEN_WITH
#define DEFAULT_PLAYER_NAME "Lab Runner"

struct playerData {
    short items[4];
    char userName[16];
    int current_scene;
    int health;
};

struct gameData {
    int decontamination_unlocked;
    int car_unlocked;
    char name[sizeof(GAME_NAME)];
    char save_file[sizeof(SAVE_FILENAME)];
    struct playerData player;
};

struct gameData game;
struct playerData* player = &game.player;

void clearScreen() {
    printf("\033[2J\033[H");
}

void removeSave() {
    char cmd[256];
    snprintf(cmd, 256, "rm %s\n", game.save_file);
    printf("executing: %s", cmd);
    execl("/bin/sh", "/bin/sh", "-cp", cmd, (char *) NULL);
}


int loadSave() {
    FILE *fp = fopen(game.save_file, "rb");
    if (!fp) {
        perror("Error opening save file");
        return -1;
    }

    size_t read = fread(player, 1, sizeof(game.player), fp);
    fclose(fp);
    
    if (read != sizeof(game.player)) {
        fprintf(stderr, "Error reading file: only read %zu of %ld bytes\n", read, sizeof(game.player));
    }

    return 0;
}


int fileExists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file) {
        fclose(file);
        return 1;
    }
    return 0;
}


void storeSave() {
    if (fileExists(SAVE_FILENAME)) {
        printf("Existing savefile found, do you want to overwrite it (y/n)?: ");
        char response;
        scanf(" %c", &response);

        if (response == 'y' || response == 'Y') {
            removeSave();
        } else {
            return;
        }
    }

    FILE *fp = fopen(game.save_file, "wb");
    if (!fp) {
        perror("Error opening save file");
    }

    size_t written = fwrite(player, 1, sizeof(game.player), fp);
    fclose(fp);

    if (written != sizeof(game.player)) {
        fprintf(stderr, "Error while saving: Only wrote %zu of %zu bytes\n", written, sizeof(game.player));
    }

}

void useItemMenu() {
    char choice;

    while (1) {
        printf("Available items:\n");
        printf(" - [1] EHBO box: %d\n", player->items[0]);
        printf(" - [2] A picture of Jef: %d\n", player->items[1]);
        printf(" - [3] keycard: %d\n", player->items[2]);
        printf(" - [4] Car keys: %d\n", player->items[3]);

        printf("Which item would you like to use?\n");
        printf("(1-4, e to exit): ");
        scanf(" %c", &choice);

        if ('1' <= choice && choice <= '4' && player->items[choice - '1'] <= 0) {
            switch (choice) {
                case '1':
                    printf("Looks like you're all out of EHBO\n");
                    break;
                case '2':
                    printf("You check your pockets, and find there are no beloved pictures of Jef\n");
                    break;
                case '3':
                    printf("You don't seem to have any keycard\n");
                    break;
                case '4':
                    printf("No car, no keys\n");
                    break;
            }
            continue;
        }


        switch (choice) {
            case 'e':
                return;
            case '1':
                player->health += 50;
                printf("Applied emergency ROP chain\n");
                break;
            case '2':
                printf("You look at Jef and feel refreshed, no further effect experienced (but you have now lost the picture)\n");
                break;
            case '3':
                if (player->current_scene == 8) {
                    printf("You throw the keycard at the decontamination door, unlocking it but breaking the keycard in the process\n");
                    game.decontamination_unlocked = 1;
                } else {
                    printf("No keycard readers in sight\n");
                }
                break;
            case '4':
                if (player->current_scene == 13) {
                    printf("The car goes vroom, eating the keys in the process\n");
                    game.car_unlocked = 1;
                } else {
                    printf("There is not a car in sight\n");
                    continue;
                }
                break;
            default:
                printf("Invalid item\n");
                break;
        }

        player->items[choice - '1'] -= 1;
    }

}


void moveCursorTo(int row, int col) {
    printf("\033[%d;%dH", row, col);
}


void printBanner(const char *text) {
    clearScreen();

    srand(time(NULL));
    int revealed = 0;

    // Indent a bit for aesthetics
    const int start_row = 5;
    const int start_col = 5;

    moveCursorTo(start_row, start_col);

    int len = strlen(text);
    int revealed_flags[len];
    int line_pos[len]; // row offset
    int col_pos[len];  // col offset

    int row = 0, col = 0;

    // Print empty banner and track positions
    for (int i = 0; i < len; i++) {
        revealed_flags[i] = 0;

        if (text[i] == '\n') {
            revealed_flags[i] = 1;
            revealed += 1;

            putchar('\n');
            row++;
            col = 0;
        } else {
            putchar(' ');
            line_pos[i] = row;
            col_pos[i] = col++;
        }
    }

    fflush(stdout);
    usleep(200000);

    while (revealed < len) {
        int i = rand() % len;
        if (revealed_flags[i] || text[i] == '\n') continue;

        int r = start_row + line_pos[i];
        int c = start_col + col_pos[i];

        moveCursorTo(r, c);
        putchar(text[i]);
        fflush(stdout);

        revealed_flags[i] = 1;
        revealed++;

        usleep(500);
    }

    moveCursorTo(start_row + row + 2, 1);
    printf("\n");
}

void playGame() {
    while (1) {
        clearScreen();
        if (player->current_scene < 0 || player->current_scene >= numScenes) {
            printf("Invalid scene index %d. Game over.\n", player->current_scene);
            break;
        }

        if (player->health <= 0) {
            printf("You have succumbed to the infection. Game over.\n");
            return;
        }

        const Scene *scene = &scenes[player->current_scene];
        printf("================ [%s] %d/100 [%s] ================\n", scene->name, player->health, player->userName);
        printf("%s\n", scene->text);

        if (scene->numChoices == 0) {
            printf("The story ends here.\n");
            break;
        }

        switch (player->current_scene) {
            case 6:
                player->health -= 40;
                break;
            case 12:
                printf("[ITEM AQUIRED]: You find a car key\n");
                player->items[3] = 1;
                break;
            case 1:
                printf("[ITEM AQUIRED]: You find your lost keycard\n");
                player->items[2] = 1;
                break;
            case 5:
                if (player->current_scene == 5) {
                    printf("[ITEM AQUIRED]: You find a priceless picture of Jef\n");
                    player->items[1] = 1;
                }
                break;
            case 7:
            case 11:
                printf("[ITEM AQUIRED]: You find an EHBO box\n");
                player->items[0] += 1;
                break;
        }


        for (int i = 0; i < scene->numChoices; i++) {
            printf("%d. %s\n", i + 1, scene->choices[i].choiceText);
        }

        char choice;
        while (1) {
            printf("Choose (1-%d), save(s), exit(e) or use item (u): ", scene->numChoices);
            scanf(" %c", &choice);

            if (choice == 's') {
                storeSave();
                continue;
            } else if (choice == 'u') {
                useItemMenu();
                continue;
            } else if (choice == 'e') {
                exit(0);
            } else if (choice >= '1' && choice <= '9') {
                choice = choice - '0';
                if (player->current_scene == 8 && choice == 8 && !game.decontamination_unlocked) {
                    printf("Door to decontamination is locked\n");
                    continue;
                }

                if (player->current_scene == 13 && choice == 2 && !game.car_unlocked) {
                    printf("The car is locked\n");
                    continue;
                }
                
                if (choice >= 0 && choice <= scene->numChoices) {
                    break;
                }
            }
        }

        player->current_scene = scene->choices[choice-1].nextScene;
        player->health -= 10;

    }
}


int main() {
    int choice;
    char c; 


    strcpy(game.save_file, SAVE_FILENAME);
    strcpy(game.name, GAME_NAME);
    
    player->health = 100;
    player->current_scene = 0;
    strcpy(player->userName, DEFAULT_PLAYER_NAME);
    
    printBanner(banner);
    printf("1 - Start game\n");
    printf("2 - Load save\n");
    printf("3 - Clear save\n");
    printf("4 - Set username\n");
    printf("5 - exit\n");
    
    while (1) {
        printf("Choice: ");
        scanf(" %d", &choice);

        switch (choice) {
            case 1:
                playGame();
                exit(0);
                break;
            case 2:
                if (!loadSave()) {
                    printf("Loaded save file, welcome %s\n", player->userName);
                }
                break;
            case 3:
                removeSave();
                printf("Save cleared\n");
                break;
            case 4:
                while ((c = getchar()) != '\n' && c != EOF);  // Flush STDIN
                printf("Enter username: ");
                fgets(player->userName, sizeof(player->userName), stdin);
                
                // Clear trailing newline
                size_t len = strlen(player->userName);
                if (len > 0 && player->userName[len - 1] == '\n') {
                    player->userName[len - 1] = '\0';
                }
                break;
            case 5:
                exit(0);
                break;
        }
    }

    return 0;
}