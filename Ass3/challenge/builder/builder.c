#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "player.h"

void admin() {
    if (system("/bin/sh") == -1) {
        perror("system");
        exit(1);
    }
}

int debug = 0;

void print_hex(char* ptr) {
    for (int i = 7; i >= 0; i--)
        printf("%02hhx", ptr[i]);
}

uint64_t read_hex() {
    uint64_t res = 0;
    char buffer[20];
    fgets(buffer, 20, stdin);

    int i = 0;
    while (i < 20 && buffer[i] != '\n') {
        if ('0' <= buffer[i] && buffer[i] <= '9')
            res = res * 16 + buffer[i] - '0';
        else
            res = res * 16 + buffer[i] - 'a' + 10;
        i++;
    }

    return res;
}

void print_info(const char* names[3], void* values[3]) {
    for (int i = 0; i < 3; i++) {
        printf("\t%s (", names[i]);
        print_hex((char*)&values[i]);
        printf(")\n");
    }
}

void build_player(struct player* p) {
    const char* name_class[3] = {"Tank", "Ranger", "Mage"};
    void (*init_class[3])(struct player*) = 
        {init_tank, init_ranger, init_mage};

    const char* name_weapon[3] = {"axe", "bow", "staff"};
    void (*attack_weapon[3])(struct player*) = 
        {attack_axe, attack_bow, attack_staff};

    const char* name_faction[3] = {"orc", "elf", "gnome"};
    void (*cast_faction[3])(struct player*, int) = 
        {cast_orc, cast_elf, cast_gnome};

    printf("What is your name?\n");
    fgets(p->name, 64, stdin);
    for (int i = 0; i < 64; i++)
        if (p->name[i] == '\n')
            p->name[i] = '\0';

    printf("Choose a class! (introduce the identifier)\n");
    print_info(name_class, 
            (void**)init_class);
    p->init = (void*)read_hex();

    printf("Choose a weapon! (introduce the identifier)\n");
    print_info(name_weapon, 
            (void**)attack_weapon);
    p->attack= (void*)read_hex();

    printf("Choose a class! (introduce the identifier)\n");
    print_info(name_faction, 
            (void**)cast_faction);
    p->cast = (void*)read_hex();

    printf("You're all ready! Good luck!\n");
}

int main(int argc, char** argv, char** envp) {
    if (setregid(getegid(), -1) == -1) {
        perror("setregid");
        exit(1);
    }

    setbuf(stdout, NULL);
    srand(time(NULL));

    if (argc == 2 && (strcmp(argv[1], "-d") == 0 ||
            strcmp(argv[1], "--debug") == 0)) {
        debug = 1;
        fprintf(stderr, "Debug mode on!\n");
    }

    printf("Quest: Defeat the boss\n");
    printf("Build your own character!\n");
    
    struct player p;
    if (debug) debug_player(&p);

    build_player(&p);

    if (debug) debug_player(&p);

    p.init(&p);
    fprintf(stderr, "%d\n", p.health);

    while (p.health > 0 && boss_health > 0) {
        int choice;
        printf("%s: %d/%d health; %d/%d power points\n", p.name, p.health, 
                p.maxhealth, p.pp, p.maxpp);
        printf("Boss has %d health remaining\n", boss_health);
        printf("Choose an action!\n1: attack; 2: special; 3: give up\n> ");
        scanf("%d", &choice);

        if (choice == 1)
            p.attack(&p);
        else if (choice == 2) {
            int action;
            printf("Choose what spell you want to cast!\n> ");
            scanf("%d", &action);

            p.cast(&p, action);
        } else if (choice == 3) {
            p.health = -1;
        } else {
            printf("You don't know what you want to do. Because of your indecision, "
                    "the boss still makes a move.\n");
        }

        p.health -= 3;
        p.pp++;
        if (p.pp > p.maxpp)
            p.pp = p.maxpp;
    }

    if (p.health <= 0)
        printf("You lost!\n");
    else
        printf("You won, the world is finally safe!");

    return 0;
}
