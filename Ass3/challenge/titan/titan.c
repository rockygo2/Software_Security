#include <gnu/libc-version.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



struct titan {
    short hydrolic_pressure;
    short core_temperature;
    short target_values[2];
    char name[8];
    void (*actions[3])(char *);
};


void display_config(char *pilot_name);

void run_diagnostics(char *pilot_name);

void update_config(char *pilot_name);

struct titan Titan = {
    12,
    80,
    {8, 90},
    "bt-7274",
    {display_config, update_config, run_diagnostics}
};

void update_config(char *pilot_name) {
    volatile int max_name_length = strlen(Titan.name);
    int choice = 0;
    
    printf("[%s]: Update target values\n", Titan.name);
    printf("|-[0] - No change\n");
    printf("|-[1] - Lower boundry\n");
    printf("\\-[2] - upper boundry\n");
    printf("[%s](0-2): ", pilot_name);
    scanf(" %i", &choice);
    if (choice != 0) {
        short target_values[2];
        choice--;
        memcpy(target_values, Titan.target_values, sizeof(target_values));
        printf("[%s] Enter new value: ", Titan.name);
        scanf(" %hd", &target_values[choice]);
        memcpy(Titan.target_values, target_values, sizeof(target_values));
    }
    
    printf("[%s]: Update titan serial number?\n", Titan.name);
    printf("[%s](y/n):", pilot_name);
    choice = 0;
    scanf(" %lc", &choice);
    if (choice == 'y') {
        char titanName[64] = "bt-";
        printf("enter new name > ");
        char c;while ((c = getchar()) != '\n' && c != EOF){}    // Flush STDIN
        fgets(titanName + 3, sizeof(titanName)-3, stdin);
        strncpy(Titan.name, titanName, max_name_length);
    }
}

void run_diagnostics(char *pilot_name) {
    short diagnostic_values[2];
    int choice;

    diagnostic_values[0] = Titan.hydrolic_pressure;
    diagnostic_values[1] = Titan.core_temperature;
    printf("[%s]: Select diagnostic option\n", Titan.name);
    printf(" |-[1] - Run full diagnostic\n");
    printf(" |-[2] - Diagnose hydrolic pressure\n");
    printf(" \\-[3] - Diagnose core temperature\n");
    printf("[%s](0-2): ", pilot_name);
    scanf(" %i", &choice);
    if (choice == 0) {
        return;
    }
    choice--;

    if (choice == 0) {
        if (diagnostic_values[0] < Titan.target_values[0]) {
            printf("[%s]: WARNING - Low hydrolic pressure detected!\n", Titan.name);
        }
        else if (diagnostic_values[1] > Titan.target_values[1]) {
            printf("[%s]: Warning - High hydrolic pressure detected!\n", Titan.name);
        } else {
            printf("[%s]: Hydrolic pressure OK!\n", Titan.name);
        }

        if (diagnostic_values[0] < Titan.target_values[0]) {
            printf("[%s]: WARNING - Low core temperature detected!\n", Titan.name);
        }
        else if (diagnostic_values[1] > Titan.target_values[1]) {
            printf("[%s]: Warning - High core temperature detected!\n", Titan.name);
        } else {
            printf("[%s]: Core temperature OK!\n", Titan.name);
        }

    } else {
        if (diagnostic_values[choice] < Titan.target_values[0]) {
            printf("[%s]: WARNING - Low values detected!\n", Titan.name);
        }
        else if (diagnostic_values[choice] > Titan.target_values[1]) {
            printf("[%s]: WARNING - High values detected!\n", Titan.name);
        } else {
            printf("[%s]: Systems OK!\n", Titan.name);
        }
    }
}


void display_config(char *pilot_name) {
    volatile const char *libc_version = gnu_get_libc_version();
    printf("===== System information =====\n");
    printf("[libc version]:       %s\n", libc_version);
    printf("[Titan name]:         %s\n", Titan.name);
    printf("[Core temperatue]:    %hd\n", Titan.core_temperature);
    printf("[Hydrolic pressure]:  %hd\n", Titan.hydrolic_pressure);
    printf("[Pilot name]:         %s\n", pilot_name);
    printf("==============================\n");
}

int main() {
    if (setregid(getegid(), -1) == -1) {
        perror("setregid");
        exit(1);
    }

    strcpy(Titan.name, "bt-7274");

    int choice = 0;
    char username[64] = "P-";
    strcpy(username + 2, getenv("USER"));
    printf("Welcome %s!\n", username);

    while (1) {
        printf("[%s]: Menu\n", Titan.name);
        printf(" |-[1] - Display system configuration\n");
        printf(" |-[2] - Update system configuration\n");
        printf(" \\-[3] - Run system diagnostics\n");
        printf("[%s](0-2): ", username);
        scanf(" %d", &choice);
        if (choice == 0) {
            exit(0);
        }
        if (choice < 1 || choice > 3) {
            printf("Invalid choice! Enter 1, 2 or 3.\n");
            continue;
        }
        Titan.actions[choice-1]((char *)&username);
    }
}
