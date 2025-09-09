#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>

#define LEVEL "3"

char argument[200] = "";
char filename[200] = "";

int main(int argc, char **argv) {

  if (!argv[1] || !argv[2]) {
    fprintf(stderr, "Please provide the program name and argument\n");
    return 1;
  }

  sprintf(filename, "/var/challenge/level"LEVEL"/%s", basename(argv[1]));
  if (access(filename, X_OK)) {
    fprintf(stderr, "You do not have the permission to execute this file\n");
    return 1;
  }

  strcpy(argument, argv[2]);

  printf("Executing filename %s\n", filename);
  execlp(filename, filename, argument, (char *)0);

  return 0;
}
  
  
  
  
