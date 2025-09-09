#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "noaslr.h"

struct params {
	char user[40], host[80];
};

void safecpy(char *to, const char *from, int maxlen) {
	if (strlen(from) > maxlen) abort();
	strcpy(to, from);
}

void readparams(struct params *params) {
	memset(params, 0, sizeof(struct params)); /* clear buffer */
	safecpy(params->user, getenv("USERNAME"), sizeof(params->user));
	safecpy(params->host, getenv("HOSTNAME"), sizeof(params->host));
}

int main(int argc, char **argv, char **envp) {
	char greeting[160];
	struct params params;

	readparams(&params);

	greeting[0] = 0;
	strcat(greeting, "hi ");
	strcat(greeting, params.user);
	strcat(greeting, "! welcome to ");
	strcat(greeting, params.host);

	printf("%s\n", greeting);
	return 0;
}
