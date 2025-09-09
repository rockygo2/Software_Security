#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "noaslr.h"

#include "aes.h"

#define IV "zos4teiVLei5Seih"
#define KEYFILE "/var/challenge/level5/key"
#define KEYSIZE 16
#define PASSWORDFILE "/var/challenge/level5/passwords"
#define PASSWORDSIZE 64

struct authentication {
  uid_t uid_new;
  uid_t uid_orig;
  unsigned char iv[KEYSIZE];
  unsigned char key[KEYSIZE];
  char passwordplain[PASSWORDSIZE];
  unsigned char passwordcrypt[PASSWORDSIZE];
  unsigned char correctcrypt[PASSWORDSIZE];
};

static void readhex(FILE *file, unsigned char *buf, size_t size) {
  int c;
  int index = 0;
  unsigned char value;

  memset(buf, 0, size);
  for (;;) {
	c = fgetc(file);
	if (c >= '0' && c <= '9') {
		value = c - '0';
	} else if (c >= 'a' && c <= 'f') {
		value = c - 'a' + 10;
	} else {
		if (c >= 0) ungetc(c, file);
		break;
	}
	if (index >= size * 2) {
		fprintf(stderr, "hex value too long\n");
		exit(1);
	}
	if (index % 2 == 0) value <<= 4;
	buf[index / 2] |= value;
	index++;
  }

  if (index != size * 2) {
	fprintf(stderr, "hex value too short\n");
	exit(1);
  }
}

static void getkey(const char *path, struct authentication *auth) {
  FILE *file;

  file = fopen(path, "r");
  if (!file) {
	perror("cannot open key file");
	exit(1);
  }

  readhex(file, auth->key, sizeof(auth->key));

  fclose(file);
}

static void readstring(char *buffer, size_t size, int *eof) {
  int c;
  int index = 0;

  memset(buffer, 0, size);
  while (index < size) {
	c = getchar();
	if (c < 0 || c == '\n') break;
	buffer[index++] = c;
  }

  if (c < 0) *eof = 1;
}

static void getpassword(struct authentication *auth) {
  char correct[64];
  int eof = 0;

  printf("enter password: ");
  for (;;) {
	readstring(auth->passwordplain, sizeof(auth->passwordplain), &eof);
	printf("your password is: ");
	printf(auth->passwordplain);
	printf("\n");
	printf("is this correct? (y/n)\n");
	readstring(correct, sizeof(correct), &eof);
	if (strcmp(correct, "y") == 0 || eof) break;
	printf("try again then: ");
  }
}

static uid_t readuid(FILE *file) {
  int c;
  uid_t result = 0;

  for (;;) {
	c = fgetc(file);
	if (c < '0' || c > '9') {
		if (c >= 0) ungetc(c, file);
		break;
	}
	result = result * 10 + c - '0';
  }

  return result;
}

static int skipwhitespace(FILE *file) {
  int c;

  for (;;) {
	c = fgetc(file);
	if (c < 0) return 0;
	if (!isspace(c)) break;
  }

  ungetc(c, file);
  return 1;
}

static void getcorrect(const char *path, struct authentication *auth) {
  FILE *file;
  uid_t uid_line;

  file = fopen(path, "r");
  if (!file) {
	perror("cannot open password file");
	exit(1);
  }

  do {
	if (!skipwhitespace(file)) {
		fprintf(stderr, "unknown uid\n");
		exit(1);
	}
	uid_line = readuid(file);
	skipwhitespace(file);
	readhex(file, auth->correctcrypt, sizeof(auth->correctcrypt));
  } while (uid_line != auth->uid_orig);

  fclose(file);
}

static void encryptpassword(struct authentication *auth) {
  AES128_CBC_encrypt_buffer(
	auth->passwordcrypt,
	(unsigned char *) auth->passwordplain,
	sizeof(auth->passwordcrypt),
	auth->key,
	auth->iv);
}

static void checkpassword(struct authentication *auth) {
  if (memcmp(auth->passwordcrypt, auth->correctcrypt, sizeof(auth->correctcrypt)) != 0) {
	fprintf(stderr, "bad password\n");
	exit(1);
  }
}

static void changeuser(struct authentication *auth) {
  if (setuid(auth->uid_new) != 0) {
	fprintf(stderr, "failed to become root\n");
	exit(1);
  }
}

int main(int argc, char **argv, char **envp) {
  struct authentication auth = {
	.uid_new = 0,
	.uid_orig = getuid(),
	.iv = IV,
  };
  struct authentication *authptr = &auth;

  getkey(KEYFILE, authptr);
  getpassword(authptr);
  encryptpassword(authptr);
  getcorrect(PASSWORDFILE, authptr);
  checkpassword(authptr);
  changeuser(authptr);

  printf("access granted\n");
  execv(argv[1], argv + 1);

  return 0;
}
