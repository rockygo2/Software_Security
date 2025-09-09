#ifndef SCENES_H
#define SCENES_H

#define MAX_CHOICES 9

typedef struct {
    const char *choiceText;
    int nextScene;
} Choice;

typedef struct {
    const char *name;
    const char *text;
    int numChoices;
    Choice choices[MAX_CHOICES];
} Scene;

extern const Scene scenes[];
extern const int numScenes;

#endif
