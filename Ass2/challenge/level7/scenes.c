#include "scenes.h"

const Scene scenes[] = {
    { "L6", "As you bend over your microscope you start feeling unwell, a headache starts building as you hear the biohazard containment breach alarm go off down the hallway.", 1, {
        { "Investigate the hallway.", 8 },
    } },
    { "L5", "As you enter L5 you spot your empty lunch box and keycard on the table. Right where you left it.", 1, {
        { "Return to the hallway.", 8 },
    } },
    { "L4", "This labratory looks empty.", 1, {
        { "Return to the hallway.", 8 },
    } },
    { "backrooms", "You are in the backrooms. How did you get here? What is your purpose now?", 1, {
        { "Cry.", 3 },
    } },
    { "L3", "This labratory looks empty.", 1, {
        { "Return to the hallway.", 8 },
    } },
    { "L2", "As you walk into the labratory you see a picture hanging on the whiteboard.", 1, {
        { "Return to the hallway.", 8 },
    } },
    { "L1", "You see the source of infection, a broken vial rests on the floor, its contents spilled out and exposed to the air. At the mere sight you feel your body shutting down.", 1, {
        { "Return to the hallway.", 8 },
    } },
    { "fridge", "As you walk into the fridge you frantically search around for something useful, stumbling upon an EHBO box.", 1, {
        { "Return to the hallway.", 8 },
    } },
    { "hallway", "The hallway looks desserted, all doors are wide open except for the one blocking access to decontamination.", 8, {
        { "Investigate L1 ", 6 },
        { "Investigate L2 ", 5 },
        { "Investigate L3 ", 4 },
        { "Investigate L4 ", 2 },
        { "Investigate L5 ", 1 },
        { "return to L6 ", 0 },
        { "Investigate the walk-in fridge ", 7 },
        { "Go to the decontamination room [keycard required] ", 9 },
    } },
    { "decontamination", "As you hit the decontamination process you feel steam cleansing your skin, you caugh into your lab coat only to find blood staining the pristine white fabric.", 2, {
        { "Return to the hallway.", 8 },
        { "Proceed to the lockers.", 10 },
    } },
    { "lockers", "The lockers are all locked, there is nothing here that will help you.", 3, {
        { "Go to cafeteria.", 12 },
        { "Go to the garage.", 13 },
        { "Go to the storage.", 11 },
    } },
    { "storage", "The storage looks deserted, everything here must have been moved recently. Luckily the EHBO box is still where it should be.", 1, {
        { "Investigate the hallway.", 8 },
    } },
    { "cafeteria", "As you stumble into the cafeteria, barely able to walk, you see car keys laying on the table.", 1, {
        { "Return to lockers.", 10 },
    } },
    { "garage", "Through your blurry vision you spot a car, an escape to get help.", 2, {
        { "Return to the lockers.", 10 },
        { "Get in the car.", 14 },
    } },
    { "car", "As you start the car and drive away at full speed you nearly pass out, after a few minutes you are too delusional to keep control over the vehicle and pass out, the car coming to a rest at the hospital enterance. When you awaken you are in a mobile quarantine unit, rapidly being treated.", 0, {
    } },
};

const int numScenes = 15;
