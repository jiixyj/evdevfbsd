#ifndef INPUT_DETECTION_H_
#define INPUT_DETECTION_H_

#include <stdbool.h>
#include <stdio.h>

#include <dev/evdev/input.h>

#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define NBITS(x) ((((x)-1) / BITS_PER_LONG) + 1)

struct input_id_input {
	unsigned long bitmask_ev[NBITS(EV_MAX)];
	unsigned long bitmask_abs[NBITS(ABS_MAX)];
	unsigned long bitmask_key[NBITS(KEY_MAX)];
	unsigned long bitmask_rel[NBITS(REL_MAX)];
	unsigned long bitmask_props[NBITS(INPUT_PROP_MAX)];
	struct input_absinfo xabsinfo;
	struct input_absinfo yabsinfo;
};

enum input_ids {
	ID_INPUT,
	ID_INPUT_ACCELEROMETER,
	ID_INPUT_POINTINGSTICK,
	ID_INPUT_MOUSE,
	ID_INPUT_TOUCHPAD,
	ID_INPUT_TOUCHSCREEN,
	ID_INPUT_JOYSTICK,
	ID_INPUT_TABLET,
	ID_INPUT_KEY,
	ID_INPUT_KEYBOARD,
	ID_INPUT_SWITCH,
	ID_INPUT_WIDTH_MM,
	ID_INPUT_HEIGHT_MM,
	ID_MAX
};

struct input_id_output {
	bool ids[ID_MAX];
	int64_t width;
	int64_t height;
};

int fill_input_id_input(int fd, struct input_id_input *input);
void input_id(struct input_id_input *input, struct input_id_output *output);
void print_output(FILE *file, struct input_id_output *output);

#endif
