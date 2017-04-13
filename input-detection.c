#include "input-detection.h"

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#define OFF(x) ((x) % BITS_PER_LONG)
#define LONG(x) ((x) / BITS_PER_LONG)
#define test_bit(bit, array) ((array[LONG(bit)] >> OFF(bit)) & 1)

void
print_output(FILE *file, struct input_id_output *output)
{
	for (int i = 0; i < ID_MAX; ++i) {
		if (output->ids[i]) {
			char const *str = NULL;

			switch (i) {
			case ID_INPUT:
				str = "inp";
				break;
			case ID_INPUT_ACCELEROMETER:
				str = "acc";
				break;
			case ID_INPUT_POINTINGSTICK:
				str = "stk";
				break;
			case ID_INPUT_MOUSE:
				str = "mou";
				break;
			case ID_INPUT_TOUCHPAD:
				str = "tpd";
				break;
			case ID_INPUT_TOUCHSCREEN:
				str = "tsc";
				break;
			case ID_INPUT_JOYSTICK:
				str = "joy";
				break;
			case ID_INPUT_TABLET:
				str = "tab";
				break;
			case ID_INPUT_KEY:
				str = "key";
				break;
			case ID_INPUT_KEYBOARD:
				str = "kbd";
				break;
			case ID_INPUT_SWITCH:
				str = "swi";
				break;
			case ID_INPUT_WIDTH_MM:
				fprintf(
				    file, "%lld:", (long long)output->width);
				str = "wmm";
				break;
			case ID_INPUT_HEIGHT_MM:
				fprintf(
				    file, "%lld:", (long long)output->height);
				str = "hww";
				break;
			default:
				abort();
			}
			fprintf(file, "%s ", str);
		}
	}
	fprintf(file, "\n");
}

static bool
is_input(struct input_id_input *input __unused)
{
	return (true);
}

static bool
is_accelerometer(struct input_id_input *input)
{
	unsigned long const *bitmask_ev = input->bitmask_ev;
	unsigned long const *bitmask_abs = input->bitmask_abs;
	unsigned long const *bitmask_props = input->bitmask_props;

	return (test_bit(INPUT_PROP_ACCELEROMETER, bitmask_props) ||
	    (!test_bit(EV_KEY, bitmask_ev) && test_bit(ABS_X, bitmask_abs) &&
	        test_bit(ABS_Y, bitmask_abs) && test_bit(ABS_Z, bitmask_abs)));
}

static bool
is_pointingstick(struct input_id_input *input)
{
	unsigned long const *bitmask_props = input->bitmask_props;

	return (test_bit(INPUT_PROP_POINTING_STICK, bitmask_props) &&
	    !is_accelerometer(input));
}

static bool
has_abs_coord(struct input_id_input *input)
{
	unsigned long const *bitmask_abs = input->bitmask_abs;

	return (test_bit(ABS_X, bitmask_abs) && test_bit(ABS_Y, bitmask_abs));
}

static bool
has_mt_coord(struct input_id_input *input)
{
	unsigned long const *bitmask_abs = input->bitmask_abs;

	return (test_bit(ABS_MT_POSITION_X, bitmask_abs) &&
	    test_bit(ABS_MT_POSITION_Y, bitmask_abs) &&
	    (!test_bit(ABS_MT_SLOT, bitmask_abs) ||
	        !test_bit(ABS_MT_SLOT - 1, bitmask_abs)));
}

static bool
is_tablet(struct input_id_input *input)
{
	unsigned long const *bitmask_key = input->bitmask_key;

	return (test_bit(BTN_STYLUS, bitmask_key) ||
	           test_bit(BTN_TOOL_PEN, bitmask_key)) &&
	    (has_abs_coord(input) || has_mt_coord(input)) &&
	    !is_accelerometer(input);
}

static bool
is_touchpad(struct input_id_input *input)
{
	unsigned long const *bitmask_key = input->bitmask_key;
	unsigned long const *bitmask_props = input->bitmask_props;

	return (test_bit(BTN_TOOL_FINGER, bitmask_key) &&
	    !test_bit(INPUT_PROP_DIRECT, bitmask_props) &&
	    (has_abs_coord(input) || has_mt_coord(input)) &&
	    !is_accelerometer(input) && !is_tablet(input));
}

static bool
is_mouse(struct input_id_input *input)
{
	unsigned long const *bitmask_ev = input->bitmask_ev;
	unsigned long const *bitmask_rel = input->bitmask_rel;
	unsigned long const *bitmask_key = input->bitmask_key;

	return (test_bit(BTN_LEFT, bitmask_key) &&
	    ((test_bit(EV_REL, bitmask_ev) && test_bit(REL_X, bitmask_rel) &&
	         test_bit(REL_Y, bitmask_rel)) ||
	        (has_abs_coord(input) && !is_tablet(input) &&
	            !is_touchpad(input))) &&
	    !is_accelerometer(input));
}

static bool
is_touchscreen(struct input_id_input *input)
{
	unsigned long const *bitmask_key = input->bitmask_key;
	unsigned long const *bitmask_props = input->bitmask_props;

	return (test_bit(BTN_TOUCH, bitmask_key) ||
	           test_bit(INPUT_PROP_DIRECT, bitmask_props)) &&
	    ((has_abs_coord(input) && !is_mouse(input)) ||
	        has_mt_coord(input)) &&
	    !is_accelerometer(input) && !is_tablet(input) &&
	    !is_touchpad(input);
}

static bool
is_joystick(struct input_id_input *input)
{
	unsigned long const *bitmask_abs = input->bitmask_abs;
	unsigned long const *bitmask_key = input->bitmask_key;

	return (has_abs_coord(input) &&
	    (test_bit(BTN_TRIGGER, bitmask_key) ||
	        test_bit(BTN_A, bitmask_key) || //
	        test_bit(BTN_1, bitmask_key) ||
	        test_bit(ABS_RX, bitmask_abs) ||
	        test_bit(ABS_RY, bitmask_abs) ||
	        test_bit(ABS_RZ, bitmask_abs) ||
	        test_bit(ABS_THROTTLE, bitmask_abs) ||
	        test_bit(ABS_RUDDER, bitmask_abs) ||
	        test_bit(ABS_WHEEL, bitmask_abs) ||
	        test_bit(ABS_GAS, bitmask_abs) ||
	        test_bit(ABS_BRAKE, bitmask_abs)) &&
	    !is_accelerometer(input) && !is_tablet(input) &&
	    !is_touchpad(input) && !is_mouse(input) && !is_touchscreen(input));
}

static bool
is_pointer(struct input_id_input *input)
{
	return (is_tablet(input) || is_joystick(input) ||
	    is_touchscreen(input) || is_touchpad(input) || is_mouse(input) ||
	    is_pointingstick(input) || is_accelerometer(input));
}

static bool
is_key(struct input_id_input *input)
{
	unsigned long const *bitmask_ev = input->bitmask_ev;
	unsigned long const *bitmask_key = input->bitmask_key;
	unsigned long const *bitmask_rel = input->bitmask_rel;

	if (test_bit(EV_KEY, bitmask_ev)) {
		for (unsigned i = 0; i < KEY_CNT; ++i) {
			if ((i < BTN_MISC ||
			        (i >= KEY_OK && i < BTN_DPAD_UP) ||
			        (i >= KEY_ALS_TOGGLE &&
			            i < BTN_TRIGGER_HAPPY)) &&
			    test_bit(i, bitmask_key)) {
				return (true);
			}
		}
	}
	if (test_bit(EV_REL, bitmask_ev) &&
	    (test_bit(REL_WHEEL, bitmask_rel) ||
	        test_bit(REL_HWHEEL, bitmask_rel)) &&
	    !is_pointer(input)) {
		return (true);
	}
	return (false);
}

static bool
is_keyboard(struct input_id_input *input)
{
	unsigned long const *bitmask_ev = input->bitmask_ev;
	unsigned long const *bitmask_key = input->bitmask_key;

	return (test_bit(EV_KEY, bitmask_ev) &&
	    (bitmask_key[0] & 0xFFFFFFFE) == 0xFFFFFFFE);
}

static bool
is_switch(struct input_id_input *input)
{
	unsigned long const *bitmask_ev = input->bitmask_ev;

	return (test_bit(EV_SW, bitmask_ev));
}

static bool
has_width_height_mm(struct input_id_input *input)
{

	return (has_abs_coord(input) && //
	    input->xabsinfo.resolution > 0 &&
	    input->yabsinfo.resolution > 0 &&
	    input->xabsinfo.maximum >= input->xabsinfo.minimum &&
	    input->yabsinfo.maximum >= input->yabsinfo.minimum);
}

static int64_t
get_touchpad_size_in_mm(struct input_absinfo *absinfo)
{
	return ((int64_t)absinfo->maximum - (int64_t)absinfo->minimum) /
	    absinfo->resolution;
}

void
input_id(struct input_id_input *input, struct input_id_output *output)
{

	memset(output, '\0', sizeof(*output));

	for (int i = 0; i < ID_MAX; ++i) {
		switch (i) {
		case ID_INPUT:
			output->ids[i] = is_input(input);
			break;
		case ID_INPUT_ACCELEROMETER:
			output->ids[i] = is_accelerometer(input);
			break;
		case ID_INPUT_POINTINGSTICK:
			output->ids[i] = is_pointingstick(input);
			break;
		case ID_INPUT_MOUSE:
			output->ids[i] = is_mouse(input);
			break;
		case ID_INPUT_TOUCHPAD:
			output->ids[i] = is_touchpad(input);
			break;
		case ID_INPUT_TOUCHSCREEN:
			output->ids[i] = is_touchscreen(input);
			break;
		case ID_INPUT_JOYSTICK:
			output->ids[i] = is_joystick(input);
			break;
		case ID_INPUT_TABLET:
			output->ids[i] = is_tablet(input);
			break;
		case ID_INPUT_KEY:
			output->ids[i] = is_key(input);
			break;
		case ID_INPUT_KEYBOARD:
			output->ids[i] = is_keyboard(input);
			break;
		case ID_INPUT_SWITCH:
			output->ids[i] = is_switch(input);
			break;
		case ID_INPUT_WIDTH_MM:
			if (has_width_height_mm(input)) {
				output->ids[i] = true;
				output->width =
				    get_touchpad_size_in_mm(&input->xabsinfo);
			}
			break;
		case ID_INPUT_HEIGHT_MM:
			if (has_width_height_mm(input)) {
				output->ids[i] = true;
				output->height =
				    get_touchpad_size_in_mm(&input->yabsinfo);
			}
			break;
		default:
			abort();
		}
	}
}

#ifdef STANDALONE

int
main(int argc, char **argv)
{
	if (argc != 2) {
		return 1;
	}

	struct input_id_input input;
	memset(&input, '\0', sizeof(input));

	int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		return 1;
	}

	if (ioctl(fd, EVIOCGBIT(0, sizeof(input.bitmask_ev)),
	        input.bitmask_ev) == -1 ||
	    ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(input.bitmask_key)),
	        input.bitmask_key) == -1 ||
	    ioctl(fd, EVIOCGBIT(EV_REL, sizeof(input.bitmask_rel)),
	        input.bitmask_rel) == -1 ||
	    ioctl(fd, EVIOCGBIT(EV_ABS, sizeof(input.bitmask_abs)),
	        input.bitmask_abs) == -1 ||
	    ioctl(fd, EVIOCGPROP(sizeof(input.bitmask_props)),
	        input.bitmask_props) == -1) {
		fprintf(stderr, "error getting device info\n");
		return 1;
	}

	if (has_abs_coord(&input)) {
		if (ioctl(fd, EVIOCGABS(ABS_X), &input.xabsinfo) == -1 ||
		    ioctl(fd, EVIOCGABS(ABS_Y), &input.yabsinfo) == -1) {
			fprintf(stderr, "error getting device info\n");
			return 1;
		}
	}

	struct input_id_output output;

	input_id(&input, &output);
	print_output(stderr, &output);
}

#endif
