#include "backend-atkbd.h"

#include <sys/kbio.h>
#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include "util.h"

#define AT_ACK 0xfa
#define AT_NAK 0xfe
#define AT_BAT 0xaa
#define AT_ES0 0xe0
#define AT_ES1 0xe1
#define AT_REL 0xf0
#define AT_HANJA 0xf1
#define AT_HANGEUL 0xf2
#define AT_ERR 0xff

// those could be both a release event and a "normal" key press or control code
static const uint16_t ambivalent_keys[] = {
    AT_BAT, AT_ERR, AT_ACK, AT_NAK, AT_HANJA, AT_HANGEUL};

struct atkbd_state {
	int escape;
	bool release_extraction_state[nitems(ambivalent_keys)];
};

struct atkbd_backend {
	int vkbd_fd;
	struct atkbd_state atkbd;
};

static const uint16_t scan_to_evdev[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
    59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77,
    78, 79, 80, 81, 82, 83, 99, 0, 86, 87, 88, 117, 0, 0, 95, 183, 184, 185, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 93, 0, 0, 89, 0, 0, 85, 91,
    90, 92, 0, 94, 0, 124, 121, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 165, 0, 0, 0, 0, 0, 0, 0, 0, 163, 0, 0, 96, 97, 0, 0, 113, 140, 164, 0,
    166, 0, 0, 0, 0, 0, 255, 0, 0, 0, 114, 0, 115, 0, 172, 0, 0, 98, 255, 99,
    100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 119, 119, 102, 103, 104, 0, 105,
    112, 106, 118, 107, 108, 109, 110, 111, 0, 0, 0, 0, 0, 0, 0, 125, 126, 127,
    116, 142, 0, 0, 0, 143, 0, 217, 156, 173, 128, 159, 158, 157, 155, 226, 0,
    112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 123, 122, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static uint16_t
raw_to_scan(int escape, uint16_t code)
{
	return (uint16_t)(
	    (code & 0x7f) | ((code & 0x80) << 1) | (escape == 1 ? 0x80 : 0));
}

static bool
release_extraction_needed(struct atkbd_state *atkbd, uint16_t code)
{
	if (code == AT_ES0 || code == AT_ES1) {
		return false;
	}

	for (unsigned i = 0; i < nitems(ambivalent_keys); ++i) {
		if (code == ambivalent_keys[i]) {
			return atkbd->release_extraction_state[i];
		}
	}

	return true;
}

static void
calculate_release_extraction_state(struct atkbd_state *atkbd, uint16_t code)
{
	for (unsigned i = 0; i < nitems(ambivalent_keys); ++i) {
		// check if the release of this key can be mistaken
		// for one of the ambivalent keys
		if (((code ^ ambivalent_keys[i]) & 0x7f) == 0) {
			if (code & 0x80) {
				atkbd->release_extraction_state[i] = false;
			} else {
				// key has been pressed, need to extract
				// release bit when released
				atkbd->release_extraction_state[i] = true;
			}
			break;
		}
	}
}

static void
detach_atkbd()
{
	system("kbdcontrol -K < /dev/console"
	       " > /dev/null 2> /dev/null");
	system("kbdcontrol -A atkbd0 < /dev/kbdmux0"
	       " > /dev/null 2> /dev/null");
	system("kbdcontrol -k /dev/kbdmux0 < /dev/console"
	       " > /dev/null 2> /dev/null");
}

static void
reattach_atkbd_part1()
{
	system("kbdcontrol -K < /dev/console"
	       " > /dev/null 2> /dev/null");
	system("kbdcontrol -A vkbd0 < /dev/kbdmux0"
	       " > /dev/null 2> /dev/null");
}

static void
reattach_atkbd_part2()
{
	system("kbdcontrol -a atkbd0 < /dev/kbdmux0"
	       " > /dev/null 2> /dev/null");
	system("kbdcontrol -k /dev/kbdmux0 < /dev/console"
	       " > /dev/null 2> /dev/null");
}

static bool
write_keycode(int fd, unsigned int kc)
{
	ssize_t len = write(fd, &kc, sizeof(kc));

	if (len != sizeof(kc))
		return false;

	return true;
}

static int
atkbd_read_packet(struct event_device *ed)
{
	ssize_t ret = read(ed->fd, ed->packet_buf, 1);

	if (ret == -1 && errno == EAGAIN) {
		return 1;
	} else if (ret != 1) {
		return -1;
	}

	ed->packet_pos = 1;
	return 0;
}

static int
atkbd_parse_packet(struct event_device *ed)
{
	struct atkbd_backend *b = ed->priv_ptr;

	uint8_t raw_code = ed->packet_buf[0];

	event_client_need_free_bufsize(ed, 8);

	uint16_t code = raw_code;
	bool release = false;
	if (b->atkbd.escape || release_extraction_needed(&b->atkbd, code)) {
		release = code >> 7;
		code &= 0x7f;
	}
	if (!b->atkbd.escape) {
		calculate_release_extraction_state(&b->atkbd, raw_code);
	}

	if (code == AT_ES0) {
		b->atkbd.escape = 1;
		return 1;
	} else if (code == AT_ES1) {
		b->atkbd.escape = 2;
		return 1;
	} else if (code == AT_BAT || code == AT_REL || code == AT_ACK ||
	    code == AT_NAK || code == AT_ERR) {
		fprintf(stderr, "unexpected control code: %d\n", +code);
		return 1;
	}

	code = raw_to_scan(b->atkbd.escape, code);

	if (b->atkbd.escape > 0) {
		--b->atkbd.escape;
		if (b->atkbd.escape > 0)
			return 1;
	}

	uint16_t evdev_code = scan_to_evdev[code];
	if (evdev_code != 255) {
		put_event(ed, &ed->packet_time, EV_MSC, MSC_SCAN, code);
	}

	if (evdev_code == 255) {
		return 1;
	} else if (evdev_code == 0) {
		fprintf(stderr, "unknown key encountered\n");
		put_event(ed, &ed->packet_time, EV_SYN, SYN_REPORT, 0);
	} else {
		int evdev_value;
		if (release) {
			evdev_value = 0;
		} else if (ed->key_state[evdev_code]) {
			evdev_value = 2;
		} else {
			evdev_value = 1;
		}

		put_event(ed, &ed->packet_time, EV_KEY, evdev_code, evdev_value);
		put_event(ed, &ed->packet_time, EV_SYN, SYN_REPORT, 0);

		if (evdev_value && (code == AT_HANJA || code == AT_HANGEUL)) {
			put_event(ed, &ed->packet_time, EV_MSC, MSC_SCAN, code);
			put_event(ed, &ed->packet_time, EV_KEY, evdev_code, 0);
			put_event(ed, &ed->packet_time, EV_SYN, SYN_REPORT, 0);
		}
	}

	if (!write_keycode(b->vkbd_fd, raw_code))
		return -1;

	return 0;
}

void
atkbd_backend_cleanup(struct event_device *ed)
{
	struct atkbd_backend *b = ed->priv_ptr;

	reattach_atkbd_part1();

	if (ed->fd != -1)
		close(ed->fd);

	if (b->vkbd_fd != -1)
		close(b->vkbd_fd);

	reattach_atkbd_part2();
}

int
atkbd_backend_init(struct event_device *ed)
{
	ed->priv_ptr = malloc(sizeof(struct atkbd_backend));
	if (!ed->priv_ptr)
		return -1;

	struct atkbd_backend *b = ed->priv_ptr;

	ed->iid.bustype = BUS_I8042;
	ed->iid.vendor = 0x01;
	ed->iid.product = 0x01;
	ed->device_name = "AT Translated Set 2 keyboard";

	memset(&b->atkbd, 0, sizeof(b->atkbd));

	b->vkbd_fd = open("/dev/vkbdctl0", O_RDWR);
	if (b->vkbd_fd == -1)
		goto fail;

	detach_atkbd();

	ed->fd = open("/dev/atkbd0", O_RDWR);
	if (ed->fd == -1 || ioctl(ed->fd, KDSKBMODE, K_RAW) == -1) {
		reattach_atkbd_part1();

		if (ed->fd != -1)
			close(ed->fd);
		close(b->vkbd_fd);

		reattach_atkbd_part2();

		goto fail;
	}

	set_bit(ed->event_bits, EV_KEY);
	for (unsigned i = 0; i < nitems(scan_to_evdev); ++i) {
		if (scan_to_evdev[i] != 0 && scan_to_evdev[i] != 255)
			set_bit(ed->key_bits, scan_to_evdev[i]);
	}
	set_bit(ed->event_bits, EV_MSC);
	set_bit(ed->msc_bits, MSC_SCAN);

	ed->read_packet = atkbd_read_packet;
	ed->parse_packet = atkbd_parse_packet;
	ed->backend_type = ATKBD_BACKEND;

	return 1;
fail:
	free(ed->priv_ptr);
	return -1;
}
