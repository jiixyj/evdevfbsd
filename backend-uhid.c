#include "backend-uhid.h"

#include <sys/sysctl.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <dev/usb/usbhid.h>
#include <usbhid.h>
#include <libusb20.h>
#include <libusb20_desc.h>

#include "util.h"

struct uhid_backend {
	report_desc_t report_desc;
	char desc[1024];
	char path[32];

	hid_item_t hiditems[1024];
	uint16_t hiditem_slots[1024];
	uint16_t hiditem_types[1024];
	int32_t *hiditem_array[1024];
	size_t hiditems_used;

	char const *application_usage;
	char const *physical_usage;

	struct event_device *rid_to_ed[256];
};

static const struct {
	int32_t x;
	int32_t y;
} hat_to_axis[] = {{0, 0}, {0, -1}, {1, -1}, {1, 0}, {1, 1}, {0, 1}, {-1, 1},
    {-1, 0}, {-1, -1}};

#define KU KEY_UNKNOWN

static const unsigned char hid_to_evdev[256] = {0, 0, 0, 0, 30, 48, 46, 32, 18,
    33, 34, 35, 23, 36, 37, 38, 50, 49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45,
    21, 44, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 28, 1, 14, 15, 57, 12, 13, 26, 27,
    43, 43, 39, 40, 41, 51, 52, 53, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
    87, 88, 99, 70, 119, 110, 102, 104, 111, 107, 109, 106, 105, 108, 103, 69,
    98, 55, 74, 78, 96, 79, 80, 81, 75, 76, 77, 71, 72, 73, 82, 83, 86, 127,
    116, 117, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 134,
    138, 130, 132, 128, 129, 131, 137, 133, 135, 136, 113, 115, 114, KU, KU,
    KU, 121, KU, 89, 93, 124, 92, 94, 95, KU, KU, KU, 122, 123, 90, 91, 85, KU,
    KU, KU, KU, KU, KU, KU, 111, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU,
    KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, 179, 180, KU, KU,
    KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU,
    KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, KU, 111, KU, KU, KU, KU, KU, KU,
    KU, 29, 42, 56, 125, 97, 54, 100, 126, 164, 166, 165, 163, 161, 115, 114,
    113, 150, 158, 159, 128, 136, 177, 178, 176, 142, 152, 173, 140, KU, KU,
    KU, KU};

#undef KU

static void
parse_hid_item(struct event_device *ed, struct event_plus_times tv,
    uint8_t *dbuf, size_t i)
{
	struct uhid_backend *b = ed->priv_ptr;

	hid_item_t h = b->hiditems[i];
	uint16_t slot = b->hiditem_slots[i];
	uint16_t type = b->hiditem_types[i];

	int32_t data = hid_get_data(dbuf, &h);
	char const *usage_page = hid_usage_page(HID_PAGE(h.usage));
	char const *usage_in_page = hid_usage_in_page(h.usage);

	if (!strcmp(usage_page, "Keyboard")) {
		if (h.report_count == 1) {
			if (ed->key_state[slot] != data) {
				put_event(ed, &tv, EV_MSC, MSC_SCAN,
				    (int32_t)h.usage);
			}
			put_event(ed, &tv, EV_KEY, slot, data);
		} else if (h.report_count > 1) {
			int32_t new_keys[128] = {0};
			if (h.report_count > 128) {
				abort();
			}
			int32_t *old_keys = b->hiditem_array[i];
			uint32_t old_pos = h.pos;
			for (int r = 0; r < h.report_count; ++r) {
				data = hid_get_data(dbuf, &h);

				if (data >= 0 && data <= 255) {
					new_keys[r] = data;
					bool is_in_old_data = false;
					for (int p = 0; p < h.report_count;
					     ++p) {
						if (data == old_keys[p]) {
							is_in_old_data = true;
							break;
						}
					}

					if (!is_in_old_data &&
					    hid_to_evdev[data]) {
						if (ed->key_state[slot] != 1) {
							put_event(ed, &tv,
							    EV_MSC, MSC_SCAN,
							    (int32_t)h.usage);
						}
						put_event(ed, &tv, EV_KEY,
						    hid_to_evdev[data], 1);
					}
				}

				if (h.report_size < 0) {
					abort();
				}
				h.pos += (uint32_t)h.report_size;
			}
			h.pos = old_pos;

			for (int r = 0; r < h.report_count; ++r) {
				bool is_in_new_data = false;
				for (int p = 0; p < h.report_count; ++p) {
					if (old_keys[r] == new_keys[p]) {
						is_in_new_data = true;
						break;
					}
				}
				if (!is_in_new_data &&
				    hid_to_evdev[old_keys[r]]) {
					if (ed->key_state[slot] != 0) {
						put_event(ed, &tv, EV_MSC,
						    MSC_SCAN,
						    (int32_t)h.usage);
					}
					put_event(ed, &tv, EV_KEY,
					    hid_to_evdev[old_keys[r]], 0);
				}
			}
			for (int r = 0; r < h.report_count; ++r) {
				old_keys[r] = new_keys[r];
			}
		}
	} else if (!strcmp(usage_page, "Button")) {
		if (ed->key_state[slot] != data) {
			put_event(ed, &tv, EV_MSC, MSC_SCAN, (int32_t)h.usage);
		}
		put_event(ed, &tv, EV_KEY, slot, data);
	} else if (!strcmp(usage_page, "Generic_Desktop")) {
		if (!strcmp(usage_in_page, "X") ||
		    !strcmp(usage_in_page, "Y") ||
		    !strcmp(usage_in_page, "Z") ||
		    !strcmp(usage_in_page, "Rz")) {
			put_event(ed, &tv, type, slot, data);
		} else if (!strcmp(usage_in_page, "Hat_Switch")) {
			int hat_dir = 1 +
			    (data - h.logical_minimum) * 8 /
				(h.logical_maximum - h.logical_minimum + 1);
			if (hat_dir < 0 || hat_dir > 8) {
				hat_dir = 0;
			}
			put_event(
			    ed, &tv, EV_ABS, slot, hat_to_axis[hat_dir].x);
			put_event(
			    ed, &tv, EV_ABS, slot + 1, hat_to_axis[hat_dir].y);
		} else if (!strcmp(usage_in_page, "Slider") ||
		    !strcmp(usage_in_page, "Wheel")) {
			put_event(ed, &tv, type, slot, data);
		}
	} else if (!strcmp(usage_page, "Consumer")) {
		if (!strcmp(usage_in_page, "AC_Pan")) {
			put_event(ed, &tv, type, slot, data);
		}
	}
}

static int
uhid_read_packet(struct event_device *ed)
{
	struct uhid_backend *b = ed->priv_ptr;

	bool use_rid = !!hid_get_report_id(ed->fd);

	int dlen = hid_report_size(b->report_desc, hid_input, -1);
	if (dlen <= 0) {
		return -1;
	}

	ssize_t ret;

	if (use_rid && ed->packet_pos == 0) {
		if ((ret = read(ed->fd, ed->packet_buf, 1)) == -1 &&
		    errno == EAGAIN) {
			return 1;
		}
		if (ret != 1) {
			return -1;
		}
		ed->packet_pos = 1;

		dlen = hid_report_size(
		    b->report_desc, hid_input, ed->packet_buf[0]);
		if (dlen <= 1) {
			return -1;
		}
	}

	if ((unsigned)dlen > sizeof(ed->packet_buf) - 1) {
		return -1;
	}

	do {
		ret = read(ed->fd, &ed->packet_buf[ed->packet_pos],
		    (unsigned)dlen - ed->packet_pos);

		if (ret == -1) {
			return errno == EAGAIN ? 1 : -1;
		} else {
			ed->packet_pos += (size_t)ret;
		}
	} while (ed->packet_pos != (unsigned)dlen);

	return 0;
}

static int
uhid_parse_packet(struct event_device *ed)
{
	struct uhid_backend *b = ed->priv_ptr;

	bool use_rid = !!hid_get_report_id(ed->fd);

	struct event_device *ev_ed = ed;
	if (use_rid) {
		ev_ed = b->rid_to_ed[ed->packet_buf[0]];
	}

	if (!ev_ed) {
		return 1;
	}

	event_client_need_free_bufsize(ev_ed, 32);

	for (size_t i = 0; i < b->hiditems_used; ++i) {
		if (use_rid && b->hiditems[i].report_ID != ed->packet_buf[0]) {
			continue;
		}
		parse_hid_item(ev_ed, ed->packet_time, ed->packet_buf, i);
	}

	put_event(ev_ed, &ed->packet_time, EV_SYN, SYN_REPORT, 0);
	return 0;
}

static int
parse_input_descriptor(
    struct event_device *ed, struct hid_item h)
{
	struct uhid_backend *b = ed->priv_ptr;

	char const *usage_page = hid_usage_page(HID_PAGE(h.usage));
	char const *usage_in_page = hid_usage_in_page(h.usage);
	uint32_t usage = HID_USAGE(h.usage);

	if (!strcmp(usage_page, "Keyboard")) {
		if (h.report_count == 1) {
			if (usage < 256) {
				if (!hid_to_evdev[usage]) {
					return 0;
				}
				b->hiditems[b->hiditems_used] = h;
				int slot = b->hiditem_slots[b->hiditems_used] =
				    hid_to_evdev[usage];
				++b->hiditems_used;

				set_bit(ed->event_bits, EV_KEY);
				set_bit(ed->key_bits, slot);
				set_bit(ed->event_bits, EV_MSC);
				set_bit(ed->msc_bits, MSC_SCAN);
			} else {
				// TODO: fix reporting of unknown keys
			}
		} else if (h.report_count > 1 && usage == 0) {
			if (h.logical_minimum > h.logical_maximum) {
				return 0;
			}
			b->hiditems[b->hiditems_used] = h;
			b->hiditem_slots[b->hiditems_used] = 0;
			b->hiditem_array[b->hiditems_used] =
			    calloc((uint32_t)h.report_count * sizeof(int), 1);
			if (!b->hiditem_array[b->hiditems_used]) {
				return -1;
			}
			++b->hiditems_used;
			for (int i = h.logical_minimum; i <= h.logical_maximum;
			     ++i) {
				if (i < 0 || i > 255 || !hid_to_evdev[i]) {
					continue;
				}
				set_bit(ed->event_bits, EV_KEY);
				set_bit(ed->key_bits, hid_to_evdev[i]);
				set_bit(ed->event_bits, EV_MSC);
				set_bit(ed->msc_bits, MSC_SCAN);
			}
		}
	} else if (!strcmp(usage_page, "Button")) {
		if (b->application_usage == NULL) {
			return -1;
		}

		b->hiditems[b->hiditems_used] = h;
		int slot;

		if (!strcmp(b->application_usage, "Mouse")) {
			slot = b->hiditem_slots[b->hiditems_used] =
			    (uint16_t)(BTN_MOUSE + (int)usage - 1);
		} else if (!strcmp(b->application_usage, "Joystick")) {
			slot = b->hiditem_slots[b->hiditems_used] =
			    (uint16_t)(BTN_JOYSTICK + (int)usage - 1);
		} else {
			return -1;
		}

		++b->hiditems_used;

		set_bit(ed->event_bits, EV_KEY);
		set_bit(ed->key_bits, slot);
		set_bit(ed->event_bits, EV_MSC);
		set_bit(ed->msc_bits, MSC_SCAN);
	} else if (!strcmp(usage_page, "Generic_Desktop")) {
		if (!strcmp(usage_in_page, "X") ||
		    !strcmp(usage_in_page, "Y") ||
		    !strcmp(usage_in_page, "Z") ||
		    !strcmp(usage_in_page, "Rz")) {
			b->hiditems[b->hiditems_used] = h;
			int slot = b->hiditem_slots[b->hiditems_used] =
			    usage & 0x0f;

			if (h.flags & HIO_RELATIVE) {
				b->hiditem_types[b->hiditems_used] = EV_REL;
				set_bit(ed->event_bits, EV_REL);
				set_bit(ed->rel_bits, slot);
			} else {
				b->hiditem_types[b->hiditems_used] = EV_ABS;
				set_bit(ed->event_bits, EV_ABS);
				set_bit(ed->abs_bits, slot);
				ed->abs_info[slot].minimum = h.logical_minimum;
				ed->abs_info[slot].maximum = h.logical_maximum;
				ed->abs_info[slot].fuzz =
				    (h.logical_maximum - h.logical_minimum) >>
				    8;
				ed->abs_info[slot].flat =
				    (h.logical_maximum - h.logical_minimum) >>
				    4;
			}

			++b->hiditems_used;
		} else if (!strcmp(usage_in_page, "Hat_Switch")) {
			b->hiditems[b->hiditems_used] = h;
			b->hiditem_slots[b->hiditems_used] = ABS_HAT0X;
			++b->hiditems_used;

			set_bit(ed->event_bits, EV_ABS);
			for (int slot = ABS_HAT0X; slot <= ABS_HAT0Y; ++slot) {
				set_bit(ed->abs_bits, slot);
				// TODO: set these to proper value
				ed->abs_state[slot] = 0;
				ed->abs_info[slot].value = 0;
				ed->abs_info[slot].minimum = -1;
				ed->abs_info[slot].maximum = 1;
			}
		} else if (!strcmp(usage_in_page, "Slider") ||
		    !strcmp(usage_in_page, "Wheel")) {
			// TODO: there can be multiple slider/wheels that
			// should map to
			// different slots.
			b->hiditems[b->hiditems_used] = h;
			int slot = b->hiditem_slots[b->hiditems_used] =
			    usage & 0x0f;

			if (h.flags & HIO_RELATIVE) {
				b->hiditem_types[b->hiditems_used] = EV_REL;
				set_bit(ed->event_bits, EV_REL);
				set_bit(ed->rel_bits, slot);
			} else {
				b->hiditem_types[b->hiditems_used] = EV_ABS;
				set_bit(ed->event_bits, EV_ABS);
				set_bit(ed->abs_bits, slot);
				ed->abs_info[slot].minimum = h.logical_minimum;
				ed->abs_info[slot].maximum = h.logical_maximum;
				ed->abs_info[slot].fuzz =
				    (h.logical_maximum - h.logical_minimum) >>
				    8;
				ed->abs_info[slot].flat =
				    (h.logical_maximum - h.logical_minimum) >>
				    4;
			}

			++b->hiditems_used;
		}
	} else if (!strcmp(usage_page, "Consumer")) {
		if (!strcmp(usage_in_page, "AC_Pan")) {
			b->hiditems[b->hiditems_used] = h;
			int slot = b->hiditem_slots[b->hiditems_used] =
			    REL_HWHEEL;
			b->hiditem_types[b->hiditems_used] = EV_REL;

			set_bit(ed->event_bits, EV_REL);
			set_bit(ed->rel_bits, slot);
			++b->hiditems_used;
		}
	}

	return 0;
}

int
uhid_backend_init(struct event_device *ed, char const *path)
{
	ed->priv_ptr = malloc(sizeof(struct uhid_backend));
	if (!ed->priv_ptr)
		return -1;

	struct uhid_backend *b = ed->priv_ptr;

	ed->iid.bustype = BUS_USB;

	ed->fd = open(path, O_RDONLY | O_NONBLOCK);
	if (ed->fd == -1)
		goto fail;

	hid_init(NULL);

	b->report_desc = hid_get_report_desc(ed->fd);
	if (b->report_desc == 0)
		goto fail;

	b->hiditems_used = 0;
	memset(b->hiditem_types, '\0', sizeof(b->hiditem_types));

	memset(b->desc, '\0', sizeof(b->desc));
	{
		char sysctl_name[64] = {0};
		snprintf(sysctl_name, sizeof(sysctl_name),
		    "dev.uhid.%c.%%location", path[9]);

		char line[1024] = {0};
		size_t line_size = sizeof(line) - 1;

		if (sysctlbyname(sysctl_name, line, &line_size, NULL, 0) ==
		    -1) {
			perror("sysctlbyname");
			goto fail;
		}

		char const *bus = strstr(line, "bus=");
		char const *devaddr = strstr(line, "devaddr=");
		if (!bus || !devaddr) {
			goto fail;
		}

		bus += 4;
		devaddr += 8;

		int bus_int = 0;
		int devaddr_int = 0;

		if (sscanf(bus, "%d", &bus_int) <= 0 ||
		    sscanf(devaddr, "%d", &devaddr_int) <= 0) {
			goto fail;
		}

		char line1[1024] = {0};
		char line2[1024] = {0};

		struct libusb20_backend *pbe;
		pbe = libusb20_be_alloc_default();
		if (pbe == NULL) {
			goto fail;
		}

		struct libusb20_device *pdev = NULL;
		while ((pdev = libusb20_be_device_foreach(pbe, pdev))) {
			if (libusb20_dev_get_bus_number(pdev) == bus_int &&
			    libusb20_dev_get_address(pdev) == devaddr_int) {
				if (libusb20_dev_open(pdev, 0)) {
					libusb20_be_free(pbe);
					goto fail;
				}

				struct LIBUSB20_DEVICE_DESC_DECODED *ddesc;
				ddesc = libusb20_dev_get_device_desc(pdev);

				libusb20_dev_req_string_simple_sync(pdev,
				    ddesc->iManufacturer, line1,
				    sizeof(line1));
				libusb20_dev_req_string_simple_sync(pdev,
				    ddesc->iProduct, line2, sizeof(line2));

				ed->iid.vendor = ddesc->idVendor;
				ed->iid.product = ddesc->idProduct;
				ed->iid.version = ddesc->bcdUSB;

				libusb20_dev_close(pdev);

				break;
			}
		}

		libusb20_be_free(pbe);

		snprintf(b->desc, sizeof(b->desc), "%s %s", line1, line2);
	}
	ed->device_name = b->desc;

	struct hid_data *d;
	struct hid_item h;

	int collection_stack = 0;
	b->application_usage = NULL;
	b->physical_usage = NULL;

	size_t ed_index = 0;
	bool use_rid = !!hid_get_report_id(ed->fd);
	memset(b->rid_to_ed, '\0', sizeof(b->rid_to_ed));

	for (d = hid_start_parse(b->report_desc, 1 << hid_input, -1);
	     hid_get_item(d, &h);) {
		switch (h.kind) {
		case hid_collection:
			if (h.collection == 1) {
				b->application_usage =
				    hid_usage_in_page(h.usage);

				if (collection_stack == 0) {
					// Each Joystick should get its own
					// device.
					if (!strcmp(b->application_usage,
						"Joystick")) {
						ed[ed_index].device_name =
						    ed->device_name;
						ed[ed_index].priv_ptr = b;
					} else if (ed_index > 0) {
						--ed_index;
					}
				}
			} else if (h.collection == 0) {
				b->physical_usage = hid_usage_in_page(h.usage);
			}

			++collection_stack;
			break;
		case hid_endcollection:
			--collection_stack;
			if (collection_stack == 0) {
				++ed_index;
			}

			break;
		case hid_input: {
			if (use_rid) {
				b->rid_to_ed[h.report_ID] = &ed[ed_index];
			}
			int ret = parse_input_descriptor(&ed[ed_index], h);
			if (ret == -1) {
				goto fail;
			}
			break;
		}
		case hid_output:
		case hid_feature:
			break;
		}

		if (ed_index == 8) {
			break;
		}
	}
	hid_end_parse(d);

	b->application_usage = NULL;
	b->physical_usage = NULL;

	ed->read_packet = uhid_read_packet;
	ed->parse_packet = uhid_parse_packet;
	ed->backend_type = UHID_BACKEND;

	return (int) ed_index;
fail:
	free(ed->priv_ptr);
	return -1;
}
