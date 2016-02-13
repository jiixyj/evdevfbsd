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

#include "util.h"


struct uhid_backend {
  int fd;
  report_desc_t report_desc;
  char desc[1024];
  char path[32];

  hid_item_t hiditems[1024];
  uint16_t hiditem_slots[1024];
  uint16_t hiditem_types[1024];
  int32_t *hiditem_array[1024];
  size_t hiditems_used;
};

static const struct {
  int32_t x;
  int32_t y;
} hat_to_axis[] = {{0, 0}, {0, -1}, {1, -1}, {1, 0},  {1, 1},
                   {0, 1}, {-1, 1}, {-1, 0}, {-1, -1}};

#define KU KEY_UNKNOWN

static const unsigned char hid_to_evdev[256] = {
    0,   0,   0,   0,   30,  48,  46,  32,  18,  33,  34,  35,  23,  36,  37,
    38,  50,  49,  24,  25,  16,  19,  31,  20,  22,  47,  17,  45,  21,  44,
    2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  28,  1,   14,  15,  57,
    12,  13,  26,  27,  43,  43,  39,  40,  41,  51,  52,  53,  58,  59,  60,
    61,  62,  63,  64,  65,  66,  67,  68,  87,  88,  99,  70,  119, 110, 102,
    104, 111, 107, 109, 106, 105, 108, 103, 69,  98,  55,  74,  78,  96,  79,
    80,  81,  75,  76,  77,  71,  72,  73,  82,  83,  86,  127, 116, 117, 183,
    184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 134, 138, 130, 132,
    128, 129, 131, 137, 133, 135, 136, 113, 115, 114, KU,  KU,  KU,  121, KU,
    89,  93,  124, 92,  94,  95,  KU,  KU,  KU,  122, 123, 90,  91,  85,  KU,
    KU,  KU,  KU,  KU,  KU,  KU,  111, KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,
    KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,
    KU,  KU,  179, 180, KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,
    KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,  KU,
    KU,  KU,  KU,  KU,  KU,  KU,  111, KU,  KU,  KU,  KU,  KU,  KU,  KU,  29,
    42,  56,  125, 97,  54,  100, 126, 164, 166, 165, 163, 161, 115, 114, 113,
    150, 158, 159, 128, 136, 177, 178, 176, 142, 152, 173, 140, KU,  KU,  KU,
    KU};

#undef KU

static void *uhid_fill_function(struct event_device *ed) {
  struct uhid_backend *b = ed->priv_ptr;

  bool use_rid = !!hid_get_report_id(b->fd);

  int dlen = hid_report_size(b->report_desc, hid_input, -1);
  if (dlen <= 0) {
    return NULL;
  }

  for (;;) {
    uint8_t dbuf[1024] = {0};

    if (use_rid) {
      if (read(b->fd, dbuf, 1) != 1) {
        break;
      }
      dlen = hid_report_size(b->report_desc, hid_input, dbuf[0]);
      if (dlen <= 1) {
        break;
      }
      --dlen;
    }

    if ((unsigned)dlen > sizeof(dbuf) - 1) {
      abort();
    }
    if (read(b->fd, use_rid ? &dbuf[1] : dbuf, (unsigned)dlen) != dlen) {
      break;
    }
#if 0
    if (use_rid) {
      ++dlen;
    }
    for (size_t i = 0; i < (unsigned)dlen; ++i) {
      printf("%02x ", dbuf[i]);
    }
    printf("\n");
#endif

    struct timeval tv;
    get_clock_value(ed, &tv);

    if (use_rid && dbuf[0] != 1) {
      continue;
    }

    pthread_mutex_lock(&ed->event_buffer_mutex); // XXX

    event_client_need_free_bufsize(ed, 32);

    for (size_t i = 0; i < b->hiditems_used; ++i) {
      hid_item_t h = b->hiditems[i];
      uint16_t slot = b->hiditem_slots[i];
      uint16_t type = b->hiditem_types[i];

      int32_t data = hid_get_data(dbuf, &h);
      char const *usage_page = hid_usage_page(HID_PAGE(h.usage));
      char const *usage_in_page = hid_usage_in_page(h.usage);

      if (!strcmp(usage_page, "Keyboard")) {
        if (h.report_count == 1) {
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
              for (int p = 0; p < h.report_count; ++p) {
                if (data == old_keys[p]) {
                  is_in_old_data = true;
                  break;
                }
              }

              if (!is_in_old_data && hid_to_evdev[data]) {
                put_event(ed, &tv, EV_KEY, hid_to_evdev[data], 1);
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
            if (!is_in_new_data && hid_to_evdev[old_keys[r]]) {
              put_event(ed, &tv, EV_KEY, hid_to_evdev[old_keys[r]], 0);
            }
          }
          for (int r = 0; r < h.report_count; ++r) {
            old_keys[r] = new_keys[r];
          }
        }
      } else if (!strcmp(usage_page, "Button")) {
        put_event(ed, &tv, EV_KEY, slot, data);
      } else if (!strcmp(usage_page, "Generic_Desktop")) {
        if (!strcmp(usage_in_page, "X") || !strcmp(usage_in_page, "Y") ||
            !strcmp(usage_in_page, "Z") || !strcmp(usage_in_page, "Rz")) {
          put_event(ed, &tv, type, slot, data);
        } else if (!strcmp(usage_in_page, "Hat_Switch")) {
          int hat_dir = (data - h.logical_minimum) * 8 /
                            (h.logical_maximum - h.logical_minimum + 1) +
                        1;
          if (hat_dir < 0 || hat_dir > 8) {
            hat_dir = 0;
          }
          put_event(ed, &tv, EV_ABS, slot, hat_to_axis[hat_dir].x);
          put_event(ed, &tv, EV_ABS, slot + 1, hat_to_axis[hat_dir].y);
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

    put_event(ed, &tv, EV_SYN, SYN_REPORT, 0);
    cuse_poll_wakeup();

    pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
  }

  return NULL;
}

int uhid_backend_init(struct event_device *ed, char const *path) {
  ed->priv_ptr = malloc(sizeof(struct uhid_backend));
  if (!ed->priv_ptr)
    return -1;

  struct uhid_backend *b = ed->priv_ptr;

  b->fd = open(path, O_RDONLY);
  if (b->fd == -1)
    goto fail;

  hid_init(NULL);

  b->report_desc = hid_get_report_desc(b->fd);
  if (b->report_desc == 0)
    goto fail;

  bool use_rid = !!hid_get_report_id(b->fd);

  int dlen = hid_report_size(b->report_desc, hid_input, -1);
  if (dlen <= 0) {
    goto fail;
  }

  uint8_t dbuf[1024] = {0};

  // TODO: remove goto logic
reread:;
  struct pollfd pfd = {b->fd, POLLIN, 0};
  int ret;
  do {
    ret = poll(&pfd, 1, 500);
  } while (ret == -1 && errno == EINTR);
  if (ret <= 0 || !(pfd.revents & POLLIN)) {
    printf("skip initial HID packet...\n");
    goto skip_reading;
  }

  if (use_rid) {
    if (read(b->fd, dbuf, 1) != 1) {
      goto fail;
    }
    dlen = hid_report_size(b->report_desc, hid_input, dbuf[0]);
    if (dlen <= 1) {
      goto fail;
    }
    --dlen;
  }

  if ((unsigned)dlen > sizeof(dbuf) - 1) {
    abort();
  }
  if (read(b->fd, use_rid ? &dbuf[1] : dbuf, (unsigned)dlen) != dlen) {
    goto fail;
  }
  if (use_rid && dbuf[0] != 1) {
    goto reread;
  }

skip_reading:
  b->hiditems_used = 0;
  memset(b->hiditem_types, '\0', sizeof(b->hiditem_types));

  struct hid_data *d;
  struct hid_item h;

  int collection_stack = 0;
  char const* application_usage = NULL;
  char const* physical_usage = NULL;

  for (d = hid_start_parse(b->report_desc, 1 << hid_input, -1);
       hid_get_item(d, &h);) {
    switch (h.kind) {
    case hid_collection:
      if (h.collection == 1) {
        application_usage = hid_usage_in_page(h.usage);
      } else if (h.collection == 0) {
        physical_usage = hid_usage_in_page(h.usage);
      }

      ++collection_stack;
      break;
    case hid_endcollection:
      --collection_stack;
      break;
    case hid_input: {

      int32_t data = hid_get_data(dbuf, &h);
      char const *usage_page = hid_usage_page(HID_PAGE(h.usage));
      char const *usage_in_page = hid_usage_in_page(h.usage);
      uint32_t usage = HID_USAGE(h.usage);

      if (!strcmp(usage_page, "Keyboard")) {
        if (h.report_count == 1) {
          if (usage < 256) {
            if (!hid_to_evdev[usage]) {
              break;
            }
            b->hiditems[b->hiditems_used] = h;
            int slot = b->hiditem_slots[b->hiditems_used] =
                hid_to_evdev[usage];
            ++b->hiditems_used;

            set_bit(ed->event_bits, EV_KEY);
            set_bit(ed->key_bits, slot);
            ed->key_state[slot] = data;
          } else {
            // TODO: fix reporting of unknown keys
          }
        } else if (h.report_count > 1 && usage == 0) {
          if (h.logical_minimum > h.logical_maximum) {
            break;
          }
          b->hiditems[b->hiditems_used] = h;
          b->hiditem_slots[b->hiditems_used] = 0;
          b->hiditem_array[b->hiditems_used] =
              calloc((uint32_t)h.report_count * sizeof(int), 1);
          if (!b->hiditem_array[b->hiditems_used]) {
            goto fail;
          }
          ++b->hiditems_used;
          for (int i = h.logical_minimum; i <= h.logical_maximum; ++i) {
            if (i < 0 || i > 255 || !hid_to_evdev[i]) {
              continue;
            }
            set_bit(ed->event_bits, EV_KEY);
            set_bit(ed->key_bits, hid_to_evdev[i]);
          }
        }
      } else if (!strcmp(usage_page, "Button")) {
        if (application_usage == NULL) {
          goto fail;
        }

        b->hiditems[b->hiditems_used] = h;
        int slot;

        if (!strcmp(application_usage, "Mouse")) {
          slot = b->hiditem_slots[b->hiditems_used] =
              (uint16_t)(BTN_MOUSE + (int)usage - 1);
        } else if (!strcmp(application_usage, "Joystick")) {
          slot = b->hiditem_slots[b->hiditems_used] =
              (uint16_t)(BTN_JOYSTICK + (int)usage - 1);
        } else {
          goto fail;
        }

        ++b->hiditems_used;

        set_bit(ed->event_bits, EV_KEY);
        set_bit(ed->key_bits, slot);
        ed->key_state[slot] = data;
      } else if (!strcmp(usage_page, "Generic_Desktop")) {
        if (!strcmp(usage_in_page, "X") || !strcmp(usage_in_page, "Y") ||
            !strcmp(usage_in_page, "Z") || !strcmp(usage_in_page, "Rz")) {
          b->hiditems[b->hiditems_used] = h;
          int slot = b->hiditem_slots[b->hiditems_used] = usage & 0x0f;

          if (h.flags & HIO_RELATIVE) {
            b->hiditem_types[b->hiditems_used] = EV_REL;
            set_bit(ed->event_bits, EV_REL);
            set_bit(ed->rel_bits, slot);
          } else {
            b->hiditem_types[b->hiditems_used] = EV_ABS;
            set_bit(ed->event_bits, EV_ABS);
            set_bit(ed->abs_bits, slot);
            ed->abs_state[slot] = data;
            ed->abs_info[slot].value = data;
            ed->abs_info[slot].minimum = h.logical_minimum;
            ed->abs_info[slot].maximum = h.logical_maximum;
            ed->abs_info[slot].fuzz =
                (h.logical_maximum - h.logical_minimum) >> 8;
            ed->abs_info[slot].flat =
                (h.logical_maximum - h.logical_minimum) >> 4;
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
          // TODO: there can be multiple slider/wheels that should map to
          // different slots.
          b->hiditems[b->hiditems_used] = h;
          int slot = b->hiditem_slots[b->hiditems_used] = usage & 0x0f;

          if (h.flags & HIO_RELATIVE) {
            b->hiditem_types[b->hiditems_used] = EV_REL;
            set_bit(ed->event_bits, EV_REL);
            set_bit(ed->rel_bits, slot);
          } else {
            b->hiditem_types[b->hiditems_used] = EV_ABS;
            set_bit(ed->event_bits, EV_ABS);
            set_bit(ed->abs_bits, slot);
            ed->abs_state[slot] = data;
            ed->abs_info[slot].value = data;
            ed->abs_info[slot].minimum = h.logical_minimum;
            ed->abs_info[slot].maximum = h.logical_maximum;
            ed->abs_info[slot].fuzz =
                (h.logical_maximum - h.logical_minimum) >> 8;
            ed->abs_info[slot].flat =
                (h.logical_maximum - h.logical_minimum) >> 4;
          }

          ++b->hiditems_used;
        }
      } else if (!strcmp(usage_page, "Consumer")) {
        if (!strcmp(usage_in_page, "AC_Pan")) {
          b->hiditems[b->hiditems_used] = h;
          int slot = b->hiditem_slots[b->hiditems_used] = REL_HWHEEL;
          b->hiditem_types[b->hiditems_used] = EV_REL;

          set_bit(ed->event_bits, EV_REL);
          set_bit(ed->rel_bits, slot);
          ++b->hiditems_used;
        }
      }
      break;
    }
    case hid_output:
    case hid_feature:
      break;
    }

    if (collection_stack == 0) {
      break;
    }
  }
  hid_end_parse(d);

  memset(b->desc, '\0', sizeof(b->desc));
  size_t siz = sizeof(b->desc) - 1;
  char sysctl_name[64] = {0};
  snprintf(sysctl_name, sizeof(sysctl_name), "dev.uhid.%c.%%desc", path[9]);
  if (sysctlbyname(sysctl_name, b->desc, &siz, NULL, 0) == -1) {
    perror("sysctlbyname");
    goto fail;
  }
  ed->device_name = b->desc;

  ed->fill_function = uhid_fill_function;
  ed->backend_type = UHID_BACKEND;

  return 1;
fail:
  free(ed->priv_ptr);
  return -1;
}
