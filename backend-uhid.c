#include "backend-uhid.h"

#include <sys/types.h>
#include <sys/sysctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include "util.h"


struct uhid_backend {
  int fd;
  report_desc_t report_desc;
  char desc[1024];
  char path[32];

  hid_item_t hiditems[1024];
  uint16_t hiditem_slots[1024];
  uint16_t hiditem_types[1024];
  size_t hiditems_used;
};


int uhid_backend_init(struct event_device *ed, char const *path) {
  ed->priv_ptr = malloc(sizeof(struct uhid_backend));
  if (!ed->priv_ptr)
    return 1;

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

  uint8_t *dbuf = calloc((unsigned)dlen, 1);
  if (!dbuf) {
    goto fail;
  }

reread:
  if (read(b->fd, dbuf, (unsigned)dlen) != dlen) {
    goto fail;
  }
  if (use_rid && dbuf[0] != 1) {
    goto reread;
  }

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

      if (!strcmp(usage_page, "Button")) {
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
  free(dbuf);

  memset(b->desc, '\0', sizeof(b->desc));
  size_t siz = sizeof(b->desc) - 1;
  char sysctl_name[64] = {0};
  snprintf(sysctl_name, sizeof(sysctl_name), "dev.uhid.%c.%%desc", path[9]);
  if (sysctlbyname(sysctl_name, b->desc, &siz, NULL, 0) == -1) {
    perror("sysctlbyname");
    goto fail;
  }
  ed->device_name = b->desc;

  return 0;
fail:
  free(ed->priv_ptr);
  return 1;
}

static const struct {
  int32_t x;
  int32_t y;
} hat_to_axis[] = {{0, 0}, {0, -1}, {1, -1}, {1, 0},  {1, 1},
                             {0, 1}, {-1, 1}, {-1, 0}, {-1, -1}};

void *uhid_fill_function(struct event_device *ed) {
  struct uhid_backend *b = ed->priv_ptr;

  bool use_rid = !!hid_get_report_id(b->fd);

  int dlen = hid_report_size(b->report_desc, hid_input, -1);
  if (dlen <= 0) {
    return NULL;
  }

  uint8_t *dbuf = calloc((unsigned)dlen, 1);
  if (!dbuf) {
    return NULL;
  }

  while (read(b->fd, dbuf, (unsigned)dlen) == dlen) {
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

      if (!strcmp(usage_page, "Button")) {
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
      }
    }

    put_event(ed, &tv, EV_SYN, SYN_REPORT, 0);
    cuse_poll_wakeup();

    pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
  }

  free(dbuf);

  return NULL;
}
