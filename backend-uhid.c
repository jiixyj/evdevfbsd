#include "backend-uhid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include "backend-psm.h"
#include "util.h"

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

  int dlen = hid_report_size(b->report_desc, hid_input, -1);
  if (dlen <= 0) {
    goto fail;
  }

  uint8_t *dbuf = calloc((unsigned)dlen, 1);
  if (!dbuf) {
    goto fail;
  }

  if (read(b->fd, dbuf, (unsigned)dlen) != dlen) {
    goto fail;
  }

  struct hid_data *d;
  struct hid_item h;

  bool end_collection = false;

  for (d = hid_start_parse(b->report_desc, 1 << hid_input, -1);
       hid_get_item(d, &h);) {
    switch (h.kind) {
    case hid_collection:
      break;
    case hid_endcollection:
      end_collection = true;
      break;
    case hid_input: {
      char const *usage_page = hid_usage_page(HID_PAGE(h.usage));
      char const *usage_in_page = hid_usage_in_page(h.usage);
      uint32_t usage = HID_USAGE(h.usage);
      if (!strcmp(usage_page, "Button")) {
        set_bit(ed->event_bits, EV_KEY);
        set_bit(ed->key_bits, BTN_JOYSTICK + (int)usage - 1);
      } else if (!strcmp(usage_page, "Generic_Desktop")) {
        if (!strcmp(usage_in_page, "X") || !strcmp(usage_in_page, "Y") ||
            !strcmp(usage_in_page, "Z") || !strcmp(usage_in_page, "Rz")) {
          set_bit(ed->event_bits, EV_ABS);
          int slot = usage & 0x0f;
          set_bit(ed->abs_bits, slot);
          ed->abs_info[slot].minimum = h.logical_minimum;
          ed->abs_info[slot].maximum = h.logical_maximum;
          ed->abs_info[slot].fuzz =
              (h.logical_maximum - h.logical_minimum) >> 8;
          ed->abs_info[slot].flat =
              (h.logical_maximum - h.logical_minimum) >> 4;
          // ed->abs_state[slot] = 128;
        }
      }
      break;
    }
    case hid_output:
    case hid_feature:
      break;
    }

    if (end_collection) {
      break;
    }
  }
  hid_end_parse(d);
  free(dbuf);

  return 0;
fail:
  free(ed->priv_ptr);
  return 1;
}

void *uhid_fill_function(struct event_device *ed) {
  struct uhid_backend *b = ed->priv_ptr;

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

    if (dbuf[0] != 1) {
      continue;
    }

    pthread_mutex_lock(&ed->event_buffer_mutex); // XXX

    event_client_need_free_bufsize(ed, 32);

    struct hid_data *d;
    struct hid_item h;

    bool end_collection = false;

    for (d = hid_start_parse(b->report_desc, 1 << hid_input, -1);
         hid_get_item(d, &h);) {
      switch (h.kind) {
      case hid_collection:
        break;
      case hid_endcollection:
        end_collection = true;
        break;
      case hid_input: {
        int32_t data = hid_get_data(dbuf, &h);
        char const *usage_page = hid_usage_page(HID_PAGE(h.usage));
        char const *usage_in_page = hid_usage_in_page(h.usage);
        uint32_t usage = HID_USAGE(h.usage);
        if (!strcmp(usage_page, "Button")) {
          put_event(ed, &tv, EV_KEY, (uint16_t)(BTN_JOYSTICK + (int)usage - 1),
                    data);
        } else if (!strcmp(usage_page, "Generic_Desktop")) {
          if (!strcmp(usage_in_page, "X") || !strcmp(usage_in_page, "Y") ||
              !strcmp(usage_in_page, "Z") || !strcmp(usage_in_page, "Rz")) {
            uint16_t slot = usage & 0x0f;
            put_event(ed, &tv, EV_ABS, slot, data);
          }
        }
        break;
      }
      case hid_output:
      case hid_feature:
        break;
      }

      if (end_collection) {
        break;
      }
    }

    put_event(ed, &tv, EV_SYN, SYN_REPORT, 0);
    cuse_poll_wakeup();

    pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
  }

  free(dbuf);

  return NULL;
}
