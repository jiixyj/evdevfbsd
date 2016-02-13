#include "backend-atkbd.h"

#include <sys/kbio.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include "util.h"

static const uint16_t scan_to_evdev[] = {
  0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15,
 16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,
 32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,
 48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,
 64,  65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,  79,
 80,  81,  82,  83,  99,   0,  86,  87,  88, 117,   0,   0,  95, 183, 184, 185,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
 93,   0,   0,  89,   0,   0,  85,  91,  90,  92,   0,  94,   0, 124, 121,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
165,   0,   0,   0,   0,   0,   0,   0,   0, 163,   0,   0,  96,  97,   0,   0,
113, 140, 164,   0, 166,   0,   0,   0,   0,   0, 255,   0,   0,   0, 114,   0,
115,   0, 172,   0,   0,  98, 255,  99, 100,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0, 119, 119, 102, 103, 104,   0, 105, 112, 106, 118, 107,
108, 109, 110, 111,   0,   0,   0,   0,   0,   0,   0, 125, 126, 127, 116, 142,
  0,   0,   0, 143,   0, 217, 156, 173, 128, 159, 158, 157, 155, 226,   0, 112,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0, 123, 122,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
};

static uint16_t raw_to_scan(int escape, uint16_t code) {
  return (uint16_t)((code & 0x7f) | ((code & 0x80) << 1) |
                    (escape == 1 ? 0x80 : 0));
}

static bool release_extraction_needed(struct atkbd_state *atkbd, uint16_t code) {
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

static void calculate_release_extraction_state(struct atkbd_state *atkbd,
                                        uint16_t code) {
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

static void detach_atkbd() {
  system("kbdcontrol -K < /dev/console");
  system("kbdcontrol -A atkbd0 < /dev/kbdmux0");
  system("kbdcontrol -k /dev/kbdmux0 < /dev/console");
}

static void reattach_atkbd_part1() {
  system("kbdcontrol -K < /dev/console");
  system("kbdcontrol -A vkbd0 < /dev/kbdmux0");
}

static void reattach_atkbd_part2() {
  system("kbdcontrol -a atkbd0 < /dev/kbdmux0");
  system("kbdcontrol -k /dev/kbdmux0 < /dev/console");
}

int atkbd_backend_init(struct event_device *ed) {
  ed->priv_ptr = malloc(sizeof(struct atkbd_backend));
  if (!ed->priv_ptr)
    return 1;

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

  b->atkbd_fd = open("/dev/atkbd0", O_RDWR);
  if (b->atkbd_fd == -1 || ioctl(b->atkbd_fd, KDSKBMODE, K_RAW) == -1) {
    reattach_atkbd_part1();

    if (b->atkbd_fd != -1)
      close(b->atkbd_fd);
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

  return 0;
fail:
  free(ed->priv_ptr);
  return 1;
}

static bool write_keycode(int fd, unsigned int kc) {
  ssize_t len = write(fd, &kc, sizeof(kc));

  if (len != sizeof(kc))
    return false;

  return true;
}

void *atkbd_fill_function(struct event_device *ed) {
  struct atkbd_backend *b = ed->priv_ptr;

  for (;;) {
    uint8_t raw_code;
    ssize_t ret = read(b->atkbd_fd, &raw_code, 1);

    if (ret == -1 || ret == 0)
      break;

    struct timeval tv;
    get_clock_value(ed, &tv);

    pthread_mutex_lock(&ed->event_buffer_mutex); // XXX

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
      goto next;
    } else if (code == AT_ES1) {
      b->atkbd.escape = 2;
      goto next;
    } else if (code == AT_BAT || code == AT_REL || code == AT_ACK ||
               code == AT_NAK || code == AT_ERR) {
      fprintf(stderr, "unexpected control code: %d\n", +code);
      goto next;
    }

    code = raw_to_scan(b->atkbd.escape, code);

    if (b->atkbd.escape > 0) {
      --b->atkbd.escape;
      if (b->atkbd.escape > 0)
        goto next;
    }

    uint16_t evdev_code = scan_to_evdev[code];
    if (evdev_code != 255) {
      put_event(ed, &tv, EV_MSC, MSC_SCAN, code);
    }

    if (evdev_code == 255) {
      goto next;
    } else if (evdev_code == 0) {
      fprintf(stderr, "unknown key encountered\n");
      put_event(ed, &tv, EV_SYN, SYN_REPORT, 0);
    } else {
      int evdev_value;
      if (release) {
        evdev_value = 0;
      } else if (ed->key_state[evdev_code]) {
        evdev_value = 2;
      } else {
        evdev_value = 1;
      }

      put_event(ed, &tv, EV_KEY, evdev_code, evdev_value);
      put_event(ed, &tv, EV_SYN, SYN_REPORT, 0);

      if (evdev_value && (code == AT_HANJA || code == AT_HANGEUL)) {
        put_event(ed, &tv, EV_MSC, MSC_SCAN, code);
        put_event(ed, &tv, EV_KEY, evdev_code, 0);
        put_event(ed, &tv, EV_SYN, SYN_REPORT, 0);
      }
    }

  next:
    cuse_poll_wakeup();

    pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
    if (!write_keycode(b->vkbd_fd, raw_code))
      break;
  }

  return NULL;
}

void atkbd_backend_cleanup(struct event_device *ed) {
  struct atkbd_backend *b = ed->priv_ptr;

  reattach_atkbd_part1();

  if (b->atkbd_fd != -1)
    close(b->atkbd_fd);

  if (b->vkbd_fd != -1)
    close(b->vkbd_fd);

  pthread_join(ed->fill_thread, NULL);

  reattach_atkbd_part2();
}
