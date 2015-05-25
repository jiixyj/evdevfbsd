#include "backend-sysmouse.h"

#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <unistd.h>

#include "util.h"
#include "backend-psm.h"

int sysmouse_backend_init(struct event_device *ed, char const *path) {
  ed->priv_ptr = malloc(sizeof(struct sysmouse_backend));
  if (!ed->priv_ptr)
    return 1;

  struct sysmouse_backend *b = ed->priv_ptr;

  if (snprintf(b->path, sizeof(b->path), "%s", path) == -1)
    return 1;

  b->fd = open(b->path, O_RDONLY);
  if (b->fd == -1)
    goto fail;

  b->level = 2;
  if (ioctl(b->fd, MOUSE_SETLEVEL, &b->level) == -1) {
    b->level = 1;
    if (ioctl(b->fd, MOUSE_SETLEVEL, &b->level) == -1) {
      goto fail;
    }
  }

  if (ioctl(b->fd, MOUSE_GETMODE, &b->mode) == -1)
    goto fail;

  if (b->mode.protocol != MOUSE_PROTO_SYSMOUSE)
    goto fail;

  if (b->mode.packetsize < 0 || b->mode.packetsize > PSM_PACKET_MAX_SIZE)
    goto fail;

  if (ioctl(b->fd, MOUSE_GETHWINFO, &b->hw_info) == -1)
    goto fail;

  printf("nr buttons: %d\n", b->hw_info.buttons);

  set_bits_generic_ps2(ed);
  for (int i = 3; i < b->hw_info.buttons; ++i) {
    set_bit(ed->key_bits, BTN_MOUSE + i);
  }
  set_bit(ed->rel_bits, REL_WHEEL);
  set_bit(ed->rel_bits, REL_HWHEEL);

  return 0;
fail:
  free(ed->priv_ptr);
  return 1;
}

void *sysmouse_fill_function(struct event_device *ed) {
  struct sysmouse_backend *b = ed->priv_ptr;
  int obuttons = 0;
  unsigned char packet[PSM_PACKET_MAX_SIZE];

  while (read(b->fd, packet, (size_t)b->mode.packetsize) ==
         b->mode.packetsize) {
    pthread_mutex_lock(&ed->event_buffer_mutex); // XXX

    event_client_need_free_bufsize(ed, 8);
    int buttons = 0, dx = 0, dy = 0, dz = 0, dw = 0;

    if (b->mode.packetsize >= 5) {
      buttons = (~packet[0]) & 0x07;
      dx = (int8_t)packet[1] + (int8_t)packet[3];
      dy = (int8_t)packet[2] + (int8_t)packet[4];
      dy = -dy;
    }

    if (b->mode.packetsize >= 8) {
      dz = ((int8_t)(packet[5] << 1) + (int8_t)(packet[6] << 1)) / 2;
      if (dz == -1 && packet[6] == 64)
        dz = 127;
      buttons |= (~packet[7] & MOUSE_SYS_EXTBUTTONS) << 3;
    }

    if (b->mode.packetsize >= 16) {
      dx = (int16_t)((packet[8] << 9) | (packet[9] << 2)) >> 2;
      dy = -((int16_t)((packet[10] << 9) | (packet[11] << 2)) >> 2);
      dz = -((int16_t)((packet[12] << 9) | (packet[13] << 2)) >> 2);
      dw = (int16_t)((packet[14] << 9) | (packet[15] << 2)) >> 2;
    }

    struct timeval tv;
    get_clock_value(ed, &tv);

    put_event(ed, &tv, EV_KEY, BTN_LEFT, !!(buttons & MOUSE_SYS_BUTTON1UP));
    put_event(ed, &tv, EV_KEY, BTN_MIDDLE, !!(buttons & MOUSE_SYS_BUTTON2UP));
    put_event(ed, &tv, EV_KEY, BTN_RIGHT, !!(buttons & MOUSE_SYS_BUTTON3UP));
    put_event(ed, &tv, EV_KEY, BTN_SIDE,
              !!(buttons & (MOUSE_SYS_BUTTON4UP << 3)));
    put_event(ed, &tv, EV_KEY, BTN_EXTRA,
              !!(buttons & (MOUSE_SYS_BUTTON5UP << 3)));

    if (dx)
      put_event(ed, &tv, EV_REL, REL_X, dx);
    if (dy)
      put_event(ed, &tv, EV_REL, REL_Y, dy);
    if (dz)
      put_event(ed, &tv, EV_REL, REL_WHEEL, dz);
    if (dw)
      put_event(ed, &tv, EV_REL, REL_HWHEEL, dw);

    put_event(ed, &tv, EV_SYN, SYN_REPORT, 0);
    cuse_poll_wakeup();
    obuttons = buttons;

    pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
  }

  return NULL;
}
