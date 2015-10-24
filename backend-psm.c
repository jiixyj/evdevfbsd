#include "backend-psm.h"

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include "linux/mouse/psmouse.h"
#include "util.h"

#define X_MIN_DEFAULT 1472
#define X_MAX_DEFAULT 5472
#define Y_MIN_DEFAULT 1408
#define Y_MAX_DEFAULT 4448

static int32_t synaptics_inverse_y(int32_t y) {
  return Y_MAX_DEFAULT + Y_MIN_DEFAULT - y;
}

static int synaptics_setup_abs_axes(struct event_device *ed,
                                    struct psm_backend *b, int x_axis,
                                    int y_axis) {
  set_bit(ed->abs_bits, x_axis);
  set_bit(ed->abs_bits, y_axis);
  if (b->synaptics_info.minimumXCoord && b->synaptics_info.minimumYCoord) {
    ed->abs_info[x_axis].minimum = b->synaptics_info.minimumXCoord;
    ed->abs_info[y_axis].minimum = b->synaptics_info.minimumYCoord;
  } else {
    ed->abs_info[x_axis].minimum = X_MIN_DEFAULT;
    ed->abs_info[y_axis].minimum = Y_MIN_DEFAULT;
  }
  if (b->synaptics_info.maximumXCoord && b->synaptics_info.maximumYCoord) {
    ed->abs_info[x_axis].maximum = b->synaptics_info.maximumXCoord;
    ed->abs_info[y_axis].maximum = b->synaptics_info.maximumYCoord;
  } else {
    ed->abs_info[x_axis].maximum = X_MAX_DEFAULT;
    ed->abs_info[y_axis].maximum = Y_MAX_DEFAULT;
  }
  if (b->synaptics_info.infoXupmm && b->synaptics_info.infoYupmm) {
    ed->abs_info[x_axis].resolution = b->synaptics_info.infoXupmm;
    ed->abs_info[y_axis].resolution = b->synaptics_info.infoYupmm;
  } else {
    switch (b->synaptics_info.infoSensor) {
      case 1:
        ed->abs_info[x_axis].resolution = 85;
        ed->abs_info[y_axis].resolution = 94;
        break;
      case 2:
        ed->abs_info[x_axis].resolution = 91;
        ed->abs_info[y_axis].resolution = 124;
        break;
      case 3:
        ed->abs_info[x_axis].resolution = 57;
        ed->abs_info[y_axis].resolution = 58;
        break;
      case 8:
        ed->abs_info[x_axis].resolution = 85;
        ed->abs_info[y_axis].resolution = 94;
        break;
      case 9:
        ed->abs_info[x_axis].resolution = 73;
        ed->abs_info[y_axis].resolution = 96;
        break;
      case 11:
        ed->abs_info[x_axis].resolution = 187;
        ed->abs_info[y_axis].resolution = 170;
        break;
      case 12:
        ed->abs_info[x_axis].resolution = 122;
        ed->abs_info[y_axis].resolution = 167;
        break;
      default:
        return 1;
    }
  }
  return 0;
}

int psm_backend_init(struct event_device *ed) {
  ed->priv_ptr = malloc(sizeof(struct psm_backend));
  if (!ed->priv_ptr)
    return 1;

  struct psm_backend *b = ed->priv_ptr;

  b->fd = open("/dev/bpsm0", O_RDONLY);
  if (b->fd == -1)
    goto fail;

  int level = 2;
  if (ioctl(b->fd, MOUSE_SETLEVEL, &level) == -1)
    goto fail;

  if (ioctl(b->fd, MOUSE_GETHWINFO, &b->hw_info) == -1)
    goto fail;

  ed->iid.bustype = BUS_I8042;
  ed->iid.vendor = 0x02;
  b->guest_dev_fd = -1;

  switch (b->hw_info.model) {
    case MOUSE_MODEL_SYNAPTICS:
      ed->device_name = "SynPS/2 Synaptics TouchPad";
      ed->iid.product = PSMOUSE_SYNAPTICS;
      if (ioctl(b->fd, MOUSE_SYN_GETHWINFO, &b->synaptics_info) == -1)
        goto fail;
      b->ews.x = b->ews.y = b->ews.z = 0;
      b->ss[0].x = b->ss[0].y = 0;
      b->ss[1].x = b->ss[1].y = 0;
      b->ss[0].tracking_id = b->ss[1].tracking_id = -1;

      printf("synaptics info:\n");
      printf("  capPalmDetect: %d\n", b->synaptics_info.capPalmDetect);
      printf("  capMultiFinger: %d\n", b->synaptics_info.capMultiFinger);
      printf("  capAdvancedGestures: %d\n",
             b->synaptics_info.capAdvancedGestures);
      printf("  capEWmode: %d\n", b->synaptics_info.capEWmode);
      printf("  nExtendedQueries: %d\n", b->synaptics_info.nExtendedQueries);

      set_bit(ed->prop_bits, INPUT_PROP_POINTER);
      set_bit(ed->event_bits, EV_ABS);
      set_bit(ed->event_bits, EV_KEY);
      set_bit(ed->key_bits, BTN_LEFT);
      set_bit(ed->key_bits, BTN_RIGHT);
      if (b->synaptics_info.capMiddle) {
        set_bit(ed->key_bits, BTN_MIDDLE);
      }
      if (b->synaptics_info.capFourButtons) {
        set_bit(ed->key_bits, BTN_FORWARD);
        set_bit(ed->key_bits, BTN_BACK);
      }
      set_bit(ed->key_bits, BTN_TOUCH);
      set_bit(ed->key_bits, BTN_TOOL_FINGER);
      if (b->synaptics_info.capMultiFinger ||
          b->synaptics_info.capAdvancedGestures) {
        set_bit(ed->key_bits, BTN_TOOL_DOUBLETAP);
        set_bit(ed->key_bits, BTN_TOOL_TRIPLETAP);
      }

      if (synaptics_setup_abs_axes(ed, b, ABS_X, ABS_Y))
        goto fail;

      if (b->synaptics_info.capAdvancedGestures) {
        if (synaptics_setup_abs_axes(ed, b, ABS_MT_POSITION_X,
                                     ABS_MT_POSITION_Y))
          goto fail;
        set_bit(ed->prop_bits, INPUT_PROP_SEMI_MT);
        set_bit(ed->abs_bits, ABS_MT_SLOT);
        ed->abs_info[ABS_MT_SLOT].minimum = 0;
        ed->abs_info[ABS_MT_SLOT].maximum = 1;
        set_bit(ed->abs_bits, ABS_MT_TRACKING_ID);
        ed->abs_info[ABS_MT_TRACKING_ID].minimum = 0;
        ed->abs_info[ABS_MT_TRACKING_ID].maximum = 0xffff;
      }

      set_bit(ed->abs_bits, ABS_PRESSURE);
      ed->abs_info[ABS_PRESSURE].minimum = 0;
      ed->abs_info[ABS_PRESSURE].maximum = 255;
      if (b->synaptics_info.capPalmDetect) {
        set_bit(ed->abs_bits, ABS_TOOL_WIDTH);
        ed->abs_info[ABS_TOOL_WIDTH].minimum = 0;
        ed->abs_info[ABS_TOOL_WIDTH].maximum = 15;
      }

      break;
    case MOUSE_MODEL_TRACKPOINT:
      ed->device_name = "TPPS/2 IBM TrackPoint";
      ed->iid.product = PSMOUSE_TRACKPOINT;
      set_bits_generic_ps2(ed);
      break;
    case MOUSE_MODEL_GENERIC:
      ed->device_name = "Generic Mouse"; // XXX not sure
      ed->iid.product = PSMOUSE_PS2;     // XXX not sure
      set_bits_generic_ps2(ed);
      break;
  }

  return 0;
fail:
  free(ed->priv_ptr);
  return 1;
}

static int psm_is_async(struct event_device *ed, unsigned char *buf) {
  struct psm_backend *b = ed->priv_ptr;

  switch (b->hw_info.model) {
    case MOUSE_MODEL_SYNAPTICS:
      return (buf[0] & 0xc8) != 0x80 || (buf[3] & 0xc8) != 0xc0;
    case MOUSE_MODEL_GENERIC:
    case MOUSE_MODEL_TRACKPOINT:
      return (buf[0] & MOUSE_PS2_SYNC) != MOUSE_PS2_SYNC;
    default:
      // assume sync
      return 0;
  }
}

static int psm_read_full_packet(struct event_device *ed, int fd,
                                unsigned char *buf, size_t siz) {
  unsigned char *obuf = buf;
  size_t osiz = siz;

  ssize_t ret;
  while (siz) {
    ret = read(fd, buf, siz);
    if (ret <= 0)
      return 1;
    siz -= (size_t)ret;
    buf += (size_t)ret;
  }

  while (psm_is_async(ed, obuf)) {
    puts("syncing...");
    memmove(obuf, obuf + 1, osiz - 1);
    if (read(fd, obuf + osiz - 1, 1) != 1)
      return 1;
  }

  return 0;
}

static int write_full_packet(int fd, unsigned char *pkt, size_t siz) {
  ssize_t ret = write(fd, pkt, siz);
  if (ret == -1 && errno == EAGAIN)
    return 1;
  if (ret == -1 || ret != (ssize_t)siz)
    return -1;

  return 0;
}

static void synaptic_parse_ew_packet(struct event_device *ed,
                                     unsigned char *packet) {
  struct psm_backend *b = ed->priv_ptr;

  int ew_packet_code = (packet[5] & 0xf0) >> 4;
  switch (ew_packet_code) {
    case 1:
      b->ews.x = (((packet[4] & 0x0f) << 8) | packet[1]) << 1;
      b->ews.y = (((packet[4] & 0xf0) << 4) | packet[2]) << 1;
      b->ews.z = ((packet[3] & 0x30) | (packet[5] & 0x0f)) << 1;
      break;
    default:
      // ignore scroll wheel and finger count packets
      break;
  }
}

void *psm_fill_function(struct event_device *ed) {
  struct psm_backend *b = ed->priv_ptr;

  size_t packetsize = MOUSE_PS2_PACKETSIZE;
  switch (b->hw_info.model) {
    case MOUSE_MODEL_SYNAPTICS:
      packetsize = MOUSE_SYNAPTICS_PACKETSIZE;
      break;
    case MOUSE_MODEL_TRACKPOINT:
      packetsize = MOUSE_PS2_PACKETSIZE;
      break;
  }

  int obuttons = 0;
  unsigned char packet[PSM_PACKET_MAX_SIZE];

  while (psm_read_full_packet(ed, b->fd, packet, packetsize) == 0) {
    struct timeval tv;
    get_clock_value(ed, &tv);

    pthread_mutex_lock(&ed->event_buffer_mutex); // XXX

    switch (b->hw_info.model) {
      case MOUSE_MODEL_SYNAPTICS: {
        event_client_need_free_bufsize(ed, 24);
        int w = ((packet[0] & 0x30) >> 2) | ((packet[0] & 0x04) >> 1) |
                ((packet[3] & 0x04) >> 2);

        // printf("%3d %3d %3d %3d %3d %3d %d\n", packet[0], packet[1],
        //        packet[2], packet[3], packet[4], packet[5], w);

        if (w == 3) {
          packet[0] = packet[1];
          packet[1] = packet[4];
          packet[2] = packet[5];
          if (b->guest_dev_fd != -1) {
            if (write_full_packet(b->guest_dev_fd, packet, 3) == -1) {
              pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
              return NULL;
            }
          }
          break;
        } else if (w == 2) {
          synaptic_parse_ew_packet(ed, packet);
          break;
        }

        int buttons = 0;
        if (packet[0] & 0x01)
          buttons |= (1 << 0);
        if (packet[0] & 0x02)
          buttons |= (1 << 1);

        if (b->synaptics_info.capFourButtons) {
          if ((packet[3] ^ packet[0]) & 0x01)
            buttons |= (1 << 5);
          if ((packet[3] ^ packet[0]) & 0x02)
            buttons |= (1 << 6);
        } else if (b->synaptics_info.capMiddle) {
          if ((packet[0] ^ packet[3]) & 0x01)
            buttons |= (1 << 2);
        }

        int x = (((packet[3] & 0x10) << 8) | ((packet[1] & 0x0f) << 8) |
                 packet[4]);
        int y = (((packet[3] & 0x20) << 7) | ((packet[1] & 0xf0) << 4) |
                 packet[5]);
        int z = packet[2];
        int no_fingers = 0;
        int finger_width = 0;
        if (z > 0 && x > 1) {
          no_fingers = 1;
          finger_width = 5;
          if (w <= 1 && (b->synaptics_info.capMultiFinger ||
                         b->synaptics_info.capAdvancedGestures)) {
            no_fingers = w + 2;
          } else if (w >= 4 && w <= 15 && b->synaptics_info.capPalmDetect) {
            finger_width = w;
          }
        }

        put_event(ed, &tv, EV_KEY, BTN_LEFT, !!(buttons & (1 << 0)));
        put_event(ed, &tv, EV_KEY, BTN_RIGHT, !!(buttons & (1 << 1)));
        put_event(ed, &tv, EV_KEY, BTN_MIDDLE, !!(buttons & (1 << 2)));
        put_event(ed, &tv, EV_KEY, BTN_FORWARD, !!(buttons & (1 << 5)));
        put_event(ed, &tv, EV_KEY, BTN_BACK, !!(buttons & (1 << 6)));

        if (b->synaptics_info.capAdvancedGestures) {
          if (no_fingers >= 2) {
            enable_mt_slot(ed, &tv, 0);
            if (x > 1 && b->ews.x > 1)
              put_event(ed, &tv, EV_ABS, ABS_MT_POSITION_X, MIN(x, b->ews.x));
            if (y > 1 && b->ews.y > 1)
              put_event(ed, &tv, EV_ABS, ABS_MT_POSITION_Y,
                        synaptics_inverse_y(MIN(y, b->ews.y)));

            enable_mt_slot(ed, &tv, 1);
            put_event(ed, &tv, EV_ABS, ABS_MT_POSITION_X, MAX(x, b->ews.x));
            put_event(ed, &tv, EV_ABS, ABS_MT_POSITION_Y,
                      synaptics_inverse_y(MAX(y, b->ews.y)));
          } else if (no_fingers == 1) {
            enable_mt_slot(ed, &tv, 0);
            put_event(ed, &tv, EV_ABS, ABS_MT_POSITION_X, x);
            put_event(ed, &tv, EV_ABS, ABS_MT_POSITION_Y,
                      synaptics_inverse_y(y));
            disable_mt_slot(ed, &tv, 1);
          } else {
            disable_mt_slot(ed, &tv, 0);
            disable_mt_slot(ed, &tv, 1);
          }
        }

        if (z > 30)
          put_event(ed, &tv, EV_KEY, BTN_TOUCH, 1);
        if (z < 25)
          put_event(ed, &tv, EV_KEY, BTN_TOUCH, 0);
        if (no_fingers > 0) {
          if (x > 1)
            put_event(ed, &tv, EV_ABS, ABS_X, x);
          if (y > 1)
            put_event(ed, &tv, EV_ABS, ABS_Y, synaptics_inverse_y(y));
        }
        put_event(ed, &tv, EV_ABS, ABS_PRESSURE, z);
        if (b->synaptics_info.capPalmDetect)
          put_event(ed, &tv, EV_ABS, ABS_TOOL_WIDTH, finger_width);

        put_event(ed, &tv, EV_KEY, BTN_TOOL_FINGER, no_fingers == 1);
        if (b->synaptics_info.capMultiFinger ||
            b->synaptics_info.capAdvancedGestures) {
          put_event(ed, &tv, EV_KEY, BTN_TOOL_DOUBLETAP, no_fingers == 2);
          put_event(ed, &tv, EV_KEY, BTN_TOOL_TRIPLETAP, no_fingers == 3);
        }

        put_event(ed, &tv, EV_SYN, SYN_REPORT, 0);
        cuse_poll_wakeup();
        obuttons = buttons;
        break;
      }
      case MOUSE_MODEL_GENERIC:
      case MOUSE_MODEL_TRACKPOINT: {
        event_client_need_free_bufsize(ed, 6);
        int buttons = (packet[0] & 0x07);
        int x = (packet[0] & (1 << 4)) ? packet[1] - 256 : packet[1];
        int y = (packet[0] & (1 << 5)) ? packet[2] - 256 : packet[2];
        y = -y;

        put_event(ed, &tv, EV_KEY, BTN_LEFT, !!(buttons & (1 << 0)));
        put_event(ed, &tv, EV_KEY, BTN_RIGHT, !!(buttons & (1 << 1)));
        put_event(ed, &tv, EV_KEY, BTN_MIDDLE, !!(buttons & (1 << 2)));

        if (x)
          put_event(ed, &tv, EV_REL, REL_X, x);
        if (y)
          put_event(ed, &tv, EV_REL, REL_Y, y);

        put_event(ed, &tv, EV_SYN, SYN_REPORT, 0);
        cuse_poll_wakeup();
        obuttons = buttons;
      }
    }

    pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
  }

  return NULL;
}

int event_device_open_as_guest(struct event_device *ed,
                               struct event_device *parent) {
  ed->priv_ptr = malloc(sizeof(struct psm_backend));
  if (!ed->priv_ptr)
    return 1;

  struct psm_backend *b = ed->priv_ptr;

  int fds[2] = {-1, -1};
  if (pipe(fds) == -1)
    goto fail;

  if (fcntl(fds[1], F_SETFL, O_NONBLOCK) == -1)
    goto fail;

  b->fd = fds[0];

  b->hw_info.model = MOUSE_MODEL_TRACKPOINT;

  ed->iid.bustype = BUS_I8042;
  ed->iid.vendor = 0x02;
  b->guest_dev_fd = -1;

  switch (b->hw_info.model) {
    case MOUSE_MODEL_TRACKPOINT:
      ed->device_name = "TPPS/2 IBM TrackPoint";
      ed->iid.product = PSMOUSE_TRACKPOINT;
      set_bits_generic_ps2(ed);
      break;
  }

  b = parent->priv_ptr;
  pthread_mutex_lock(&parent->event_buffer_mutex); // XXX
  b->guest_dev_fd = fds[1];
  pthread_mutex_unlock(&parent->event_buffer_mutex); // XXX

  ed->fill_function = psm_fill_function;
  ed->backend_type = PSM_BACKEND;

  return 0;

fail:
  if (fds[0] != -1) {
    close(fds[0]);
  }
  if (fds[1] != -1) {
    close(fds[1]);
  }
  free(ed->priv_ptr);
  return 1;
}
