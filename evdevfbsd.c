#include <sys/mouse.h>
#include <sys/param.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <cuse.h>
#include <err.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

#include "linux/input.h"
#include "linux/mouse/psmouse.h"

#define EVENT_BUFFER_SIZE 1024

struct event_device {
  int fd;
  struct input_event event_buffer[EVENT_BUFFER_SIZE];
  int event_buffer_end;   /* index at which to write next event */
  pthread_mutex_t event_buffer_mutex;
  sem_t event_buffer_sem;
  pthread_t fill_thread;
  bool has_reader;
  void* priv_ptr;

  struct input_id iid;
  char const* device_name;
  uint64_t event_bits[256];
  uint64_t rel_bits[256];
  uint64_t key_bits[256];
  uint64_t abs_bits[256];
  uint64_t prop_bits[256];
  struct input_absinfo abs_info[ABS_MAX];
};

int event_device_nr_free_buffer(struct event_device* ed) {
  return EVENT_BUFFER_SIZE - ed->event_buffer_end;
}

int evdevfbsd_open(struct cuse_dev *cdev, int fflags) {
  // puts("device opened");
  struct event_device *ed = cuse_dev_get_priv0(cdev);

  int ret = CUSE_ERR_NONE;

  pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
  if (ed->has_reader) {
    ret = CUSE_ERR_BUSY;
  } else {
    ed->has_reader = true;
  }
  pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
  return ret;
}

int evdevfbsd_close(struct cuse_dev *cdev, int fflags) {
  // puts("device closed");
  struct event_device *ed = cuse_dev_get_priv0(cdev);

  pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
  for (int i = 0; i < ed->event_buffer_end; ++i)
    sem_wait(&ed->event_buffer_sem);
  ed->event_buffer_end = 0;
  ed->has_reader = false;
  pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
  return CUSE_ERR_NONE;
}

int evdevfbsd_read(struct cuse_dev *cdev, int fflags, void *user_ptr,
                   int len) {
  if (len < 0)
    return CUSE_ERR_INVALID;

  if (len < (int)sizeof(struct input_event))
    return CUSE_ERR_INVALID;

  int requested_events = len / sizeof(struct input_event);
  int nr_events;

  struct event_device* ed = cuse_dev_get_priv0(cdev);
  int ret;

retry:
  if (!(fflags & CUSE_FFLAG_NONBLOCK)) {
    ret = sem_wait(&ed->event_buffer_sem);
    if (ret == -1 && cuse_got_peer_signal() == 0)
      return CUSE_ERR_SIGNAL;
  }

  pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
  if (ed->event_buffer_end == 0) {
    if (fflags & CUSE_FFLAG_NONBLOCK)
      ret = CUSE_ERR_WOULDBLOCK;
    else {
      sem_post(&ed->event_buffer_sem);
      pthread_mutex_unlock(&ed->event_buffer_mutex);
      goto retry;
    }
  } else {
    nr_events = MIN(requested_events, ed->event_buffer_end);
    ret = cuse_copy_out(ed->event_buffer, user_ptr,
                        nr_events * sizeof(struct input_event));
    if (ret == 0) {
      memmove(ed->event_buffer, &ed->event_buffer[nr_events],
              (ed->event_buffer_end - nr_events) * sizeof(struct input_event));
      ed->event_buffer_end = ed->event_buffer_end - nr_events;
      for (int i = 0; i < nr_events - 1; ++i)
        sem_wait(&ed->event_buffer_sem);
    }
  }
  pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX

  return ret == 0 ? nr_events * sizeof(struct input_event) : ret;
}


int evdevfbsd_poll(struct cuse_dev *cdev, int fflags, int events) {
  if (!(events & CUSE_POLL_READ))
    return CUSE_POLL_NONE;

  int ret = CUSE_POLL_NONE;
  struct event_device* ed = cuse_dev_get_priv0(cdev);

  pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
  if (ed->event_buffer_end > 0)
    ret = CUSE_POLL_READ;
  pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX

  return ret;
}

void set_bit(uint64_t *array, int bit) {
  array[bit / 64] |= (1LL << (bit % 64));
}

int evdevfbsd_ioctl(struct cuse_dev *cdev, int fflags, unsigned long cmd,
                    void *peer_data) {
  uint64_t bits[256];
  struct event_device* ed = cuse_dev_get_priv0(cdev);

  switch (cmd) {
    case TIOCFLUSH:
    case FIONBIO:
      // ignore these for now
      return CUSE_ERR_INVALID;
  }

  switch (cmd) {
    case EVIOCGID: {
      // printf("got ioctl EVIOCGID\n");
      return cuse_copy_out(&ed->iid, peer_data, sizeof(ed->iid));
    }
    case EVIOCGVERSION: {
      // printf("got ioctl EVIOCGVERSION\n");
      int version = EV_VERSION;
      return cuse_copy_out(&version, peer_data, sizeof(version));
    }
    case EVIOCGRAB:
      // Can be noop, event devices are always grabbed exclusively
      printf("got ioctl EVIOCGRAB\n");
      return 0;
  }

  unsigned long base_cmd = IOCBASECMD(cmd);
  unsigned long len = IOCPARM_LEN(cmd);

  switch (base_cmd) {
    case EVIOCGBIT(0, 0): {
      // printf("got ioctl EVIOCGBIT %d\n", len);
      return cuse_copy_out(ed->event_bits, peer_data,
                           MIN(sizeof(ed->event_bits), len));
    }
    case EVIOCGNAME(0): {
      // printf("got ioctl EVIOCGNAME %d\n", len);
      if (ed->device_name) {
        return cuse_copy_out(ed->device_name, peer_data,
                             MIN(strlen(ed->device_name), len));
      } else {
        return 0;
      }
    }
    case EVIOCGPHYS(0):
      // printf("got ioctl EVIOCGPHYS %d\n", len);
      // ENOENT would be better, but that is not supported by cuse
      return 0;
    case EVIOCGUNIQ(0):
      // printf("got ioctl EVIOCGUNIQ %d\n", len);
      // ENOENT would be better, but that is not supported by cuse
      return 0;
    case EVIOCGBIT(EV_REL, 0): {
      // printf("got ioctl EVIOCGBIT %d\n", len);
      return cuse_copy_out(ed->rel_bits, peer_data,
                           MIN(sizeof(ed->rel_bits), len));
    }
    case EVIOCGBIT(EV_KEY, 0): {
      // printf("got ioctl EVIOCGBIT %d\n", len);
      return cuse_copy_out(ed->key_bits, peer_data,
                           MIN(sizeof(ed->key_bits), len));
    }
    case EVIOCGBIT(EV_ABS, 0): {
      // printf("got ioctl EVIOCGBIT %d\n", len);
      return cuse_copy_out(ed->abs_bits, peer_data,
                           MIN(sizeof(ed->abs_bits), len));
    }
    case EVIOCGBIT(EV_LED, 0):
    case EVIOCGBIT(EV_SW, 0):
    case EVIOCGBIT(EV_MSC, 0):
    case EVIOCGBIT(EV_FF, 0):
    case EVIOCGBIT(EV_SND, 0):
      // printf("got ioctl EVIOCGBIT %d\n", len);
      memset(bits, 0, sizeof(bits));
      return cuse_copy_out(bits, peer_data, MIN(sizeof(bits), len));
    case EVIOCGKEY(0):
      // printf("got ioctl EVIOCGKEY %d\n", len);
      return 0;
    case EVIOCGLED(0):
      // printf("got ioctl EVIOCGLED %d\n", len);
      return 0;
    case EVIOCGSW(0):
      // printf("got ioctl EVIOCGSW %d\n", len);
      return 0;
    case EVIOCGPROP(0):
      return cuse_copy_out(ed->prop_bits, peer_data,
                           MIN(sizeof(ed->prop_bits), len));
  }

  if ((cmd & IOC_DIRMASK) == IOC_OUT) {
    if ((cmd & ~ABS_MAX) == EVIOCGABS(0)) {
      printf("got eviocgabs for axis %d\n", cmd & ABS_MAX);
      return cuse_copy_out(&ed->abs_info[cmd & ABS_MAX], peer_data,
                           MIN(sizeof(struct input_absinfo), len));
    }
  }

  printf("got ioctl %lu %lu %lu\n", cmd, base_cmd, len);
  return CUSE_ERR_INVALID;
}

struct cuse_methods evdevfbsd_methods = {.cm_open = evdevfbsd_open,
                                         .cm_close = evdevfbsd_close,
                                         .cm_read = evdevfbsd_read,
                                         .cm_poll = evdevfbsd_poll,
                                         .cm_ioctl = evdevfbsd_ioctl};

#define PACKET_MAX 32

int read_full_packet(int fd, unsigned char *buf, size_t siz) {
  ssize_t ret;
  while (siz) {
    ret = read(fd, buf, siz);
    if (ret <= 0)
      return 1;
    siz -= ret;
    buf += ret;
  }
  return 0;
}

void put_event(struct event_device *ed, struct timeval *tv, uint16_t type,
               uint16_t code, int32_t value) {
  struct input_event *buf;
  buf = &ed->event_buffer[ed->event_buffer_end];
  buf->time = *tv;
  buf->type = type;
  buf->code = code;
  buf->value = value;
  ++ed->event_buffer_end;
  sem_post(&ed->event_buffer_sem);
}

struct synaptics_ew_state {
  int x;
  int y;
  int z;
};

struct psm_backend {
  int fd;
  mousehw_t hw_info;
  int guest_dev_fd;
  synapticshw_t synaptics_info;
  struct synaptics_ew_state ews;
};

void set_bits_generic_ps2(struct event_device *ed) {
  set_bit(ed->event_bits, EV_REL);
  set_bit(ed->event_bits, EV_KEY);
  set_bit(ed->key_bits, BTN_LEFT);
  set_bit(ed->key_bits, BTN_RIGHT);
  set_bit(ed->key_bits, BTN_MIDDLE);
  set_bit(ed->rel_bits, REL_X);
  set_bit(ed->rel_bits, REL_Y);
}

int32_t synaptics_reverse_y(int32_t y) {
  y -= 2928;
  y = -y;
  y += 2928;
  return y;
}

int synaptics_setup_abs_axes(struct event_device *ed, struct psm_backend *b,
                             int x_axis, int y_axis) {
  set_bit(ed->abs_bits, x_axis);
  set_bit(ed->abs_bits, y_axis);
  ed->abs_info[x_axis].minimum = 1472;
  ed->abs_info[x_axis].maximum = 5472;
  ed->abs_info[y_axis].minimum = 1408;
  ed->abs_info[y_axis].maximum = 4448;
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
      if (b->synaptics_info.capMultiFinger) {
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
      ed->iid.product = PSMOUSE_PS2; // XXX not sure
      set_bits_generic_ps2(ed);
      break;
  }

  return 0;
fail:
  free(ed->priv_ptr);
  return 1;
}

int write_full_packet(int fd, unsigned char* pkt, size_t siz) {
  ssize_t ret = write(fd, pkt, siz);
  if (ret == -1 && errno == EAGAIN)
    return 1;
  if (ret == -1)
    return -1;

  pkt += ret;
  siz -= ret;

  while (siz) {
    ret = write(fd, pkt, siz);
    if (ret > 0) {
      pkt += ret;
      siz -= ret;
    }
  }
  return 0;
}

void synaptic_parse_ew_packet(struct event_device *ed, unsigned char *packet) {
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

void* psm_fill_function(struct event_device *ed) {
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
  int oslot0 = 0;
  int oslot1 = 0;
  uint16_t tracking_ids = 0;
  unsigned char packet[PACKET_MAX];

  while (read_full_packet(b->fd, packet, packetsize) == 0) {
    pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
    if (!ed->has_reader && b->guest_dev_fd == -1) {
      obuttons = 0;
      pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
      continue;
    }

    switch (b->hw_info.model) {
      case MOUSE_MODEL_SYNAPTICS: {
        if (event_device_nr_free_buffer(ed) >= 16) {
          int w = ((packet[0] & 0x30) >> 2) | ((packet[0] & 0x04) >> 1) |
                  ((packet[3] & 0x04) >> 2);

          // printf("%3d %3d %3d %3d %3d %3d %d\n", packet[0], packet[1],
          //        packet[2], packet[3], packet[4], packet[5], w);

          if (w == 3) {
            packet[0] = packet[1];
            packet[1] = packet[4];
            packet[2] = packet[5];
            if (b->guest_dev_fd != -1) {
              write_full_packet(b->guest_dev_fd, packet, 3);
            }
            break;
          } else if (w == 2) {
            synaptic_parse_ew_packet(ed, packet);
            break;
          }
          if (!ed->has_reader)
            break;

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
            if (w <= 1 && b->synaptics_info.capMultiFinger) {
              no_fingers = w + 2;
            } else if (w >= 4 && w <= 15 && b->synaptics_info.capPalmDetect) {
              finger_width = w;
            }
          }

          struct timeval tv;
          gettimeofday(&tv, NULL); // XXX
          struct input_event *buf;

          if ((buttons ^ obuttons) & (1 << 0))
            put_event(ed, &tv, EV_KEY, BTN_LEFT, !!(buttons & (1 << 0)));
          if ((buttons ^ obuttons) & (1 << 1))
            put_event(ed, &tv, EV_KEY, BTN_RIGHT, !!(buttons & (1 << 1)));
          if ((buttons ^ obuttons) & (1 << 2))
            put_event(ed, &tv, EV_KEY, BTN_MIDDLE, !!(buttons & (1 << 2)));
          if ((buttons ^ obuttons) & (1 << 5))
            put_event(ed, &tv, EV_KEY, BTN_FORWARD, !!(buttons & (1 << 5)));
          if ((buttons ^ obuttons) & (1 << 6))
            put_event(ed, &tv, EV_KEY, BTN_BACK, !!(buttons & (1 << 6)));

          if (b->synaptics_info.capAdvancedGestures) {
            if (no_fingers >= 2) {
              put_event(ed, &tv, EV_ABS, ABS_MT_SLOT, 0);
              if (!oslot0)
                put_event(ed, &tv, EV_ABS, ABS_MT_TRACKING_ID, ++tracking_ids);
              put_event(ed, &tv, EV_ABS, ABS_MT_POSITION_X, MIN(x, b->ews.x));
              put_event(ed, &tv, EV_ABS, ABS_MT_POSITION_X,
                        synaptics_reverse_y(MIN(y, b->ews.y)));
              put_event(ed, &tv, EV_ABS, ABS_MT_SLOT, 1);
              if (!oslot1)
                put_event(ed, &tv, EV_ABS, ABS_MT_TRACKING_ID, ++tracking_ids);
              put_event(ed, &tv, EV_ABS, ABS_MT_POSITION_X, MAX(x, b->ews.x));
              put_event(ed, &tv, EV_ABS, ABS_MT_POSITION_X,
                        synaptics_reverse_y(MAX(y, b->ews.y)));
              oslot0 = oslot1 = 1;
            } else if (no_fingers == 1) {
              put_event(ed, &tv, EV_ABS, ABS_MT_SLOT, 0);
              if (!oslot0)
                put_event(ed, &tv, EV_ABS, ABS_MT_TRACKING_ID, ++tracking_ids);
              put_event(ed, &tv, EV_ABS, ABS_MT_POSITION_X, x);
              put_event(ed, &tv, EV_ABS, ABS_MT_POSITION_X,
                        synaptics_reverse_y(y));
              if (oslot1) {
                put_event(ed, &tv, EV_ABS, ABS_MT_SLOT, 1);
                put_event(ed, &tv, EV_ABS, ABS_MT_TRACKING_ID, -1);
              }
              oslot0 = 1;
              oslot1 = 0;
            } else {
              if (oslot0) {
                put_event(ed, &tv, EV_ABS, ABS_MT_SLOT, 0);
                put_event(ed, &tv, EV_ABS, ABS_MT_TRACKING_ID, -1);
              }
              if (oslot1) {
                put_event(ed, &tv, EV_ABS, ABS_MT_SLOT, 1);
                put_event(ed, &tv, EV_ABS, ABS_MT_TRACKING_ID, -1);
              }
              oslot0 = oslot1 = 0;
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
              put_event(ed, &tv, EV_ABS, ABS_Y, synaptics_reverse_y(y));
          }
          put_event(ed, &tv, EV_ABS, ABS_PRESSURE, z);
          if (b->synaptics_info.capPalmDetect)
            put_event(ed, &tv, EV_ABS, ABS_TOOL_WIDTH, finger_width);

          put_event(ed, &tv, EV_KEY, BTN_TOOL_FINGER, no_fingers == 1);
          if (b->synaptics_info.capMultiFinger) {
            put_event(ed, &tv, EV_KEY, BTN_TOOL_DOUBLETAP, no_fingers == 2);
            put_event(ed, &tv, EV_KEY, BTN_TOOL_TRIPLETAP, no_fingers == 3);
          }

          put_event(ed, &tv, EV_SYN, SYN_REPORT, 0);
          cuse_poll_wakeup();
          obuttons = buttons;
          break;
        }
      }
      case MOUSE_MODEL_GENERIC:
      case MOUSE_MODEL_TRACKPOINT: {
        if (event_device_nr_free_buffer(ed) >= 6) {
          int buttons = (packet[0] & 0x07);
          int x = (packet[0] & (1 << 4)) ? packet[1] - 256 : packet[1];
          int y = (packet[0] & (1 << 5)) ? packet[2] - 256 : packet[2];
          y = -y;

          struct timeval tv;
          gettimeofday(&tv, NULL); // XXX
          struct input_event *buf;

          if ((buttons ^ obuttons) & (1 << 0))
            put_event(ed, &tv, EV_KEY, BTN_LEFT, !!(buttons & (1 << 0)));
          if ((buttons ^ obuttons) & (1 << 1))
            put_event(ed, &tv, EV_KEY, BTN_RIGHT, !!(buttons & (1 << 1)));
          if ((buttons ^ obuttons) & (1 << 2))
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
    }

    pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
  }

  return NULL;
}

struct sysmouse_backend {
  int fd;
};

int sysmouse_backend_init(struct event_device *ed) {
  ed->priv_ptr = malloc(sizeof(struct sysmouse_backend));
  if (!ed->priv_ptr)
    return 1;

  struct sysmouse_backend *b = ed->priv_ptr;

  b->fd = open("/dev/sysmouse", O_RDONLY);
  if (b->fd == -1)
    goto fail;

  int level = 2;
  if (ioctl(b->fd, MOUSE_SETLEVEL, &level) == -1)
    goto fail;

  return 0;
fail:
  free(ed->priv_ptr);
  return 1;
}

void* sysmouse_fill_function(struct event_device *ed) {
  struct sysmouse_backend *b = ed->priv_ptr;
  int obuttons = 0;
  unsigned char packet[19];

  while (read(b->fd, packet, sizeof(packet)) == sizeof(packet)) {
    pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
    if (!ed->has_reader) {
      obuttons = 0;
      pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
      continue;
    }

    if (event_device_nr_free_buffer(ed) >= 8) {
      int buttons, dx, dy, dz, dw;

      buttons = (~packet[0]) & 0x07;
      dx = (int16_t)((packet[8] << 9) | (packet[9] << 2)) >> 2;
      dy = -((int16_t)((packet[10] << 9) | (packet[11] << 2)) >> 2);
      dz = -((int16_t)((packet[12] << 9) | (packet[13] << 2)) >> 2);
      dw = (int16_t)((packet[14] << 9) | (packet[15] << 2)) >> 2;

      struct timeval tv;
      gettimeofday(&tv, NULL); // XXX
      struct input_event *buf;

      if ((buttons ^ obuttons) & MOUSE_SYS_BUTTON1UP)
        put_event(ed, &tv, EV_KEY, BTN_LEFT,
                  !!(buttons & MOUSE_SYS_BUTTON1UP));
      if ((buttons ^ obuttons) & MOUSE_SYS_BUTTON2UP)
        put_event(ed, &tv, EV_KEY, BTN_MIDDLE,
                  !!(buttons & MOUSE_SYS_BUTTON2UP));
      if ((buttons ^ obuttons) & MOUSE_SYS_BUTTON3UP)
        put_event(ed, &tv, EV_KEY, BTN_RIGHT,
                  !!(buttons & MOUSE_SYS_BUTTON3UP));

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
    }

    pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
  }

  return NULL;
}

void evdevfbsd_hup_catcher(int dummy) {}

void *wait_and_proc(void *notused) {
  int ret;

  struct sigaction act = {0};
  act.sa_handler = &evdevfbsd_hup_catcher;
  sigaction(SIGHUP, &act, NULL); // XXX

  for (;;) {
    ret = cuse_wait_and_process();
    if (ret < 0)
      break;
  }
  return NULL;
}

int event_device_init(struct event_device* ed) {
  memset(ed, 0, sizeof(*ed));
  ed->fd = -1;
  ed->event_buffer_end = 0;
  return pthread_mutex_init(&ed->event_buffer_mutex, NULL) ||
         sem_init(&ed->event_buffer_sem, 0, 0);
}

int event_device_open(struct event_device *ed, char const *path) {
  void *(*fill_function)(void *);

  if (!strcmp(path, "/dev/bpsm0")) {
    psm_backend_init(ed);
    fill_function = (void *(*)(void *)) psm_fill_function;
  } else if (!strcmp(path, "/dev/sysmouse")) {
    sysmouse_backend_init(ed);
    fill_function = (void *(*)(void *)) sysmouse_fill_function;
  } else {
    return -EINVAL;
  }

  return pthread_create(&ed->fill_thread, NULL, fill_function, ed);
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

  if (pthread_create(&ed->fill_thread, NULL, psm_fill_function, ed) == 0)
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

int main() {
  int ret;

  if ((ret = cuse_init()) < 0)
    errx(1, "cuse_init returned %d", ret);

  struct event_device ed;
  event_device_init(&ed); // XXX
  event_device_open(&ed, "/dev/bpsm0"); // XXX

  struct event_device ed_guest;
  event_device_init(&ed_guest); // XXX
  event_device_open_as_guest(&ed_guest, &ed); // XXX

  {
    struct cuse_dev *evdevfbsddev = cuse_dev_create(
        &evdevfbsd_methods, &ed, NULL, 0, 0, 0444, "input/event0");
    if (!evdevfbsddev)
      errx(1, "cuse_dev_create failed");
  }

  {
    struct cuse_dev *evdevfbsddev = cuse_dev_create(
        &evdevfbsd_methods, &ed_guest, NULL, 0, 0, 0444, "input/event1");
    if (!evdevfbsddev)
      errx(1, "cuse_dev_create failed");
  }

  pthread_t worker[4];
  pthread_create(&worker[0], NULL, wait_and_proc, NULL); // XXX
  pthread_create(&worker[1], NULL, wait_and_proc, NULL); // XXX
  pthread_create(&worker[2], NULL, wait_and_proc, NULL); // XXX
  pthread_create(&worker[3], NULL, wait_and_proc, NULL); // XXX

  pthread_join(worker[3], NULL); // XXX
  pthread_join(worker[2], NULL); // XXX
  pthread_join(worker[1], NULL); // XXX
  pthread_join(worker[0], NULL); // XXX
}
