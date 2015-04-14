#include <sys/consio.h>
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
#include <termios.h>
#include <unistd.h>

#include "linux/input.h"
#include "linux/mouse/psmouse.h"
#include "zero_initializer.h"

#define EVENT_BUFFER_SIZE 1024
#define MAX_SLOTS 16

#define ABS_MT_FIRST ABS_MT_TOUCH_MAJOR
#define ABS_MT_LAST ABS_MT_TOOL_Y

struct input_mt_request {
  uint32_t code;
  int32_t values[MAX_SLOTS];
};

enum backends { PSM_BACKEND, SYSMOUSE_BACKEND };

struct event_device {
  int fd;
  struct input_event event_buffer[EVENT_BUFFER_SIZE];
  int event_buffer_end; /* index at which to write next event */
  pthread_mutex_t event_buffer_mutex;
  sem_t event_buffer_sem;
  pthread_t fill_thread;
  bool is_open;
  uint16_t tracking_ids;
  int clock;
  int backend_type;
  void *priv_ptr;

  struct input_id iid;
  char const *device_name;
  uint64_t event_bits[256];
  uint64_t rel_bits[256];
  uint64_t key_bits[256];
  uint64_t abs_bits[256];
  uint64_t prop_bits[256];
  struct input_absinfo abs_info[ABS_MAX];

  uint16_t events_since_last_syn;
  int32_t key_state[KEY_CNT];
  int32_t abs_state[ABS_CNT];
  int32_t current_mt_slot;
  int32_t mt_state[MAX_SLOTS][ABS_MT_LAST - ABS_MT_FIRST + 1];
};

static void get_clock_value(struct event_device *ed, struct timeval *tv) {
  struct timespec ts;
  clock_gettime(ed->clock, &ts); // XXX
  struct bintime bt;
  timespec2bintime(&ts, &bt);
  bintime2timeval(&bt, tv);
}

static int event_device_nr_free_buffer(struct event_device *ed) {
  return EVENT_BUFFER_SIZE - ed->event_buffer_end;
}

static int evdevfbsd_open(struct cuse_dev *cdev, int fflags __unused) {
  // puts("device opened");
  struct event_device *ed = cuse_dev_get_priv0(cdev);

  int ret = CUSE_ERR_NONE;

  pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
  if (ed->is_open) {
    ret = CUSE_ERR_BUSY;
  } else {
    ed->is_open = true;
  }
  pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
  return ret;
}

static int evdevfbsd_close(struct cuse_dev *cdev, int fflags __unused) {
  struct event_device *ed = cuse_dev_get_priv0(cdev);

  pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
  for (int i = 0; i < ed->event_buffer_end; ++i)
    sem_wait(&ed->event_buffer_sem);
  ed->event_buffer_end = 0;
  ed->is_open = false;
  pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
  return CUSE_ERR_NONE;
}

static int evdevfbsd_read(struct cuse_dev *cdev, int fflags, void *user_ptr,
                          int len) {
  if (len < 0)
    return CUSE_ERR_INVALID;

  if (len < (int)sizeof(struct input_event))
    return CUSE_ERR_INVALID;

  int requested_events = len / (int)sizeof(struct input_event);
  int nr_events = 0;

  struct event_device *ed = cuse_dev_get_priv0(cdev);
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
                        nr_events * (int)sizeof(struct input_event));
    if (ret == 0) {
      memmove(ed->event_buffer, &ed->event_buffer[nr_events],
              (size_t)(ed->event_buffer_end - nr_events) *
                  sizeof(struct input_event));
      ed->event_buffer_end = ed->event_buffer_end - nr_events;
      for (int i = 0; i < nr_events - 1; ++i)
        sem_wait(&ed->event_buffer_sem);
    }
  }
  pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX

  return ret == 0 ? nr_events * (int)sizeof(struct input_event) : ret;
}

static int evdevfbsd_poll(struct cuse_dev *cdev, int fflags __unused,
                          int events) {
  if (!(events & CUSE_POLL_READ))
    return CUSE_POLL_NONE;

  int ret = CUSE_POLL_NONE;
  struct event_device *ed = cuse_dev_get_priv0(cdev);

  pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
  if (ed->event_buffer_end > 0)
    ret = CUSE_POLL_READ;
  pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX

  return ret;
}

static void set_bit(uint64_t *array, int bit) {
  array[bit / 64] |= (1LL << (bit % 64));
}

static int evdevfbsd_ioctl(struct cuse_dev *cdev, int fflags __unused,
                           unsigned long cmd, void *peer_data) {
  uint64_t bits[256];
  struct event_device *ed = cuse_dev_get_priv0(cdev);

  switch (cmd) {
    case TIOCFLUSH:
    case TIOCGETA:
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
      // Can be noop, event devices are always grabbed exclusively for now
      // printf("GRAB: %p\n", peer_data);
      return 0;
    case EVIOCSCLOCKID: {
      int new_clock, ret;
      if ((ret = cuse_copy_in(peer_data, &new_clock, sizeof(new_clock))))
        return ret;
      if (new_clock == CLOCK_REALTIME || new_clock == CLOCK_MONOTONIC) {
        ed->clock = new_clock;
        return 0;
      } else {
        return CUSE_ERR_INVALID;
      }
    }
  }

  unsigned long base_cmd = IOCBASECMD(cmd);
  unsigned long len = IOCPARM_LEN(cmd);

  switch (base_cmd) {
    case EVIOCGBIT(0, 0): {
      // printf("got ioctl EVIOCGBIT %d\n", len);
      return cuse_copy_out(ed->event_bits, peer_data,
                           (int)MIN(sizeof(ed->event_bits), len));
    }
    case EVIOCGNAME(0): {
      // printf("got ioctl EVIOCGNAME %d\n", len);
      if (ed->device_name) {
        return cuse_copy_out(ed->device_name, peer_data,
                             (int)MIN(strlen(ed->device_name), len));
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
                           (int)MIN(sizeof(ed->rel_bits), len));
    }
    case EVIOCGBIT(EV_KEY, 0): {
      // printf("got ioctl EVIOCGBIT %d\n", len);
      return cuse_copy_out(ed->key_bits, peer_data,
                           (int)MIN(sizeof(ed->key_bits), len));
    }
    case EVIOCGBIT(EV_ABS, 0): {
      // printf("got ioctl EVIOCGBIT %d\n", len);
      return cuse_copy_out(ed->abs_bits, peer_data,
                           (int)MIN(sizeof(ed->abs_bits), len));
    }
    case EVIOCGBIT(EV_LED, 0):
    case EVIOCGBIT(EV_SW, 0):
    case EVIOCGBIT(EV_MSC, 0):
    case EVIOCGBIT(EV_FF, 0):
    case EVIOCGBIT(EV_SND, 0):
      // printf("got ioctl EVIOCGBIT %d\n", len);
      memset(bits, 0, sizeof(bits));
      return cuse_copy_out(bits, peer_data, (int)MIN(sizeof(bits), len));
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
                           (int)MIN(sizeof(ed->prop_bits), len));
    case EVIOCGMTSLOTS(0): {
      int ret;
      uint32_t code;
      if (len < sizeof(uint32_t))
        return CUSE_ERR_INVALID;
      if ((ret = cuse_copy_in(peer_data, &code, sizeof(code))))
        return ret;
      if (code < ABS_MT_FIRST || code > ABS_MT_LAST)
        return CUSE_ERR_INVALID;
      struct input_mt_request mtr = ZERO_INITIALIZER;
      mtr.code = code;
      for (int i = 0; i < MAX_SLOTS; ++i) {
        mtr.values[i] = ed->mt_state[i][code - ABS_MT_FIRST];
      }
      return cuse_copy_out(&mtr, peer_data,
                           (int)MIN(sizeof(struct input_mt_request), len));
    }
  }

  if ((cmd & IOC_DIRMASK) == IOC_OUT) {
    if ((cmd & ~(unsigned long)ABS_MAX) == EVIOCGABS(0)) {
      // printf("got eviocgabs for axis %ld\n", cmd & ABS_MAX);
      return cuse_copy_out(&ed->abs_info[cmd & ABS_MAX], peer_data,
                           (int)MIN(sizeof(struct input_absinfo), len));
    }
  }

  printf("got unknown ioctl %lu %lu %lu\n", cmd, base_cmd, len);
  unsigned long direction = cmd & IOC_DIRMASK;
  if (direction == IOC_VOID) {
    puts("direction: void");
  } else if (direction == IOC_OUT) {
    puts("direction: out");
  } else if (direction == IOC_IN) {
    puts("direction: in");
  }
  printf("length: %lu\n", IOCPARM_LEN(cmd));
  printf("group: %c\n", (unsigned char)IOCGROUP(cmd));
  printf("num: %lu 0x%02lx\n", cmd & 0xff, cmd & 0xff);
  return CUSE_ERR_INVALID;
}

static struct cuse_methods evdevfbsd_methods = {.cm_open = evdevfbsd_open,
                                                .cm_close = evdevfbsd_close,
                                                .cm_read = evdevfbsd_read,
                                                .cm_poll = evdevfbsd_poll,
                                                .cm_ioctl = evdevfbsd_ioctl};

struct sysmouse_backend {
  int fd;
  int level;
  mousemode_t mode;
  mousehw_t hw_info;
  char path[32];
};

#define PSM_PACKET_MAX_SIZE 32

static int compare_times(struct timeval tv1, struct timeval tv2) {
  tv1.tv_usec -= 500000;
  if (tv1.tv_usec < 0) {
    tv1.tv_usec += 1000000;
    tv1.tv_sec -= 1;
  }
  return (tv1.tv_sec < tv2.tv_sec ||
          (tv1.tv_sec == tv2.tv_sec && tv1.tv_usec <= tv2.tv_usec));
}

static void put_event(struct event_device *ed, struct timeval *tv,
                      uint16_t type, uint16_t code, int32_t value) {
  if (type == EV_KEY) {
    if (ed->key_state[code] == value)
      return;
    else
      ed->key_state[code] = value;
  } else if (type == EV_ABS && code < ABS_MT_SLOT) {
    if (ed->abs_state[code] == value)
      return;
    else
      ed->abs_state[code] = value;
  } else if (type == EV_ABS && code > ABS_MT_SLOT) {
    if (ed->current_mt_slot == -1) {
      // error
      return;
    }
    if (ed->mt_state[ed->current_mt_slot][code - ABS_MT_FIRST] == value)
      return;
    else
      ed->mt_state[ed->current_mt_slot][code - ABS_MT_FIRST] = value;
  } else if (type == EV_SYN) {
    if (ed->events_since_last_syn == 0)
      return;
  }

  if (code == ABS_MT_SLOT) {
    if (ed->current_mt_slot == value)
      return;
    else
      ed->current_mt_slot = value;
  }

  // if (code == ABS_MT_TRACKING_ID) {
  //   printf("seding tid %d for slot %d\n", value, ed->current_mt_slot);
  // }

  if (ed->is_open) {
    struct input_event *buf;
    buf = &ed->event_buffer[ed->event_buffer_end];
    buf->time = *tv;
    buf->type = type;
    buf->code = code;
    buf->value = value;
    ++ed->event_buffer_end;
    sem_post(&ed->event_buffer_sem);
  }

  if (type == EV_SYN) {
    ed->events_since_last_syn = 0;
  } else {
    ed->events_since_last_syn++;
  }

  // prevent recursion of events
  if (ed->backend_type == SYSMOUSE_BACKEND) {
    struct sysmouse_backend *b = ed->priv_ptr;
    if (!strcmp(b->path, "/dev/sysmouse"))
      return;
  }

  static pthread_mutex_t cons_mutex = PTHREAD_MUTEX_INITIALIZER;

  pthread_mutex_lock(&cons_mutex);

  static struct mouse_data md;
  static struct timeval last_left;
  static int left_times;
  static int cfd;
  if (cfd == 0) {
    cfd = open("/dev/consolectl", O_RDWR, 0);
    if (cfd != -1) {
      system("for tty in /dev/ttyv*; do vidcontrol < $tty -m on; done");
    }
  }
  if (cfd == -1) {
    pthread_mutex_unlock(&cons_mutex);
    return;
  }

  if (type == EV_REL) {
    if (code == REL_X)
      md.x = value;
    if (code == REL_Y)
      md.y = value;
  } else if (type == EV_KEY) {
    struct mouse_info mi = ZERO_INITIALIZER;
    mi.operation = MOUSE_BUTTON_EVENT;

    if (code == BTN_LEFT) {
      mi.u.event.id = (1 << 0);
      mi.u.event.value = value;
      if (value) {
        if (compare_times(*tv, last_left)) {
          left_times += 1;
        } else {
          left_times = 1;
        }
        last_left = *tv;
        mi.u.event.value = left_times;
      }
    }
    if (code == BTN_MIDDLE) {
      mi.u.event.id = (1 << 1);
      mi.u.event.value = value;
    }
    if (code == BTN_RIGHT) {
      mi.u.event.id = (1 << 2);
      mi.u.event.value = value;
    }

    if (ioctl(cfd, CONS_MOUSECTL, &mi) == -1)
      perror("ioctl");
  } else if (type == EV_SYN && (md.x || md.y)) {
    struct mouse_info mi = ZERO_INITIALIZER;
    mi.operation = MOUSE_MOTION_EVENT;
    mi.u.data = md;
    if (ioctl(cfd, CONS_MOUSECTL, &mi) == -1)
      perror("ioctl");
    struct mouse_data tmp = ZERO_INITIALIZER;
    md = tmp;
  }

  pthread_mutex_unlock(&cons_mutex);
}

static void enable_mt_slot(struct event_device *ed, struct timeval *tv,
                           int32_t slot) {
  put_event(ed, tv, EV_ABS, ABS_MT_SLOT, slot);
  if (ed->mt_state[slot][ABS_MT_TRACKING_ID - ABS_MT_FIRST] == -1) {
    put_event(ed, tv, EV_ABS, ABS_MT_TRACKING_ID, ++ed->tracking_ids);
  }
  // else {
  //   put_event(ed, tv, EV_ABS, ABS_MT_TRACKING_ID,
  //             ed->mt_state[slot][ABS_MT_TRACKING_ID - ABS_MT_FIRST]);
  // }
}

static void disable_mt_slot(struct event_device *ed, struct timeval *tv,
                            int32_t slot) {
  if (ed->mt_state[slot][ABS_MT_TRACKING_ID - ABS_MT_FIRST] >= 0) {
    put_event(ed, tv, EV_ABS, ABS_MT_SLOT, slot);
    put_event(ed, tv, EV_ABS, ABS_MT_TRACKING_ID, -1);
  }
}

struct synaptics_ew_state {
  int32_t x;
  int32_t y;
  int32_t z;
};

struct synaptics_slot_state {
  int32_t x;
  int32_t y;
  int32_t tracking_id;
};

struct psm_backend {
  int fd;
  mousehw_t hw_info;
  int guest_dev_fd;

  // synaptics stuff
  synapticshw_t synaptics_info;
  struct synaptics_ew_state ews;
  struct synaptics_slot_state ss[2];
};

static void set_bits_generic_ps2(struct event_device *ed) {
  set_bit(ed->event_bits, EV_REL);
  set_bit(ed->event_bits, EV_KEY);
  set_bit(ed->key_bits, BTN_LEFT);
  set_bit(ed->key_bits, BTN_RIGHT);
  set_bit(ed->key_bits, BTN_MIDDLE);
  set_bit(ed->rel_bits, REL_X);
  set_bit(ed->rel_bits, REL_Y);
}

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

static int psm_backend_init(struct event_device *ed) {
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

static void *psm_fill_function(struct event_device *ed) {
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
    pthread_mutex_lock(&ed->event_buffer_mutex); // XXX

    switch (b->hw_info.model) {
      case MOUSE_MODEL_SYNAPTICS: {
        if (event_device_nr_free_buffer(ed) >= 24) {
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
            if (w <= 1 && b->synaptics_info.capMultiFinger) {
              no_fingers = w + 2;
            } else if (w >= 4 && w <= 15 && b->synaptics_info.capPalmDetect) {
              finger_width = w;
            }
          }

          struct timeval tv;
          get_clock_value(ed, &tv);

          put_event(ed, &tv, EV_KEY, BTN_LEFT, !!(buttons & (1 << 0)));
          put_event(ed, &tv, EV_KEY, BTN_RIGHT, !!(buttons & (1 << 1)));
          put_event(ed, &tv, EV_KEY, BTN_MIDDLE, !!(buttons & (1 << 2)));
          put_event(ed, &tv, EV_KEY, BTN_FORWARD, !!(buttons & (1 << 5)));
          put_event(ed, &tv, EV_KEY, BTN_BACK, !!(buttons & (1 << 6)));

          if (b->synaptics_info.capAdvancedGestures) {
            if (no_fingers >= 2) {
              enable_mt_slot(ed, &tv, 0);
              if (x > 1 && b->ews.x > 1)
                put_event(ed, &tv, EV_ABS, ABS_MT_POSITION_X,
                          MIN(x, b->ews.x));
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
          get_clock_value(ed, &tv);

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
    }

    pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
  }

  return NULL;
}

static int sysmouse_backend_init(struct event_device *ed, char const *path) {
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

static void *sysmouse_fill_function(struct event_device *ed) {
  struct sysmouse_backend *b = ed->priv_ptr;
  int obuttons = 0;
  unsigned char packet[PSM_PACKET_MAX_SIZE];

  while (read(b->fd, packet, (size_t)b->mode.packetsize) ==
         b->mode.packetsize) {
    pthread_mutex_lock(&ed->event_buffer_mutex); // XXX

    if (event_device_nr_free_buffer(ed) >= 8) {
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
      put_event(ed, &tv, EV_KEY, BTN_MIDDLE,
                !!(buttons & MOUSE_SYS_BUTTON2UP));
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
    }

    pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
  }

  return NULL;
}

static void evdevfbsd_hup_catcher(int dummy __unused) {}

static void *wait_and_proc(void *notused __unused) {
  int ret;

  struct sigaction act;
  memset(&act, 0, sizeof(act));
  act.sa_handler = &evdevfbsd_hup_catcher;
  sigaction(SIGHUP, &act, NULL); // XXX

  for (;;) {
    ret = cuse_wait_and_process();
    if (ret < 0)
      break;
  }
  return NULL;
}

static int event_device_init(struct event_device *ed) {
  memset(ed, 0, sizeof(*ed));
  ed->fd = -1;
  ed->event_buffer_end = 0;
  ed->clock = CLOCK_REALTIME;
  ed->current_mt_slot = -1;
  for (int i = 0; i < MAX_SLOTS; ++i) {
    ed->mt_state[i][ABS_MT_TRACKING_ID - ABS_MT_FIRST] = -1;
  }
  return pthread_mutex_init(&ed->event_buffer_mutex, NULL) ||
         sem_init(&ed->event_buffer_sem, 0, 0);
}

static int event_device_open(struct event_device *ed, char const *path) {
  void *(*fill_function)(void *);

  if (!strcmp(path, "/dev/bpsm0") || !strcmp(path, "/dev/psm0")) {
    if (psm_backend_init(ed))
      return -1;
    fill_function = (void *(*)(void *))psm_fill_function;
    ed->backend_type = PSM_BACKEND;
  } else if (!strcmp(path, "/dev/sysmouse") || !strcmp(path, "/dev/ums0")) {
    if (sysmouse_backend_init(ed, path))
      return -1;
    fill_function = (void *(*)(void *))sysmouse_fill_function;
    ed->backend_type = SYSMOUSE_BACKEND;
  } else {
    return -EINVAL;
  }

  return pthread_create(&ed->fill_thread, NULL, fill_function, ed);
}

static int event_device_open_as_guest(struct event_device *ed,
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

  if (pthread_create(&ed->fill_thread, NULL,
                     (void *(*)(void *))psm_fill_function, ed) == 0)
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

static int create_cuse_device(struct event_device *ed) {
  char device_name[32] = ZERO_INITIALIZER;
  for (int i = 0; i < 32; ++i) {
    if (snprintf(device_name, sizeof(device_name), "/dev/input/event%d", i) ==
        -1)
      errx(1, "snprintf failed");
    if (access(device_name, F_OK))
      break;
  }

  struct cuse_dev *evdevfbsddev = cuse_dev_create(&evdevfbsd_methods, ed, NULL,
                                                  0, 0, 0444, &device_name[5]);
  if (!evdevfbsddev)
    return -1;

  return 0;
}

int main(int argc, char **argv) {
  int ret;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <device>\n", argv[0]);
    exit(1);
  }

  if ((ret = cuse_init()) < 0)
    errx(1, "cuse_init returned %d", ret);

  struct event_device ed;
  event_device_init(&ed); // XXX
  if (event_device_open(&ed, argv[1]))
    errx(1, "could not open event device");

  bool has_guest_device = false;
  struct event_device ed_guest;
  if (ed.backend_type == PSM_BACKEND) {
    struct psm_backend *b = ed.priv_ptr;
    if (b->hw_info.model == MOUSE_MODEL_SYNAPTICS &&
        b->synaptics_info.capPassthrough) {
      event_device_init(&ed_guest); // XXX
      if (event_device_open_as_guest(&ed_guest, &ed) == 0)
        has_guest_device = true;
    }
  }

  if (create_cuse_device(&ed))
    errx(1, "failed to create event device");

  if (has_guest_device) {
    if (create_cuse_device(&ed_guest))
      errx(1, "failed to create event device");
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
