#include "evdevfbsd.h"

#include <sys/event.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include "util.h"
#include "zero_initializer.h"

#include "backend-psm.h"
#include "backend-sysmouse.h"
#include "backend-atkbd.h"

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
    case EVIOCGBIT(EV_MSC, 0): {
      // printf("got ioctl EVIOCGBIT %d\n", len);
      return cuse_copy_out(ed->msc_bits, peer_data,
                           (int)MIN(sizeof(ed->msc_bits), len));
    }
    case EVIOCGBIT(EV_LED, 0):
    case EVIOCGBIT(EV_SW, 0):
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

      struct input_mt_request {
        uint32_t code;
        int32_t values[MAX_SLOTS];
      };

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
  ed->cuse_device = NULL;
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
  } else if (!strcmp(path, "/dev/atkbd0")) {
    if (atkbd_backend_init(ed))
      return -1;
    fill_function = (void *(*)(void *))atkbd_fill_function;
    ed->backend_type = ATKBD_BACKEND;
  } else {
    return -EINVAL;
  }

  return pthread_create(&ed->fill_thread, NULL, fill_function, ed);
}

static void event_device_cleanup(struct event_device *ed) {
  if (ed->backend_type == ATKBD_BACKEND) {
    atkbd_backend_cleanup(ed);
  }
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

  ed->cuse_device = cuse_dev_create(&evdevfbsd_methods, ed, NULL, 0, 0, 0444,
                                    &device_name[5]);
  if (!ed->cuse_device)
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

  for (unsigned i = 0; i < nitems(worker); ++i) {
    pthread_create(&worker[i], NULL, wait_and_proc, NULL); // XXX
  }

  signal(SIGINT, SIG_IGN);
  signal(SIGTERM, SIG_IGN);
  int kq = kqueue();
  if (kq == -1)
    errx(1, "failed to create kqueue");

  struct kevent evs[2];
  EV_SET(&evs[0], SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);
  EV_SET(&evs[1], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);
  if (kevent(kq, evs, 2, NULL, 0, NULL) == -1)
    errx(1, "kevent failed");

  kevent(kq, NULL, 0, evs, 1, NULL);

  for (unsigned i = 0; i < nitems(worker); ++i) {
    pthread_kill(worker[i], SIGHUP);
    pthread_join(worker[i], NULL); // XXX
  }

  fprintf(stderr, "workers joined...\n");

  if (has_guest_device) {
    cuse_dev_destroy(ed_guest.cuse_device);
    event_device_cleanup(&ed_guest);
  }

  cuse_dev_destroy(ed.cuse_device);
  event_device_cleanup(&ed);

  fprintf(stderr, "closing...\n");
}
