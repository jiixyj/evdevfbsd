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
#include "backend-uhid.h"

static volatile sig_atomic_t hup_catched = 0;

static struct event_client_state *event_client_new() {
  struct event_client_state *ret =
      calloc(sizeof(struct event_client_state), 1);
  if (!ret)
    return NULL;

  if (sem_init(&ret->event_buffer_sem, 0, 0) == -1) {
    free(ret);
    return NULL;
  }

  return ret;
}

static int evdevfbsd_open(struct cuse_dev *cdev, int fflags __unused) {
  // puts("device opened");
  struct event_device *ed = cuse_dev_get_priv0(cdev);

  int ret = CUSE_ERR_BUSY;

  pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
  for (unsigned i = 0; i < nitems(ed->event_clients); ++i) {
    if (!ed->event_clients[i]) {
      ed->event_clients[i] = event_client_new();
      if (ed->event_clients[i]) {
        cuse_dev_set_per_file_handle(cdev, ed->event_clients[i]);
        ret = CUSE_ERR_NONE;
      }
      break;
    }
  }
  pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
  return ret;
}

static int evdevfbsd_close(struct cuse_dev *cdev, int fflags __unused) {
  struct event_device *ed = cuse_dev_get_priv0(cdev);

  pthread_mutex_lock(&ed->event_buffer_mutex); // XXX

  struct event_client_state *client_state = cuse_dev_get_per_file_handle(cdev);

  for (int i = 0; i < client_state->event_buffer_end; ++i)
    sem_wait(&client_state->event_buffer_sem);

  sem_destroy(&client_state->event_buffer_sem);
  client_state->event_buffer_end = 0;

  for (unsigned i = 0; i < nitems(ed->event_clients); ++i) {
    if (ed->event_clients[i] == client_state) {
      ed->event_clients[i] = NULL;
      if (ed->exclusive_client == client_state) {
        ed->exclusive_client = NULL;
      }
      break;
    }
  }

  free(client_state);

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

  struct event_client_state *client_state = cuse_dev_get_per_file_handle(cdev);

retry:
  if (!(fflags & CUSE_FFLAG_NONBLOCK)) {
    ret = sem_wait(&client_state->event_buffer_sem);
    if (ret == -1 && (cuse_got_peer_signal() == 0 || hup_catched))
      return CUSE_ERR_SIGNAL;
  }

  pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
  if (client_state->event_buffer_end == 0) {
    if (fflags & CUSE_FFLAG_NONBLOCK)
      ret = CUSE_ERR_WOULDBLOCK;
    else {
      sem_post(&client_state->event_buffer_sem);
      pthread_mutex_unlock(&ed->event_buffer_mutex);
      goto retry;
    }
  } else {
    nr_events = MIN(requested_events, client_state->event_buffer_end);
    ret = cuse_copy_out(client_state->event_buffer, user_ptr,
                        nr_events * (int)sizeof(struct input_event));
    if (ret == 0) {
      memmove(client_state->event_buffer,
              &client_state->event_buffer[nr_events],
              (size_t)(client_state->event_buffer_end - nr_events) *
                  sizeof(struct input_event));
      client_state->event_buffer_end =
          client_state->event_buffer_end - nr_events;
      for (int i = 0; i < nr_events - 1; ++i)
        sem_wait(&client_state->event_buffer_sem);
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

  struct event_client_state *client_state = cuse_dev_get_per_file_handle(cdev);

  pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
  if (client_state->event_buffer_end > 0)
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
    case EVIOCGRAB: {
      // printf("GRAB: %p\n", peer_data);
      struct event_client_state *client_state =
          cuse_dev_get_per_file_handle(cdev);

      if (peer_data) {
        if (ed->exclusive_client != NULL) {
          return CUSE_ERR_BUSY;
        } else {
          ed->exclusive_client = client_state;
        }
      } else {
        if (ed->exclusive_client != client_state) {
          return CUSE_ERR_INVALID;
        } else {
          ed->exclusive_client = NULL;
        }
      }

      return 0;
    }
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
      // printf("got ioctl EVIOCGBIT %lu\n", len);
      return cuse_copy_out(ed->event_bits, peer_data,
                           (int)MIN(sizeof(ed->event_bits), len));
    }
    case EVIOCGNAME(0): {
      // printf("got ioctl EVIOCGNAME %lu\n", len);
      if (ed->device_name) {
        return cuse_copy_out(ed->device_name, peer_data,
                             (int)MIN(strlen(ed->device_name), len));
      } else {
        return 0;
      }
    }
    case EVIOCGPHYS(0):
      // printf("got ioctl EVIOCGPHYS %lu\n", len);
      // ENOENT would be better, but that is not supported by cuse
      return 0;
    case EVIOCGUNIQ(0):
      // printf("got ioctl EVIOCGUNIQ %lu\n", len);
      // ENOENT would be better, but that is not supported by cuse
      return 0;
    case EVIOCGBIT(EV_REL, 0): {
      // printf("got ioctl EVIOCGBIT %lu\n", len);
      return cuse_copy_out(ed->rel_bits, peer_data,
                           (int)MIN(sizeof(ed->rel_bits), len));
    }
    case EVIOCGBIT(EV_KEY, 0): {
      // printf("got ioctl EVIOCGBIT %lu\n", len);
      return cuse_copy_out(ed->key_bits, peer_data,
                           (int)MIN(sizeof(ed->key_bits), len));
    }
    case EVIOCGBIT(EV_ABS, 0): {
      // printf("got ioctl EVIOCGBIT %lu\n", len);
      return cuse_copy_out(ed->abs_bits, peer_data,
                           (int)MIN(sizeof(ed->abs_bits), len));
    }
    case EVIOCGBIT(EV_MSC, 0): {
      // printf("got ioctl EVIOCGBIT %lu\n", len);
      return cuse_copy_out(ed->msc_bits, peer_data,
                           (int)MIN(sizeof(ed->msc_bits), len));
    }
    case EVIOCGBIT(EV_LED, 0):
    case EVIOCGBIT(EV_SW, 0):
    case EVIOCGBIT(EV_FF, 0):
    case EVIOCGBIT(EV_SND, 0):
      // printf("got ioctl EVIOCGBIT %lu\n", len);
      memset(bits, 0, sizeof(bits));
      return cuse_copy_out(bits, peer_data, (int)MIN(sizeof(bits), len));
    case EVIOCGKEY(0):
      // TODO: implement this
      // printf("got ioctl EVIOCGKEY %lu\n", len);
      return 0;
    case EVIOCGLED(0):
      // printf("got ioctl EVIOCGLED %lu\n", len);
      return 0;
    case EVIOCGSW(0):
      // printf("got ioctl EVIOCGSW %lu\n", len);
      return 0;
    case EVIOCGPROP(0):
      // printf("got ioctl EVIOCGPROP %lu\n", len);
      return cuse_copy_out(ed->prop_bits, peer_data,
                           (int)MIN(sizeof(ed->prop_bits), len));
    case EVIOCGMTSLOTS(0): {
      // printf("got ioctl EVIOCGMTSLOTS %lu\n", len);
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
      // printf("got ioctl EVIOCGABS for axis %ld\n", cmd & ABS_MAX);
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

static void evdevfbsd_hup_catcher(int dummy __unused) {
  hup_catched = 1;
}

static void *wait_and_proc(void *notused __unused) {
  int ret;

  struct sigaction act;
  memset(&act, 0, sizeof(act));
  act.sa_handler = &evdevfbsd_hup_catcher;
  sigaction(SIGHUP, &act, NULL); // XXX

  while (!hup_catched) {
    ret = cuse_wait_and_process();
    if (ret < 0)
      break;
  }
  return NULL;
}

static int event_device_init(struct event_device *ed) {
  memset(ed, 0, sizeof(*ed));
  ed->fd = -1;
  ed->clock = CLOCK_REALTIME;
  ed->cuse_device = NULL;
  ed->current_mt_slot = -1;
  for (int i = 0; i < MAX_SLOTS; ++i) {
    ed->mt_state[i][ABS_MT_TRACKING_ID - ABS_MT_FIRST] = -1;
  }
  return pthread_mutex_init(&ed->event_buffer_mutex, NULL);
}

static int event_device_open(struct event_device *ed, char const *path) {
  if (!strcmp(path, "/dev/bpsm0") || !strcmp(path, "/dev/psm0")) {
    if (psm_backend_init(ed))
      return -1;
    ed->fill_function = psm_fill_function;
    ed->backend_type = PSM_BACKEND;
  } else if (!strcmp(path, "/dev/sysmouse") || !strcmp(path, "/dev/ums0")) {
    if (sysmouse_backend_init(ed, path))
      return -1;
    ed->fill_function = sysmouse_fill_function;
    ed->backend_type = SYSMOUSE_BACKEND;
  } else if (!strcmp(path, "/dev/atkbd0")) {
    if (atkbd_backend_init(ed))
      return -1;
    ed->fill_function = atkbd_fill_function;
    ed->backend_type = ATKBD_BACKEND;
  } else if (!strncmp(path, "/dev/uhid", 9)) {
    if (uhid_backend_init(ed, path))
      return -1;
    ed->fill_function = uhid_fill_function;
    ed->backend_type = UHID_BACKEND;
  } else {
    return -EINVAL;
  }

  return 0;
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

  ed->cuse_device = cuse_dev_create(&evdevfbsd_methods, ed, NULL, 0, 0, 0666,
                                    &device_name[5]);
  if (!ed->cuse_device)
    return -1;

  return 0;
}

static void *fill_thread_starter(void *edp) {
  struct event_device *ed = (struct event_device *)edp;
  return ed->fill_function(ed);
}

static void usage(char const *program_name) __attribute__ ((noreturn));
static void usage(char const *program_name) {
  fprintf(stderr, "usage: %s [-d] <device>\n", program_name);
  exit(1);
}

int main(int argc, char **argv) {
  char *program_name = argv[0];
  int ch;
  bool daemonize = false;

  while ((ch = getopt(argc, argv, "d")) != -1) {
    switch (ch) {
      case 'd':
        daemonize = true;
        break;
      default:
        usage(argv[0]);
    }
  }
  argc -= optind;
  argv += optind;

  int ret;

  if (argc != 1) {
    usage(program_name);
  }

  if ((ret = cuse_init()) < 0)
    errx(1, "cuse_init returned %d", ret);

  struct event_device ed;
  event_device_init(&ed); // XXX
  if (event_device_open(&ed, argv[0]))
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

  if (daemonize && daemon(0, 0) == -1) {
    perror("daemon");
    errx(1, "failed to daemonize");
  }

  pthread_create(&ed.fill_thread, NULL, fill_thread_starter, &ed); // XXX
  if (has_guest_device) {
    pthread_create(&ed_guest.fill_thread, NULL, fill_thread_starter,
                   &ed_guest); // XXX
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
