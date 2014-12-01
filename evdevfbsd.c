#include <sys/param.h>

#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <cuse.h>
#include <err.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

#include "linux/input.h"

#define EVENT_BUFFER_SIZE 1024

struct event_device {
  int fd;
  struct input_event event_buffer[EVENT_BUFFER_SIZE];
  int event_buffer_end;   /* index at which to write next event */
  pthread_mutex_t event_buffer_mutex;
  sem_t event_buffer_sem;
  pthread_t fill_thread;
  bool has_reader;
};

int event_device_nr_free_buffer(struct event_device* ed) {
  return EVENT_BUFFER_SIZE - ed->event_buffer_end;
}

int evdevfbsd_open(struct cuse_dev *cdev, int fflags) {
  puts("device opened");
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
  puts("device closed");
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
  printf("device read %d\n", fflags);

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
    puts("sem wait...");
    ret = sem_wait(&ed->event_buffer_sem);
    puts("sem wait done!");
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
    puts("copy out");
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

  switch (cmd) {
    case EVIOCGID: {
      printf("got ioctl EVIOCGID\n");
      struct input_id iid = {0};
      iid.bustype = BUS_VIRTUAL;
      return cuse_copy_out(&iid, peer_data, sizeof(iid));
    }
    case EVIOCGVERSION: {
      printf("got ioctl EVIOCGVERSION\n");
      int version = EV_VERSION;
      return cuse_copy_out(&version, peer_data, sizeof(version));
    }
  }

  int base_cmd = IOCBASECMD(cmd);
  int len = IOCPARM_LEN(cmd);

  switch (base_cmd) {
    case EVIOCGBIT(0, 0): {
      printf("got ioctl EVIOCGBIT %d\n", len);
      memset(bits, 0, sizeof(bits));
      set_bit(bits, EV_KEY);
      set_bit(bits, EV_REL);
      return cuse_copy_out(bits, peer_data, MIN((int)sizeof(bits), len));
    }
    case EVIOCGNAME(0): {
      printf("got ioctl EVIOCGNAME %d\n", len);
      const char* name = "testmouse";
      return cuse_copy_out(name, peer_data, MIN((int)strlen(name), len));
    }
    case EVIOCGPHYS(0):
      printf("got ioctl EVIOCGPHYS %d\n", len);
      // ENOENT would be better, but that is not supported by cuse
      return 0;
    case EVIOCGUNIQ(0):
      printf("got ioctl EVIOCGUNIQ %d\n", len);
      // ENOENT would be better, but that is not supported by cuse
      return 0;
    case EVIOCGBIT(EV_REL, 0): {
      printf("got ioctl EVIOCGBIT %d\n", len);
      memset(bits, 0, sizeof(bits));
      set_bit(bits, REL_X);
      set_bit(bits, REL_Y);
      return cuse_copy_out(bits, peer_data, MIN((int)sizeof(bits), len));
    }
    case EVIOCGBIT(EV_ABS, 0):
    case EVIOCGBIT(EV_LED, 0):
    case EVIOCGBIT(EV_KEY, 0):
    case EVIOCGBIT(EV_SW, 0):
    case EVIOCGBIT(EV_MSC, 0):
    case EVIOCGBIT(EV_FF, 0):
    case EVIOCGBIT(EV_SND, 0):
      printf("got ioctl EVIOCGBIT %d\n", len);
      memset(bits, 0, sizeof(bits));
      return cuse_copy_out(bits, peer_data, MIN((int)sizeof(bits), len));
    case EVIOCGKEY(0):
      printf("got ioctl EVIOCGKEY %d\n", len);
      return 0;
    case EVIOCGLED(0):
      printf("got ioctl EVIOCGLED %d\n", len);
      return 0;
    case EVIOCGSW(0):
      printf("got ioctl EVIOCGSW %d\n", len);
      return 0;
  }

  printf("got ioctl %lu\n", cmd);
  return CUSE_ERR_INVALID;
}

struct cuse_methods evdevfbsd_methods = {.cm_open = evdevfbsd_open,
                                         .cm_close = evdevfbsd_close,
                                         .cm_read = evdevfbsd_read,
                                         .cm_poll = evdevfbsd_poll,
                                         .cm_ioctl = evdevfbsd_ioctl};

int event_device_init(struct event_device* ed) {
  ed->fd = -1;
  memset(&ed->event_buffer, 0, sizeof(ed->event_buffer));
  ed->event_buffer_end = 0;
  return pthread_mutex_init(&ed->event_buffer_mutex, NULL) ||
         sem_init(&ed->event_buffer_sem, 0, 0);
}

int event_device_open(struct event_device *ed, char const *path,
                      void *(*fill_function)(struct event_device *ed)) {
  if (path) {
    // TODO;
  }

  return pthread_create(&ed->fill_thread, NULL,
                        (void *(*)(void *))fill_function, ed);
}

#if 1
void* dummy_fill_function(struct event_device *ed) {
  for (;;) {
    pthread_mutex_lock(&ed->event_buffer_mutex); // XXX

    if (ed->has_reader && event_device_nr_free_buffer(ed) >= 3) {
      puts("putting events...");

      struct timeval tv;
      gettimeofday(&tv, NULL); // XXX
      struct input_event *buf;

      buf = &ed->event_buffer[ed->event_buffer_end];
      buf->time = tv;
      buf->type = EV_REL;
      buf->code = REL_X;
      buf->value = 3;
      ++ed->event_buffer_end;
      sem_post(&ed->event_buffer_sem);

      buf = &ed->event_buffer[ed->event_buffer_end];
      buf->time = tv;
      buf->type = EV_REL;
      buf->code = REL_Y;
      buf->value = 4;
      ++ed->event_buffer_end;
      sem_post(&ed->event_buffer_sem);

      buf = &ed->event_buffer[ed->event_buffer_end];
      buf->time = tv;
      buf->type = EV_SYN;
      buf->code = SYN_REPORT;
      buf->value = 0;
      ++ed->event_buffer_end;
      sem_post(&ed->event_buffer_sem);

      cuse_poll_wakeup();
    }

    pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX

    sleep(5);
  }

  return NULL;
}
#endif

void evdevfbsd_hup_catcher(int dummy) {
  puts("SIGHUP");
}

void *wait_and_proc(void *notused) {
  int ret;

  signal(SIGHUP, evdevfbsd_hup_catcher);
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

int main() {
  printf("sizeof struct event: %d\n", (int) sizeof(struct input_event));
  int ret;

  if ((ret = cuse_init()) < 0)
    errx(1, "cuse_init returned %d", ret);


  struct event_device ed;
  event_device_init(&ed); // XXX
  event_device_open(&ed, NULL, dummy_fill_function); // XXX

  struct cuse_dev *evdevfbsddev = cuse_dev_create(
      &evdevfbsd_methods, &ed, NULL, 0, 0, 0444, "input/event0");
  if (!evdevfbsddev)
    errx(1, "cuse_dev_create failed");


  pthread_t worker1, worker2;
  pthread_create(&worker1, NULL, wait_and_proc, NULL); // XXX
  pthread_create(&worker2, NULL, wait_and_proc, NULL); // XXX

  pthread_join(worker2, NULL); // XXX
  pthread_join(worker1, NULL); // XXX
}
