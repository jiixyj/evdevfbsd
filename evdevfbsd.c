#include <sys/param.h>

#include <stdio.h>
#include <string.h>

#include <cuse.h>
#include <err.h>
#include <pthread.h>
#include <unistd.h>

#include "linux/input.h"

struct event_device {
  int fd;
  struct input_event event_buffer[512];
  int event_buffer_start; /* index of oldest event */
  int event_buffer_end;   /* index at which to write next event */
  pthread_mutex_t event_buffer_mutex;
  pthread_cond_t event_buffer_cond;
  pthread_t fill_thread;
};

int event_device_nr_free_buffer(struct event_device* ed) {
  int buf_size = sizeof(ed->event_buffer) / sizeof(ed->event_buffer[1]);
  int start = ed->event_buffer_start;
  while (start <= ed->event_buffer_end)
    start += buf_size;
  return start - ed->event_buffer_end - 1;
}

int event_device_nr_inside_buffer(struct event_device* ed) {
  int buf_size = sizeof(ed->event_buffer) / sizeof(ed->event_buffer[1]);
  return buf_size - 1 - event_device_nr_free_buffer(ed);
}

int evdevfbsd_open(struct cuse_dev *cdev, int fflags) {
  puts("device opened");
  return CUSE_ERR_NONE;
}

int evdevfbsd_close(struct cuse_dev *cdev, int fflags) {
  puts("device closed");
  return CUSE_ERR_NONE;
}

int evdevfbsd_read(struct cuse_dev *cdev, int fflags, void *user_ptr,
                   int len) {
  printf("device read %d\n", fflags);

  int requested_events = len / sizeof(struct input_event);
  int nr_events;

  struct event_device* ed = cuse_dev_get_priv0(cdev);

  int ret;

  pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
do_copy_out:
  nr_events = MIN(requested_events, event_device_nr_inside_buffer(ed));
  if (nr_events > 0) {
    puts("copy out");
    ret = cuse_copy_out(&ed->event_buffer[ed->event_buffer_start], user_ptr,
                        nr_events * sizeof(struct input_event));
    if (ret == 0)
      ed->event_buffer_start += nr_events;
  } else if (fflags & CUSE_FFLAG_NONBLOCK) {
    ret = CUSE_ERR_WOULDBLOCK;
  } else {
    puts("waiting on cond");
    pthread_cond_wait(&ed->event_buffer_cond, &ed->event_buffer_mutex); // XXX
    goto do_copy_out;
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
  if (event_device_nr_inside_buffer(ed) > 0)
    ret = CUSE_POLL_READ;
  pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX

  return ret;
}

struct cuse_methods evdevfbsd_methods = {.cm_open = evdevfbsd_open,
                                         .cm_close = evdevfbsd_close,
                                         .cm_read = evdevfbsd_read,
                                         .cm_poll = evdevfbsd_poll};

int event_device_init(struct event_device* ed) {
  ed->fd = -1;
  memset(&ed->event_buffer, 0, sizeof(ed->event_buffer));
  ed->event_buffer_start = 0;
  ed->event_buffer_end = 0;
  return pthread_mutex_init(&ed->event_buffer_mutex, NULL) ||
         pthread_cond_init(&ed->event_buffer_cond, NULL);
}

int event_device_open(struct event_device *ed, char const *path,
                       void *(*fill_function)(struct event_device *)) {
  if (path) {
    // TODO;
  }

  return pthread_create(&ed->fill_thread, NULL,
                        (void *(*)(void *))fill_function, ed);
}

void* dummy_fill_function(struct event_device *ed) {
  for (;;) {
    pthread_mutex_lock(&ed->event_buffer_mutex); // XXX

    if (event_device_nr_free_buffer(ed) >= 3) {
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

      buf = &ed->event_buffer[ed->event_buffer_end];
      buf->time = tv;
      buf->type = EV_REL;
      buf->code = REL_Y;
      buf->value = 4;
      ++ed->event_buffer_end;

      buf = &ed->event_buffer[ed->event_buffer_end];
      buf->time = tv;
      buf->type = EV_SYN;
      buf->code = SYN_REPORT;
      buf->value = 0;
      ++ed->event_buffer_end;

      cuse_poll_wakeup();
      pthread_cond_broadcast(&ed->event_buffer_cond);
    }

    pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX

    sleep(5);
  }

  return NULL;
}

void *wait_and_proc(void *notused) {
  int ret;
  for (;;) {
    ret = cuse_wait_and_process();
    if (ret < 0)
      warnx("cuse_wait_and_process returned %d\n", ret);
  }
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
