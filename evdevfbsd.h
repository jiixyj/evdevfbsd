#ifndef EVDEVFBSD_H_
#define EVDEVFBSD_H_

#include <stdbool.h>
#include <stdint.h>

#include <cuse.h>
#include <pthread.h>
#include <semaphore.h>

#include "linux/input.h"

#define EVENT_BUFFER_SIZE 1024
#define MAX_SLOTS 16

#define ABS_MT_FIRST ABS_MT_TOUCH_MAJOR
#define ABS_MT_LAST ABS_MT_TOOL_Y

enum backends { PSM_BACKEND, SYSMOUSE_BACKEND, ATKBD_BACKEND };

struct event_client_state {
  struct input_event event_buffer[EVENT_BUFFER_SIZE];
  int event_buffer_end; /* index at which to write next event */
  int free_buffer_needed;
  sem_t event_buffer_sem;
};

struct event_device {
  int fd;
  struct event_client_state *event_clients[8];
  pthread_mutex_t event_buffer_mutex;
  pthread_t fill_thread;
  void *(*fill_function)(struct event_device *);
  uint16_t tracking_ids;
  int clock;
  int backend_type;
  struct cuse_dev *cuse_device;
  void *priv_ptr;

  struct input_id iid;
  char const *device_name;
  uint64_t event_bits[256];
  uint64_t rel_bits[256];
  uint64_t key_bits[256];
  uint64_t abs_bits[256];
  uint64_t msc_bits[256];
  uint64_t prop_bits[256];
  struct input_absinfo abs_info[ABS_MAX];

  uint16_t events_since_last_syn;
  int32_t key_state[KEY_CNT];
  int32_t abs_state[ABS_CNT];
  int32_t current_mt_slot;
  int32_t mt_state[MAX_SLOTS][ABS_MT_LAST - ABS_MT_FIRST + 1];
};

#endif
