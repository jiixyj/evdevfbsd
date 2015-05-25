#include "util.h"

#include <sys/consio.h>
#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include "backend-sysmouse.h"
#include "zero_initializer.h"

void set_bit(uint64_t *array, int bit) {
  array[bit / 64] |= (1LL << (bit % 64));
}

void set_bits_generic_ps2(struct event_device *ed) {
  set_bit(ed->event_bits, EV_REL);
  set_bit(ed->event_bits, EV_KEY);
  set_bit(ed->key_bits, BTN_LEFT);
  set_bit(ed->key_bits, BTN_RIGHT);
  set_bit(ed->key_bits, BTN_MIDDLE);
  set_bit(ed->rel_bits, REL_X);
  set_bit(ed->rel_bits, REL_Y);
}

static int compare_times(struct timeval tv1, struct timeval tv2) {
  tv1.tv_usec -= 500000;
  if (tv1.tv_usec < 0) {
    tv1.tv_usec += 1000000;
    tv1.tv_sec -= 1;
  }
  return (tv1.tv_sec < tv2.tv_sec ||
          (tv1.tv_sec == tv2.tv_sec && tv1.tv_usec <= tv2.tv_usec));
}

void put_event(struct event_device *ed, struct timeval *tv,
                      uint16_t type, uint16_t code, int32_t value) {
  if (type == EV_KEY) {
    if (ed->key_state[code] == value && value < 2)
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

  for (unsigned i = 0; i < nitems(ed->event_clients); ++i) {
    struct input_event *buf;
    struct event_client_state *client_state = ed->event_clients[i];
    if (!client_state)
      continue;

    int needed_buffer = client_state->free_buffer_needed;
    if (needed_buffer < 1)
      needed_buffer = 1;

    if (EVENT_BUFFER_SIZE - client_state->event_buffer_end < needed_buffer)
      continue;

    buf = &client_state->event_buffer[client_state->event_buffer_end];
    buf->time = *tv;
    buf->type = type;
    buf->code = code;
    buf->value = value;
    ++client_state->event_buffer_end;
    --client_state->free_buffer_needed;
    sem_post(&client_state->event_buffer_sem);
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

    if (mi.u.event.id) {
      if (ioctl(cfd, CONS_MOUSECTL, &mi) == -1)
        perror("ioctl");
    }
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

void enable_mt_slot(struct event_device *ed, struct timeval *tv,
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

void disable_mt_slot(struct event_device *ed, struct timeval *tv,
                     int32_t slot) {
  if (ed->mt_state[slot][ABS_MT_TRACKING_ID - ABS_MT_FIRST] >= 0) {
    put_event(ed, tv, EV_ABS, ABS_MT_SLOT, slot);
    put_event(ed, tv, EV_ABS, ABS_MT_TRACKING_ID, -1);
  }
}

void get_clock_value(struct event_device *ed, struct timeval *tv) {
  struct timespec ts;
  clock_gettime(ed->clock, &ts); // XXX
  struct bintime bt;
  timespec2bintime(&ts, &bt);
  bintime2timeval(&bt, tv);
}

void event_client_need_free_bufsize(struct event_device *ed, int needed_buffer) {
  for (unsigned i = 0; i < nitems(ed->event_clients); ++i) {
    struct event_client_state *client_state = ed->event_clients[i];
    if (!client_state)
      continue;

    client_state->free_buffer_needed = needed_buffer;
  }
}
