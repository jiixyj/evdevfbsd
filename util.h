#ifndef UTIL_EFBSD_H_
#define UTIL_EFBSD_H_

#include "evdevfbsd.h"

#include <sys/time.h>

void set_bit(uint64_t *array, int bit);
void set_bits_generic_ps2(struct event_device *ed);
void put_event(struct event_device *ed, struct timeval *tv, uint16_t type,
               uint16_t code, int32_t value);
void enable_mt_slot(struct event_device *ed, struct timeval *tv, int32_t slot);
void disable_mt_slot(struct event_device *ed, struct timeval *tv,
                     int32_t slot);
void event_client_need_free_bufsize(struct event_device *ed,
                                    int needed_buffer);
void get_clock_value(struct event_device *ed, struct timeval *tv);

#endif
