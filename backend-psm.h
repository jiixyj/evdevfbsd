#ifndef BACKEND_PSM_H_
#define BACKEND_PSM_H_

#include "evdevfbsd.h"

#define PSM_PACKET_MAX_SIZE 32

int psm_backend_init(struct event_device *ed);
void *psm_fill_function(struct event_device *ed);

int psm_open_as_guest(
    struct event_device *ed, struct event_device *parent);

#endif
