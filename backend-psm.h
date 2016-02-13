#ifndef BACKEND_PSM_H_
#define BACKEND_PSM_H_

#include "evdevfbsd.h"

#define PSM_PACKET_MAX_SIZE 32

int psm_backend_init(struct event_device *ed);

#endif
