#ifndef BACKEND_ATKBD_H_
#define BACKEND_ATKBD_H_

#include "evdevfbsd.h"

int atkbd_backend_init(struct event_device *ed);
void atkbd_backend_cleanup(struct event_device *ed);

#endif
