#ifndef BACKEND_UHID_H_
#define BACKEND_UHID_H_

#include "evdevfbsd.h"

int uhid_backend_init(struct event_device *ed, char const *path);

#endif
