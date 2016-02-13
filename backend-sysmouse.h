#ifndef BACKEND_SYSMOUSE_H_
#define BACKEND_SYSMOUSE_H_

#include "evdevfbsd.h"

int sysmouse_backend_init(struct event_device *ed, char const *path);
char const *sysmouse_backend_get_path(struct event_device *ed);

#endif
