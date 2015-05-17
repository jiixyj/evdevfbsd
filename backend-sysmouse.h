#ifndef BACKEND_SYSMOUSE_H_
#define BACKEND_SYSMOUSE_H_

#include <sys/mouse.h>

#include "evdevfbsd.h"

struct sysmouse_backend {
  int fd;
  int level;
  mousemode_t mode;
  mousehw_t hw_info;
  char path[32];
};

int sysmouse_backend_init(struct event_device *ed, char const *path);
void *sysmouse_fill_function(struct event_device *ed);

#endif
