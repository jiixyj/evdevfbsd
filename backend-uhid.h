#ifndef BACKEND_UHID_H_
#define BACKEND_UHID_H_

#include "evdevfbsd.h"

#include <usbhid.h>
#include <dev/usb/usbhid.h>

struct uhid_backend {
  int fd;
  report_desc_t report_desc;
  char path[32];
};

int uhid_backend_init(struct event_device *ed, char const *path);
void *uhid_fill_function(struct event_device *ed);

#endif
