#ifndef BACKEND_UHID_H_
#define BACKEND_UHID_H_

#include "evdevfbsd.h"

#include <usbhid.h>
#include <dev/usb/usbhid.h>

int uhid_backend_init(struct event_device *ed, char const *path);
void *uhid_fill_function(struct event_device *ed);

#endif
