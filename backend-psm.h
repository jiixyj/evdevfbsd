#ifndef BACKEND_PSM_H_
#define BACKEND_PSM_H_

#include <sys/mouse.h>

#include <stdint.h>

#define PSM_PACKET_MAX_SIZE 32

#include "evdevfbsd.h"

struct synaptics_ew_state {
	int32_t x;
	int32_t y;
	int32_t z;
};

struct synaptics_slot_state {
	int32_t x;
	int32_t y;
	int32_t tracking_id;
};

struct psm_backend {
	int fd;
	mousehw_t hw_info;
	int guest_dev_fd;

	// synaptics stuff
	synapticshw_t synaptics_info;
	struct synaptics_ew_state ews;
	struct synaptics_slot_state ss[2];
};

int psm_backend_init(struct event_device *ed);
void *psm_fill_function(struct event_device *ed);

int event_device_open_as_guest(
    struct event_device *ed, struct event_device *parent);

#endif
