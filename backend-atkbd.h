#ifndef BACKEND_ATKBD_H_
#define BACKEND_ATKBD_H_

#include <sys/param.h>

#include "evdevfbsd.h"

#define AT_ACK 0xfa
#define AT_NAK 0xfe
#define AT_BAT 0xaa
#define AT_ES0 0xe0
#define AT_ES1 0xe1
#define AT_REL 0xf0
#define AT_HANJA 0xf1
#define AT_HANGEUL 0xf2
#define AT_ERR 0xff

// those could be both a release event and a "normal" key press or control code
static const uint16_t ambivalent_keys[] = {
    AT_BAT, AT_ERR, AT_ACK, AT_NAK, AT_HANJA, AT_HANGEUL};

struct atkbd_state {
	int escape;
	bool release_extraction_state[nitems(ambivalent_keys)];
};

struct atkbd_backend {
	int atkbd_fd;
	int vkbd_fd;
	struct atkbd_state atkbd;
};

int atkbd_backend_init(struct event_device *ed);
void *atkbd_fill_function(struct event_device *ed);
void atkbd_backend_cleanup(struct event_device *ed);

#endif
