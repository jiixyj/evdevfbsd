#ifndef _LINUX_INPUT_H
#define _LINUX_INPUT_H

#include <linux/autogen/input.h>

/* FreeBSD specific changes follow */

#undef EVIOCGMTSLOTS
#define EVIOCGMTSLOTS(len) _IOC(IOC_INOUT, 'E', 0x0a, len)

#endif
