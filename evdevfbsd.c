#include <sys/param.h>

#include <stdio.h>
#include <string.h>

#include <cuse.h>
#include <err.h>

#include "linux/input.h"

int evdevfbsd_open(struct cuse_dev *cdev, int fflags) {
  puts("device opened");
  return CUSE_ERR_NONE;
}

int evdevfbsd_close(struct cuse_dev *cdev, int fflags) {
  puts("device closed");
  return CUSE_ERR_NONE;
}

int evdevfbsd_read(struct cuse_dev *cdev, int fflags, void *user_ptr,
                   int len) {
  puts("device read");

  char const msg[] = "hello world";
  size_t msg_len = strlen(msg);

  len = MIN(len, (int)msg_len);
  int ret = cuse_copy_out(msg, user_ptr, len);
  return ret == 0 ? len : ret;
}

struct cuse_methods evdevfbsd_methods = {.cm_open = evdevfbsd_open,
                                         .cm_close = evdevfbsd_close,
                                         .cm_read = evdevfbsd_read};

int main() {
  int ret;

  if ((ret = cuse_init()) < 0)
    errx(1, "cuse_init returned %d", ret);


  struct cuse_dev *evdevfbsddev = cuse_dev_create(
      &evdevfbsd_methods, NULL, NULL, 0, 0, 0444, "input/event0");
  if (!evdevfbsddev)
    errx(1, "cuse_dev_create failed");


  for (;;) {
    ret = cuse_wait_and_process();
    if (ret < 0)
      warnx("cuse_wait_and_process returned %d\n", ret);
  }
}
