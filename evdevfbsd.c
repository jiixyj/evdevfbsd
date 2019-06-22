#include "evdevfbsd.h"

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/filio.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <termios.h>
#include <unistd.h>

#include "util.h"
#include "zero_initializer.h"

#include "backend-atkbd.h"
#include "backend-psm.h"
#include "backend-sysmouse.h"
#include "backend-uhid.h"

#include "input-detection.h"

static atomic_int is_exiting = 0;

static struct event_client_state *
event_client_new()
{
	struct event_client_state *ret =
	    calloc(sizeof(struct event_client_state), 1);
	if (!ret)
		return NULL;

	if (sem_init(&ret->event_buffer_sem, 0, 0) == -1) {
		free(ret);
		return NULL;
	}

	ret->clock = CLOCK_REALTIME;
	ret->revoked = false;

	return ret;
}

static int
evdevfbsd_open(struct cuse_dev *cdev, int fflags __unused)
{
	// fprintf(stderr, "device opened");
	struct event_device *ed = cuse_dev_get_priv0(cdev);

	int ret = CUSE_ERR_BUSY;

	pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
	for (unsigned i = 0; i < nitems(ed->event_clients); ++i) {
		if (!ed->event_clients[i]) {
			ed->event_clients[i] = event_client_new();
			if (ed->event_clients[i]) {
				cuse_dev_set_per_file_handle(
				    cdev, ed->event_clients[i]);
				ret = CUSE_ERR_NONE;
			}
			break;
		}
	}
	pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
	return ret;
}

static int
evdevfbsd_close(struct cuse_dev *cdev, int fflags __unused)
{
	struct event_device *ed = cuse_dev_get_priv0(cdev);

	pthread_mutex_lock(&ed->event_buffer_mutex); // XXX

	struct event_client_state *client_state =
	    cuse_dev_get_per_file_handle(cdev);

	for (int i = 0; i < client_state->event_buffer_end; ++i)
		sem_wait(&client_state->event_buffer_sem);

	sem_destroy(&client_state->event_buffer_sem);
	client_state->event_buffer_end = 0;

	for (unsigned i = 0; i < nitems(ed->event_clients); ++i) {
		if (ed->event_clients[i] == client_state) {
			ed->event_clients[i] = NULL;
			if (ed->exclusive_client == client_state) {
				ed->exclusive_client = NULL;
			}
			break;
		}
	}

	free(client_state);

	pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
	return CUSE_ERR_NONE;
}

static int
evdevfbsd_read(struct cuse_dev *cdev, int fflags, void *user_ptr, int len)
{
	if (len < 0)
		return CUSE_ERR_INVALID;

	if (len < (int)sizeof(struct input_event))
		return CUSE_ERR_INVALID;

	struct event_client_state *client_state =
	    cuse_dev_get_per_file_handle(cdev);

#ifdef CUSE_ERR_NO_DEVICE
	if (client_state->revoked) {
		return CUSE_ERR_NO_DEVICE;
	}
#endif

	int requested_events = len / (int)sizeof(struct input_event);
	int nr_events = 0;

	struct event_device *ed = cuse_dev_get_priv0(cdev);
	int ret;

retry:
	if (!(fflags & CUSE_FFLAG_NONBLOCK)) {
		ret = sem_wait(&client_state->event_buffer_sem);
		if (ret == -1 && (cuse_got_peer_signal() == 0 || is_exiting))
			return CUSE_ERR_SIGNAL;
	}

	pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
	if (client_state->event_buffer_end == 0) {
		if (fflags & CUSE_FFLAG_NONBLOCK)
			ret = CUSE_ERR_WOULDBLOCK;
		else {
			sem_post(&client_state->event_buffer_sem);
			pthread_mutex_unlock(&ed->event_buffer_mutex);
			goto retry;
		}
	} else {
		nr_events =
		    MIN(requested_events, client_state->event_buffer_end);
		for (int i = 0; i < nr_events; ++i) {
			client_state->event_buffer[i].time =
			    client_state->clock == CLOCK_REALTIME ?
			    client_state->event_times[i].real_time :
			    client_state->event_times[i].monotonic_time;
		}
		ret = cuse_copy_out(client_state->event_buffer, user_ptr,
		    nr_events * (int)sizeof(struct input_event));
		if (ret == 0) {
			memmove(client_state->event_buffer,
			    &client_state->event_buffer[nr_events],
			    (size_t)(
			        client_state->event_buffer_end - nr_events) *
			        sizeof(struct input_event));
			memmove(client_state->event_times,
			    &client_state->event_times[nr_events],
			    (size_t)(
			        client_state->event_buffer_end - nr_events) *
			        sizeof(struct event_times));

			client_state->event_buffer_end =
			    client_state->event_buffer_end - nr_events;
			for (int i = 0; i < nr_events - 1; ++i)
				sem_wait(&client_state->event_buffer_sem);
		}
	}
	pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX

	return ret == 0 ? nr_events * (int)sizeof(struct input_event) : ret;
}

static int
evdevfbsd_write(
    struct cuse_dev *cdev, int fflags __unused, const void *user_ptr, int len)
{
	if (len < 0)
		return CUSE_ERR_INVALID;

	if (len < (int)sizeof(struct input_event))
		return CUSE_ERR_INVALID;

	struct event_client_state *client_state =
	    cuse_dev_get_per_file_handle(cdev);

#ifdef CUSE_ERR_NO_DEVICE
	if (client_state->revoked) {
		return CUSE_ERR_NO_DEVICE;
	}
#endif

	int requested_events = len / (int)sizeof(struct input_event);

	struct event_device *ed = cuse_dev_get_priv0(cdev);

	struct event_times tv;
	get_clock_values(&tv);

	// always succeed
	int retval = requested_events * (int)sizeof(struct input_event);

	// ignore events from other devices if grabbed
	if (ed->exclusive_client && ed->exclusive_client != client_state) {
		return retval;
	}

	pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
	event_client_need_free_bufsize(ed, requested_events);

	struct input_event const *user_events = user_ptr;

	bool did_put_event = false;

	for (int i = 0; i < requested_events; ++i) {
		bool do_put_event = false;

		struct input_event ev;
		if (cuse_copy_in(&user_events[i], &ev,
			(int)sizeof(struct input_event)) != 0) {
			fprintf(stderr, "error copying in\n");
			continue;
		}

		if (get_bit(ed->event_bits, ev.type, EV_MAX)) {
			if (ev.type == EV_LED) {
				if (get_bit(ed->led_bits, ev.code, LED_MAX)) {
					do_put_event = true;
				}
			}
		}

		if (ev.type == EV_SYN) {
			if (ev.code <= SYN_MAX) {
				do_put_event = true;
			}
		}

		if (do_put_event) {
			put_event(ed, &tv, ev.type, ev.code, ev.value);
			if (ed->handle_injected_event) {
				ed->handle_injected_event(ed, &ev);
			}
			did_put_event = true;
		} else {
			fprintf(stderr, "did not put event %d %d %d\n",
			    (int)ev.type, (int)ev.code, (int)ev.value);
		}
	}

	if (did_put_event) {
		cuse_poll_wakeup();
	}

	pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX

	return retval;
}

static int
evdevfbsd_poll(struct cuse_dev *cdev, int fflags __unused, int events)
{
	if (!(events & CUSE_POLL_READ))
		return CUSE_POLL_NONE;

	struct event_client_state *client_state =
	    cuse_dev_get_per_file_handle(cdev);

	if (client_state->revoked) {
		return CUSE_POLL_ERROR;
	}

	int ret = CUSE_POLL_NONE;
	struct event_device *ed = cuse_dev_get_priv0(cdev);

	pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
	if (client_state->event_buffer_end > 0)
		ret = CUSE_POLL_READ;
	pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX

	return ret;
}

static int
evdevfbsd_ioctl(struct cuse_dev *cdev, int fflags __unused, unsigned long cmd,
    void *peer_data)
{
	uint64_t bits[256] = ZERO_INITIALIZER;
	struct event_device *ed = cuse_dev_get_priv0(cdev);
	struct event_client_state *client_state =
	    cuse_dev_get_per_file_handle(cdev);

#ifdef CUSE_ERR_NO_DEVICE
	if (client_state->revoked) {
		return CUSE_ERR_NO_DEVICE;
	}
#endif

	switch (cmd) {
	case TIOCFLUSH:
	case TIOCGETA:
		// ignore these for now
		return CUSE_ERR_INVALID;
	case FIONBIO:
		return 0;
	}

	void *iowint_data = NULL;
	if (cmd == EVIOCGRAB || cmd == EVIOCREVOKE) {
		int arg;
		int ret;
		if ((ret = cuse_copy_in(peer_data, &arg, sizeof(arg))) != 0) {
			return ret;
		}
		iowint_data = (void *)(intptr_t)arg;
		fprintf(stderr, "iowint_data: %p\n", iowint_data);
	}

	switch (cmd) {
	case EVIOCGID: {
		// printf("got ioctl EVIOCGID\n");
		return cuse_copy_out(&ed->iid, peer_data, sizeof(ed->iid));
	}
	case EVIOCGVERSION: {
		// printf("got ioctl EVIOCGVERSION\n");
		int version = EV_VERSION;
		return cuse_copy_out(&version, peer_data, sizeof(version));
	}
	case EVIOCGRAB: {
		// fprintf(stderr, "GRAB: %lx %p\n", cmd, iowint_data);
		if (iowint_data) {
			if (ed->exclusive_client != NULL) {
				return CUSE_ERR_BUSY;
			} else {
				ed->exclusive_client = client_state;
			}
		} else {
			if (ed->exclusive_client != client_state) {
				return CUSE_ERR_INVALID;
			} else {
				ed->exclusive_client = NULL;
			}
		}

		return 0;
	}
	case EVIOCREVOKE: {
#ifdef CUSE_ERR_NO_DEVICE
		// fprintf(stderr, "REVOKE: %lx %p\n", cmd, iowint_data);
		if (iowint_data) {
			return CUSE_ERR_INVALID;
		} else {
			client_state->revoked = true;
		}

		return 0;
#else
		return CUSE_ERR_INVALID;
#endif
	}
	case EVIOCGREP: {
		return cuse_copy_out(&ed->rep, peer_data, sizeof(ed->rep));
	}
	case EVIOCSCLOCKID: {
		int new_clock, ret;
		if ((ret = cuse_copy_in(
			 peer_data, &new_clock, sizeof(new_clock))))
			return ret;
		if (new_clock == CLOCK_REALTIME ||
		    new_clock == CLOCK_MONOTONIC) {
			client_state->clock = new_clock;
			return 0;
		} else {
			return CUSE_ERR_INVALID;
		}
	}
	}

	unsigned long base_cmd = IOCBASECMD(cmd);
	unsigned long len = IOCPARM_LEN(cmd);

	switch (base_cmd) {
	case EVIOCGBIT(0, 0): {
		// printf("got ioctl EVIOCGBIT %lu\n", len);
		return cuse_copy_out(ed->event_bits, peer_data,
		    (int)MIN(sizeof(ed->event_bits), len));
	}
	case EVIOCGNAME(0): {
		// printf("got ioctl EVIOCGNAME %lu\n", len);
		if (ed->device_name) {
			return cuse_copy_out(ed->device_name, peer_data,
			    (int)MIN(strlen(ed->device_name), len));
		} else {
			return 0;
		}
	}
	case EVIOCGPHYS(0):
		// fprintf(stderr, "got ioctl EVIOCGPHYS %lu %s\n", len,
		//     ed->phys_name);
		return cuse_copy_out(ed->phys_name, peer_data,
		    (int)MIN(strlen(ed->phys_name), len));
	case EVIOCGUNIQ(0):
		// fprintf(stderr, "got ioctl EVIOCGUNIQ %lu\n", len);
		// ENOENT would be better, but this is not supported by cuse
		return 0;
	case EVIOCGBIT(EV_REL, 0): {
		// printf("got ioctl EVIOCGBIT %lu\n", len);
		return cuse_copy_out(ed->rel_bits, peer_data,
		    (int)MIN(sizeof(ed->rel_bits), len));
	}
	case EVIOCGBIT(EV_KEY, 0): {
		// printf("got ioctl EVIOCGBIT %lu\n", len);
		return cuse_copy_out(ed->key_bits, peer_data,
		    (int)MIN(sizeof(ed->key_bits), len));
	}
	case EVIOCGBIT(EV_ABS, 0): {
		// printf("got ioctl EVIOCGBIT %lu\n", len);
		return cuse_copy_out(ed->abs_bits, peer_data,
		    (int)MIN(sizeof(ed->abs_bits), len));
	}
	case EVIOCGBIT(EV_MSC, 0): {
		// printf("got ioctl EVIOCGBIT %lu\n", len);
		return cuse_copy_out(ed->msc_bits, peer_data,
		    (int)MIN(sizeof(ed->msc_bits), len));
	}
	case EVIOCGBIT(EV_LED, 0):
		// printf("got ioctl EVIOCGBIT LED %lu\n", len);
		return cuse_copy_out(ed->led_bits, peer_data,
		    (int)MIN(sizeof(ed->led_bits), len));
	case EVIOCGBIT(EV_SW, 0):
		// printf("got unimplemented ioctl EVIOCGBIT EV_SW %lu\n",
		// len);
		return cuse_copy_out(
		    bits, peer_data, (int)MIN(sizeof(bits), len));
	case EVIOCGBIT(EV_FF, 0):
		// printf("got unimplemented ioctl EVIOCGBIT EV_FF %lu\n",
		// len);
		return cuse_copy_out(
		    bits, peer_data, (int)MIN(sizeof(bits), len));
	case EVIOCGBIT(EV_SND, 0):
		// printf("got unimplemented ioctl EVIOCGBIT EV_SND %lu\n",
		// len);
		return cuse_copy_out(
		    bits, peer_data, (int)MIN(sizeof(bits), len));
	case EVIOCGKEY(0):
		// TODO: implement this
		// fprintf(stderr, "got unimplemented EVIOCGKEY %lu\n", len);
		return 0;
	case EVIOCGLED(0):
		// TODO: implement this
		// fprintf(stderr, "got unimplemented EVIOCGLED %lu\n", len);
		return 0;
	case EVIOCGSW(0):
		// fprintf(stderr, "got unimplemented EVIOCGSW %lu\n", len);
		return 0;
	case EVIOCGPROP(0):
		// printf("got ioctl EVIOCGPROP %lu\n", len);
		return cuse_copy_out(ed->prop_bits, peer_data,
		    (int)MIN(sizeof(ed->prop_bits), len));
	case EVIOCGMTSLOTS(0): {
		// printf("got ioctl EVIOCGMTSLOTS %lu\n", len);
		int ret;
		uint32_t code;
		if (len < sizeof(uint32_t))
			return CUSE_ERR_INVALID;
		if ((ret = cuse_copy_in(peer_data, &code, sizeof(code))))
			return ret;
		if (code < ABS_MT_FIRST || code > ABS_MT_LAST)
			return CUSE_ERR_INVALID;

		struct input_mt_request {
			uint32_t code;
			int32_t values[MAX_SLOTS];
		};

		struct input_mt_request mtr = ZERO_INITIALIZER;
		mtr.code = code;
		for (int i = 0; i < MAX_SLOTS; ++i) {
			mtr.values[i] = ed->mt_state[i][code - ABS_MT_FIRST];
		}
		return cuse_copy_out(&mtr, peer_data,
		    (int)MIN(sizeof(struct input_mt_request), len));
	}
	}

	if ((cmd & IOC_DIRMASK) == IOC_OUT) {
		if ((cmd & ~(unsigned long)ABS_MAX) == EVIOCGABS(0)) {
			// printf("got ioctl EVIOCGABS for axis %ld\n",
			//     cmd & ABS_MAX);
			return cuse_copy_out(&ed->abs_info[cmd & ABS_MAX],
			    peer_data,
			    (int)MIN(sizeof(struct input_absinfo), len));
		}
	}

	fprintf(stderr, "got unknown ioctl %lu %lu %lu\n", cmd, base_cmd, len);
	unsigned long direction = cmd & IOC_DIRMASK;
	if (direction == IOC_VOID) {
		fprintf(stderr, "direction: void\n");
	} else if (direction == IOC_OUT) {
		fprintf(stderr, "direction: out\n");
	} else if (direction == IOC_IN) {
		fprintf(stderr, "direction: in\n");
	}
	fprintf(stderr, "length: %lu\n", IOCPARM_LEN(cmd));
	fprintf(stderr, "group: %c\n", (unsigned char)IOCGROUP(cmd));
	fprintf(stderr, "num: %lu 0x%02lx\n", cmd & 0xff, cmd & 0xff);
	return CUSE_ERR_INVALID;
}

static struct cuse_methods evdevfbsd_methods = {.cm_open = evdevfbsd_open,
    .cm_close = evdevfbsd_close,
    .cm_read = evdevfbsd_read,
    .cm_write = evdevfbsd_write,
    .cm_poll = evdevfbsd_poll,
    .cm_ioctl = evdevfbsd_ioctl};

static void
evdevfbsd_hup_catcher(int dummy __unused)
{
}

static void *
wait_and_proc(void *notused __unused)
{
	int ret;

	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_handler = &evdevfbsd_hup_catcher;
	sigaction(SIGHUP, &act, NULL); // XXX

	while (!is_exiting) {
		ret = cuse_wait_and_process();
		if (ret < 0)
			break;
	}
	return NULL;
}

static int
event_device_init(struct event_device *ed)
{
	memset(ed, 0, sizeof(*ed));
	ed->fd = -1;
	ed->cuse_device = NULL;
	ed->current_mt_slot = -1;
	for (int i = 0; i < MAX_SLOTS; ++i) {
		ed->mt_state[i][ABS_MT_TRACKING_ID - ABS_MT_FIRST] = -1;
	}
	return pthread_mutex_init(&ed->event_buffer_mutex, NULL);
}

static int
event_device_open(struct event_device *eds, size_t neds, char const *path)
{
	int num_devices, i;

	if (neds < 2) {
		return -1;
	}

	if (!strcmp(path, "/dev/bpsm0") || !strcmp(path, "/dev/psm0")) {
		num_devices = psm_backend_init(eds);
	} else if (!strcmp(path, "/dev/sysmouse") ||
	    !strncmp(path, "/dev/ums", 8)) {
		num_devices = sysmouse_backend_init(eds, path);
	} else if (!strcmp(path, "/dev/atkbd0")) {
		num_devices = atkbd_backend_init(eds);
	} else if (!strncmp(path, "/dev/uhid", 9)) {
		num_devices = uhid_backend_init(eds, path);
	} else {
		return -1;
	}

	for (i = 0; i < num_devices; ++i) {
		snprintf(eds[i].phys_name, sizeof(eds[i].phys_name), "%s",
		    path + 5);
	}

	return num_devices;
}

static void
event_device_cleanup(struct event_device *ed)
{
	if (ed->backend_type == ATKBD_BACKEND) {
		atkbd_backend_cleanup(ed);
	}
}

static int
create_cuse_device(struct event_device *ed, int permissions)
{
	for (int i = 0; i < 32; ++i) {
		if (snprintf(ed->cuse_dev_name, sizeof(ed->cuse_dev_name),
			"input/event%d", i) == -1) {
			errx(1, "snprintf failed");
		}

		ed->cuse_device = cuse_dev_create(&evdevfbsd_methods, ed, NULL,
		    0, 0, permissions, ed->cuse_dev_name);
		if (ed->cuse_device) {
			break;
		}
	}

	if (!ed->cuse_device) {
		ed->cuse_dev_name[0] = '\0';
		return -1;
	}

	return 0;
}

static void *
fill_thread_starter(void *edp)
{
	struct event_device *ed = (struct event_device *)edp;
	return ed->fill_function(ed);
}

static void usage(char const *program_name) __attribute__((noreturn));
static void
usage(char const *program_name)
{
	fprintf(stderr, "usage: %s [-c] <device>\n", program_name);
	exit(1);
}

static int cfd = -1;

static int
open_consolectl_fd()
{
	if (cfd != -1) {
		return 0;
	}
	cfd = open("/dev/consolectl", O_RDWR, 0);
	if (cfd != -1) {
		system("for tty in /dev/ttyv*;"
		       "do vidcontrol < $tty -m on; done");
		return 0;
	} else {
		perror("open");
		return -1;
	}
}

int
get_cfd()
{
	return cfd;
}

static int
handle_new_input(struct event_device *ed)
{
	int ret = ed->read_packet(ed);
	if (ret == -1) {
		return -1;
	} else if (ret == 0) {
		struct event_times tv;
		get_clock_values(&tv);
		ed->packet_time = tv;
		pthread_mutex_lock(&ed->event_buffer_mutex); // XXX
		ret = ed->parse_packet(ed);
		ed->packet_pos = 0;
		if (ret == 0) {
			cuse_poll_wakeup();
		}
		pthread_mutex_unlock(&ed->event_buffer_mutex); // XXX
		if (ret == -1) {
			return -1;
		}
	} else if (ret == 1) {
		// fprintf(stderr, "packet incomplete, pos at %d\n",
		//     (int)ed->packet_pos);
	}

	return 0;
}

int
main(int argc, char **argv)
{
	char *program_name = argv[0];
	int ch;

	while ((ch = getopt(argc, argv, "c")) != -1) {
		switch (ch) {
		case 'c':
			if (open_consolectl_fd() == -1) {
				return EXIT_FAILURE;
			}
			break;
		default:
			usage(argv[0]);
		}
	}
	argc -= optind;
	argv += optind;

	int ret;

	if (argc != 1) {
		usage(program_name);
	}

	if ((ret = cuse_init()) < 0)
		errx(1, "cuse_init returned %d", ret);

	struct event_device eds[8];
	for (unsigned i = 0; i < nitems(eds); ++i) {
		event_device_init(&eds[i]); // XXX
	}
	size_t nr_eds = 0;

	int new_eds = event_device_open(eds, nitems(eds), argv[0]);
	if (new_eds <= 0) {
		errx(1, "could not open event device(s)");
	}

	nr_eds = (size_t)new_eds;

	// Spawn a child process that restores the keyboard on exit.
	// This cannot be done in the parent process, as it is in capabilities
	// mode by then.
	int cleanup_pipe[2];
	if (eds[0].backend_type == ATKBD_BACKEND) {
		if (pipe(cleanup_pipe) == -1) {
			errx(1, "could not create cleanup pipe");
		}
		signal(SIGCHLD, SIG_IGN);
		pid_t cleanup_process = fork();
		if (cleanup_process == 0) {
			signal(SIGINT, SIG_IGN);
			signal(SIGTERM, SIG_IGN);
			char c;
			read(cleanup_pipe[0], &c, 1);
			for (unsigned i = 0; i < nr_eds; ++i) {
				event_device_cleanup(&eds[nr_eds - 1 - i]);
			}
			write(cleanup_pipe[0], &c, 1);
			exit(0);
		} else if (cleanup_process == -1) {
			perror("fork");
			exit(1);
		}
	}

	for (unsigned i = 0; i < nr_eds; ++i) {
		struct input_id_input input;
		struct input_id_output output;

		memcpy(&input.bitmask_ev, &eds[i].event_bits,
		    sizeof(input.bitmask_ev));
		memcpy(&input.bitmask_abs, &eds[i].abs_bits,
		    sizeof(input.bitmask_abs));
		memcpy(&input.bitmask_key, &eds[i].key_bits,
		    sizeof(input.bitmask_key));
		memcpy(&input.bitmask_rel, &eds[i].rel_bits,
		    sizeof(input.bitmask_rel));
		memcpy(&input.bitmask_props, &eds[i].prop_bits,
		    sizeof(input.bitmask_props));
		memcpy(&input.xabsinfo, &eds[i].abs_info[ABS_X],
		    sizeof(input.xabsinfo));
		memcpy(&input.yabsinfo, &eds[i].abs_info[ABS_Y],
		    sizeof(input.yabsinfo));

		input_id(&input, &output);

		if (create_cuse_device(
		        &eds[i], output.ids[ID_INPUT_JOYSTICK] ? 0666 : 0600))
			errx(1, "failed to create event device");

		fprintf(stderr, "%s: ", eds[i].cuse_dev_name);
		print_output(stderr, &output);
	}

	for (unsigned i = 0; i < nr_eds; ++i) {
		if (eds[i].fill_function) {
			pthread_create(&eds[i].fill_thread, NULL,
			    fill_thread_starter,
			    &eds[i]); // XXX
		}
	}

	pthread_t worker[4];

	for (unsigned i = 0; i < nitems(worker); ++i) {
		pthread_create(&worker[i], NULL, wait_and_proc, NULL); // XXX
	}

	if (cap_enter() == -1) {
		fprintf(stderr, "error entering capabilities mode\n");
		goto exit;
	}

	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);

	int kq = kqueue();
	if (kq == -1) {
		perror("kqueue");
		goto exit;
	}

	// main event loop
	struct kevent evs[2];
	EV_SET(&evs[0], SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);
	EV_SET(&evs[1], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);
	if (kevent(kq, evs, 2, NULL, 0, NULL) == -1) {
		perror("kevent");
		goto exit;
	}

	for (unsigned i = 0; i < nr_eds; ++i) {
		if (eds[i].fill_function == NULL) {
			if (eds[i].fd == -1) {
				continue;
			}
			EV_SET(&evs[0], eds[i].fd, EVFILT_READ, EV_ADD, 0, 0,
			    &eds[i]);
			if (kevent(kq, evs, 1, NULL, 0, NULL) == -1) {
				int err = errno;
				if (err == ENODEV) {
					fprintf(stderr,
					    "device does not support kqueue, "
					    "falling back to poll\n");
					eds[i].do_poll = true;
				} else {
					perror("kevent");
					goto exit;
				}
			}
		}
	}

	struct pollfd pfds[nitems(eds) + 1] = {ZERO_INITIALIZER};
	struct event_device *poll_to_ed[nitems(pfds)] = ZERO_INITIALIZER;
	for (unsigned i = 0; i < nitems(pfds); ++i) {
		pfds[i].fd = -1;
	}
	pfds[0].fd = kq;
	pfds[0].events = POLLIN;
	unsigned npfds = 1;
	for (unsigned i = 0; i < nr_eds; ++i) {
		if (eds[i].do_poll) {
			pfds[npfds].fd = eds[i].fd;
			pfds[npfds].events = POLLIN;
			poll_to_ed[npfds] = &eds[i];
			++npfds;
		}
	}

	// we are ready!
	char ready_line[1024] = ZERO_INITIALIZER;
	for (unsigned i = 0; i < nr_eds; ++i) {
		snprintf(ready_line, sizeof(ready_line),
		    ready_line[0] == '\0' ? "%s%s" : "%s:%s", ready_line,
		    eds[i].cuse_dev_name);
	}
	snprintf(ready_line, sizeof(ready_line), "%s\n", ready_line);
	if (strlen(ready_line) >= sizeof(ready_line) - 1 ||
	    write(1, ready_line, strlen(ready_line)) !=
		(ssize_t)strlen(ready_line) ||
	    close(1) != 0) {
		fprintf(stderr, "error printing ready line\n");
		goto exit;
	}

	while (poll(pfds, npfds, INFTIM) > 0) {
		if (pfds[0].revents & POLLIN) {
			struct timespec ts = ZERO_INITIALIZER;
			for (;;) {
				int nev = kevent(kq, NULL, 0, evs, 1, &ts);
				if (nev == 0) {
					break;
				} else if (nev != 1) {
					goto exit;
				}

				if (evs[0].filter == EVFILT_READ) {
					struct event_device *ed = evs[0].udata;
					// fprintf(stderr, "handle k\n");
					if (handle_new_input(ed) == -1) {
						goto exit;
					}
				} else {
					goto exit;
				}
			}
		}
		for (unsigned i = 1; i < npfds; ++i) {
			if (pfds[i].fd != -1 && (pfds[i].revents & POLLIN)) {
				struct event_device *ed = &eds[i - 1];
				// fprintf(stderr, "handle p\n");
				if (handle_new_input(ed) == -1) {
					goto exit;
				}
			}
		}
	}

exit:
	is_exiting = 1;

	for (unsigned i = 0; i < nitems(worker); ++i) {
		pthread_kill(worker[i], SIGHUP);
		pthread_join(worker[i], NULL); // XXX
	}

	fprintf(stderr, "workers joined...\n");

	for (unsigned i = 0; i < nr_eds; ++i) {
		cuse_dev_destroy(eds[nr_eds - 1 - i].cuse_device);
	}

	for (unsigned i = 0; i < nr_eds; ++i) {
		event_device_cleanup(&eds[nr_eds - 1 - i]);
	}

	if (eds[0].backend_type == ATKBD_BACKEND) {
		char c = '\0';
		write(cleanup_pipe[1], &c, 1);
		read(cleanup_pipe[1], &c, 1);
	}

	fprintf(stderr, "closing...\n");
}
