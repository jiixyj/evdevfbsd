PROG=	evdevfbsd
SRCS=	evdevfbsd.c \
	backend-psm.c \
	backend-sysmouse.c \
	backend-atkbd.c \
	backend-uhid.c \
	util.c
MAN=

LDADD=		-lcuse -lusbhid -lusb
CFLAGS+=	-Wall -Wextra -Weverything -Wno-padded -pthread

.include <bsd.prog.mk>
