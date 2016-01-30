PROG=	evdevfbsd
SRCS=	evdevfbsd.c \
	backend-psm.c \
	backend-sysmouse.c \
	backend-atkbd.c \
	backend-uhid.c \
	util.c
MAN=

LDADD=		-lcuse -lusbhid
CFLAGS+=	-Wall -Wextra -Weverything -Wno-padded -isystem include -pthread

.include <bsd.prog.mk>
