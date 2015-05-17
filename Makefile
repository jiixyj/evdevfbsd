PROG=	evdevfbsd
SRCS=	evdevfbsd.c backend-psm.c backend-sysmouse.c backend-atkbd.c util.c
MAN=

LDADD=		-lcuse
CFLAGS+=	-Wall -Wextra -Weverything -Wno-padded -isystem include -pthread

.include <bsd.prog.mk>
