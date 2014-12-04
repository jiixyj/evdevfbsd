PROG=	evdevfbsd
MAN=

LDADD=		-lcuse
CFLAGS+=	-Wall -Wextra -Weverything -Wno-padded -isystem include -pthread

.include <bsd.prog.mk>
