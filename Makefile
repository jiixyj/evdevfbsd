PROG=	evdevfbsd
MAN=

LDADD=		-lcuse
CFLAGS+=	-Wall -Wextra -Iinclude -pthread

.include <bsd.prog.mk>
