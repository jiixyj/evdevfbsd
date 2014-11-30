PROG=	evdevfbsd
MAN=

LDADD=		-lcuse
CFLAGS+=	-Iinclude

.include <bsd.prog.mk>
