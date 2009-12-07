LIB=		imp
SHLIB_MAJOR=	1
NOLINT=		true

IMPDIR=/root/src/impersonate/libimp
CFLAGS+=-I${IMPDIR}

SRCS=	findmod.c impersonate.c
INCS=	impersonate.h
INCSDIR=${INCLUDEDIR}/imp

.include <bsd.lib.mk>

.PATH:	${IMPDIR}
