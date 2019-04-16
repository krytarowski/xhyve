#	$NetBSD$

STAND=	${.CURDIR}/../stand

.PATH: ${STAND}/userboot/userboot
.PATH: ${STAND}/common

CPPFLAGS+=	-I${STAND}/libsa
CPPFLAGS+=	-D__dead2=__dead

LIB=	userboot-freebsd

SRCS=	#

SRCS=           autoload.c
SRCS+=          bcache.c
SRCS+=          biossmap.c
SRCS+=          bootinfo.c
SRCS+=          bootinfo32.c
SRCS+=          bootinfo64.c
SRCS+=          conf.c
SRCS+=          console.c
SRCS+=          copy.c
SRCS+=          devicename.c
SRCS+=          elf32_freebsd.c
SRCS+=          elf64_freebsd.c
SRCS+=          host.c
SRCS+=          main.c
SRCS+=          userboot_cons.c
SRCS+=          userboot_disk.c
SRCS+=          vers.c

LDFLAGS+=       -nostdlib -Wl,-Bsymbolic

LDFLAGS+=	/usr/lib/sysident.o # NetBSD ELF notes

NOMAN=	yes

VERSION_FILE?=  ${STAND}/userboot/userboot/version
NEWVERSWHAT?=        "bootstrap loader" x86
REPRO_FLAG=	-r

vers.c: ${STAND}/common/newvers.sh ${VERSION_FILE}
	sh ${STAND}/common/newvers.sh ${REPRO_FLAG} ${VERSION_FILE} ${NEWVERSWHAT}

.include <bsd.lib.mk>
