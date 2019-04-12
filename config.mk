###############################################################################
# Config                                                                      #
#                                                                             #
# [XHYVE_CONFIG_ASSERT] VMM asserts (disable for release builds?)             #
# [XHYVE_CONFIG_TRACE]  VMM event tracer                                      #
# [XHYVE_CONFIG_STATS]  VMM event profiler                                    #
###############################################################################

DEFINES := \
  -DXHYVE_CONFIG_ASSERT

###############################################################################
# Toolchain                                                                   #
###############################################################################

CC := clang
AS := clang
LD := clang
STRIP := strip
DSYM := dsymutil

ENV := \
  LANG=en_US.US-ASCII

###############################################################################
# CFLAGS                                                                      #
###############################################################################

CFLAGS_OPT := \
  -Os \
  -fstrict-aliasing

CFLAGS_WARN := \
  -Weverything \
  -Wno-unknown-warning-option \
  -Wno-reserved-id-macro

CFLAGS_DIAG := \
  -fmessage-length=152 \
  -fdiagnostics-show-note-include-stack \
  -fmacro-backtrace-limit=0 \
  -fcolor-diagnostics

CFLAGS_DBG := \
  -g

CFLAGS := \
  -pthread \
  -x c \
  -std=c11 \
  -fno-common \
  -fvisibility=hidden \
  -D_KERNTYPES \
  -I/usr/src/lib/libnvmm \
  -I/usr/src/sys/ \
  $(DEFINES) \
  $(CFLAGS_OPT) \
  $(CFLAGS_WARN) \
  $(CFLAGS_DIAG) \
  $(CFLAGS_DBG)

###############################################################################
# LDFLAGS                                                                     #
###############################################################################

LDFLAGS := \
  -lz \
  -lpthread \
  -lprop \
  $(LDFLAGS_DBG)
