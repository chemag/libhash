#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
dnl AC_INIT(FULL-PACKAGE-NAME, VERSION, BUG-REPORT-ADDRESS)
AC_INIT(src/hash.c)
AM_INIT_AUTOMAKE(libhash,  esyscmd([tr -d '\n' < VERSION]))
dnl AC_CONFIG_SRCDIR([hash.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC

# need libtool
AC_PROG_LIBTOOL

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])
AC_CHECK_HEADERS(memory.h netinet/in.h socket.h getopt.h)
AC_CHECK_HEADERS(net/ethernet.h netinet/ether.h netinet/if_ether.h sys/ethernet.h,,,
		[#include <sys/types.h>
		#include <netinet/in.h>])
# see if we have sin_len
AC_CHECK_MEMBER(struct sockaddr_in.sin_len,
	[AC_DEFINE(SIN_LEN,,[have sin_len field in sockaddr_in])],,
	[
#if HAVE_SYS_TYPES_H
#	include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#	include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif
])



# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STAT
AC_FUNC_STRTOD
AC_CHECK_FUNCS([gettimeofday inet_ntoa memchr memset strcasecmp strerror strncasecmp])
AC_CHECK_FUNCS([floor rint select strchr])

AC_PROG_GCC_TRADITIONAL
AC_PROG_MAKE_SET
AC_PROG_RANLIB

#AC_CONFIG_FILES([Makefile])
AC_OUTPUT([Makefile
		src/Makefile
		])


