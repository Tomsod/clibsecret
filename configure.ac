#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([clibsecret], [0.1], [tomsod-m@ya.ru])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([clibsecret.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99

# Checks for libraries.

PKG_CHECK_MODULES(LIBSECRET, [libsecret-unstable], [
AC_SUBST(LIBSECRET_CFLAGS)
AC_SUBST(LIBSECRET_LIBS)
])

PKG_CHECK_MODULES(GLIB, [glib-2.0], [
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)
])

PKG_CHECK_MODULES(GIO, [gio-2.0], [
AC_SUBST(GIO_CFLAGS)
AC_SUBST(GIO_LIBS)
])

# Checks for header files.

AC_CHECK_HEADERS([stdio.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_OUTPUT
