AC_INIT([cryptohash], [0.1],[andreas@ml.ignorelist.com],[cryptohash])

AC_PROG_CC
AC_CONFIG_HEADERS([config.h])
AC_USE_SYSTEM_EXTENSIONS
AC_CHECK_HEADERS(errno.h)
AC_CHECK_TYPE([ssize_t],
  [AC_DEFINE([HAVE_SSIZE_T], [1], [Define if ssize_t exists])],
  [AC_DEFINE([HAVE_SSIZE_T], [0], [Define if ssize_t does not exist])])
AC_C_BIGENDIAN
AC_OUTPUT
