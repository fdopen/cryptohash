/* Copyright (c) 2014  Andreas Hauptmann
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "config.h"
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <fcntl.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif

#if HAVE_ERRNO_H
#  include <errno.h>
#endif
#ifndef errno
extern int errno;
#endif

#include <caml/misc.h>
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/fail.h>
#include <caml/threads.h>
#include <caml/bigarray.h>
#include <caml/unixsupport.h>

#include "@include@"

#if !HAVE_SSIZE_T && defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

#ifdef TEMP_FAILURE_RETRY
#define OPEN(a,b) TEMP_FAILURE_RETRY(open((a),(b)))
#define READ(a,b,c) TEMP_FAILURE_RETRY(read((a),(b),(c)))
#else
static inline int
wrap_open(const char *pathname, int flags)
{
   int ret;
   do {
      ret = open(pathname,flags);
   } while (ret ==-1 && errno == EINTR);
   return ret;
}

static inline ssize_t
wrap_read(int fd,
          void *buf,
          size_t count)
{
   ssize_t ret;
   do {
      ret = read(fd,buf,count);
   } while (ret ==-1 && errno == EINTR);
   return ret;
}
#define OPEN wrap_open
#define READ wrap_read
#endif

/*
  no wrapper for close, because the semantic differs to
  much from platform to platform.

  Linux and other platforms release the file descriptor, even
  if EINTR is returned. Other platforms don't release it.
  I don't know a workaround, that is portable.

  So we just follow the current linux convention and pray that everythings
  works fine in all other cases.
*/
#define CLOSE close

#define CAML_LIBRARY_NAME "Cryptohash"
