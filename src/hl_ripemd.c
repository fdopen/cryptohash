#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <caml/misc.h>
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/fail.h>
#include <caml/threads.h>
#include <caml/bigarray.h>

#include "sph_ripemd.c"


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
  works fine in all other cases :(
*/
#define CLOSE close

#define CAML_LIBRARY_NAME "Hashlib"



#define H_CTX(x)                                \
   ((sph_ripemd_context*) &Field((x),0))

#define CAML_ALLOC_SPH()                                          \
   ((sizeof(sph_ripemd_context)) <= Max_young_wosize ?          \
    caml_alloc_small(sizeof(sph_ripemd_context),Abstract_tag) : \
    caml_alloc_shr(sizeof(sph_ripemd_context),Abstract_tag))

static int
ripemd_file(char *filename,
              void * digest)
{
#define BLKSIZE 8192
   unsigned char buf[BLKSIZE];
   int fd; ssize_t n;
   sph_ripemd_context ctx;
#if defined(O_CLOEXEC) && !defined(_WIN32)
   fd = OPEN(filename, O_RDONLY | O_CLOEXEC);
   if (fd == -1 && errno == EINVAL)
#endif
   {
      fd = OPEN(filename, O_RDONLY);
#if !defined(_WIN32) && defined(FD_CLOEXEC) && defined(F_SETFD) && defined(F_GETFD)
      if (fd != -1){
         int x = fcntl(fd, F_GETFD);
         if ( x != -1 ){
            fcntl(fd,
                  F_SETFD,
                  x | FD_CLOEXEC);
         }
      }
#endif
   }
   if (fd == -1){
     return 1;
   }
   sph_ripemd_init(&ctx);
   while ((n = READ(fd, buf, BLKSIZE)) > 0){
      sph_ripemd(&ctx, buf, n);
   }
   if (n == 0)
     sph_ripemd_close(&ctx,digest);
   fd=CLOSE(fd);
   return ( n < 0 || fd == -1);
#undef BLKSIZE
}

CAMLprim value
caml_hashlib_ripemd_init(value unit)
{
   value ret;
   ret=CAML_ALLOC_SPH();
   sph_ripemd_init(H_CTX(ret));
   return ret;
}

CAMLprim value
caml_hashlib_ripemd_update(value octx,
                             value data,
                             value offset,
                             value len)
{
   sph_ripemd(H_CTX(octx),
                String_val(data) + Long_val(offset),
                Long_val(len));
   return Val_unit;
}

CAMLprim value
caml_hashlib_ripemd_finalize(value octx)
{
   CAMLparam1(octx);
   CAMLlocal1(ret);
   ret = caml_alloc_string(16);
   sph_ripemd_close(H_CTX(octx),String_val(ret));
   CAMLreturn(ret);
}

CAMLprim value
caml_hashlib_ripemd_copy(value octx)
{
   CAMLparam1(octx);
   CAMLlocal1(ret);
   sph_ripemd_context * ctx_n;
   sph_ripemd_context * ctx_o;
   ret=CAML_ALLOC_SPH();
   ctx_o=H_CTX(octx);
   ctx_n=H_CTX(ret);
   *ctx_n=*ctx_o;
   CAMLreturn(ret);
}

CAMLprim value
caml_hashlib_ripemd_to_hex(value s)
{
   CAMLparam1(s);
   CAMLlocal1(ret);
   mlsize_t len = caml_string_length(s);
   static const char hex[]="0123456789abcdef";
   unsigned char * digest;
   char * buf;
   mlsize_t i;
   ret=caml_alloc_string(len*2);
   digest=(unsigned char *)String_val(s);
   buf=String_val(ret);
   for (i = 0; i < len; i++) {
      buf[i+i] = hex[digest[i] >> 4];
      buf[i+i+1] = hex[digest[i] & 0x0f];
   }
   CAMLreturn(ret);
}

#define DIGIT(x)                                                \
   ((x) >= '0' && (x) <= '9' ?  (x) - '0' :                     \
    (x) >= 'a' && (x) <= 'f' ? (x) - 'a' + 10 :                 \
    (x) >= 'A' && (x) <= 'F' ? (x) - 'A' + 10 :                 \
    (caml_invalid_argument(CAML_LIBRARY_NAME ".from_hex"),0))

CAMLprim value
caml_hashlib_ripemd_from_hex(value s)
{
   CAMLparam1(s);
   CAMLlocal1(ret);
   int i;
   unsigned char * digest;
   char * buf;
   if ( caml_string_length(s) != (16 *2 )){
      caml_invalid_argument(CAML_LIBRARY_NAME ".from_hex");
   }
   ret = caml_alloc_string(16);
   buf = String_val(s);
   digest=(unsigned char*)String_val(ret);
   for ( i = 0 ; i < 16 ; ++i ){
      mlsize_t j = i * 2 ;
      digest[i]=(DIGIT(buf[j]) << 4) + DIGIT(buf[j+1]);
   }
   CAMLreturn(ret);
}

CAMLprim value
caml_hashlib_ripemd_file(value name)
{
   CAMLparam1(name);
   CAMLlocal1(ret);
   mlsize_t len = caml_string_length(name);
   char *name_dup;
   char digest[16];
   int x;

   if ( len == 0 || (String_val(name))[0] == '\0' ){
      ret=caml_copy_string("No such file or directory");
      caml_raise_sys_error(ret);
   }
   name_dup = caml_stat_alloc(len+1);
   memcpy(name_dup,String_val(name),len);
   name_dup[len]='\0';

   caml_release_runtime_system();
   x=ripemd_file(name_dup, digest);
   caml_acquire_runtime_system();
   caml_stat_free(name_dup);

   if (x) {
#define ERROR_MESSAGE ": I/O error"
      ret=caml_alloc_string(len + sizeof(ERROR_MESSAGE));
      name_dup=String_val(ret);
      memcpy(name_dup,String_val(name),len);
      memcpy(name_dup + len,ERROR_MESSAGE,sizeof(ERROR_MESSAGE));
      caml_raise_sys_error(ret);
#undef ERROR_MESSAGE
   }

   ret = caml_alloc_string(16);
   memcpy(String_val(ret),digest,16);

   CAMLreturn(ret);
}

CAMLprim value
caml_hashlib_ripemd_update_bigarray(value ctx, value buf)
{
   CAMLparam2(ctx, buf);
   unsigned char *data = Data_bigarray_val(buf);
   size_t len = Bigarray_val(buf)->dim[0];

   caml_release_runtime_system();
   sph_ripemd(H_CTX(ctx), data, len);
   caml_acquire_runtime_system();

   CAMLreturn(Val_unit);
}

#undef CAML_ALLOC_SPH
#undef H_CTX
