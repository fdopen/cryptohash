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


#define H_CTX(x)                                \
   ((sph_@sph_name@_context*) &Field((x),0))

#define CAML_ALLOC_SPH()                                            \
   ((sizeof(sph_@sph_name@_context)) <= Max_young_wosize ?          \
    caml_alloc_small(sizeof(sph_@sph_name@_context),Abstract_tag) : \
    caml_alloc_shr(sizeof(sph_@sph_name@_context),Abstract_tag))

/* UNIX_BUFFER_SIZE should be defined in unixsupport.h */

#ifndef UNIX_BUFFER_SIZE
#define UNIX_BUFFER_SIZE 16384
#endif
#if UNIX_BUFFER_SIZE < 16384
#undef UNIX_BUFFER_SIZE
#define UNIX_BUFFER_SIZE 16384
#endif

static int
@digest@_file(const char *filename,
              void * digest)
{
   unsigned char buf[UNIX_BUFFER_SIZE];
   int fd; ssize_t n;
   sph_@sph_name@_context ctx;
#if defined(O_CLOEXEC) && !defined(_WIN32)
   fd = OPEN(filename, O_RDONLY | O_CLOEXEC);
   if (fd == -1 && errno == EINVAL)
#endif
   {
      fd = OPEN(filename, O_RDONLY);
#if !defined(_WIN32) && defined(FD_CLOEXEC) && defined(F_SETFD) && defined(F_GETFD)
      if (fd != -1){
         /* errors are ignored, because they are not fatal and this feature
            isn't  documented anyway */
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
   sph_@sph_name@_init(&ctx);
   while ((n = READ(fd, buf, UNIX_BUFFER_SIZE)) > 0){
      sph_@sph_name@(&ctx, buf, n);
   }
   if (n == 0){
      sph_@sph_name@_close(&ctx,digest);
   }
   fd=CLOSE(fd);
   return ( n < 0 || fd == -1);
}

CAMLprim value
cryptohash_ml_@digest@_init(value unit)
{
   value ret;
   ret=CAML_ALLOC_SPH();
   sph_@sph_name@_init(H_CTX(ret));
   return ret;
}

CAMLprim value
cryptohash_ml_@digest@_update_substring(value octx,
                                        value data,
                                        value offset,
                                        value len)
{
   sph_@sph_name@(H_CTX(octx),
                  String_val(data) + Long_val(offset),
                  Long_val(len));
   return Val_unit;
}

CAMLprim value
cryptohash_ml_@digest@_finalize(value octx)
{
   CAMLparam1(octx);
   CAMLlocal1(ret);
   ret=caml_alloc_string(@size@);
   sph_@sph_name@_close(H_CTX(octx),String_val(ret));
   CAMLreturn(ret);
}

CAMLprim value
cryptohash_ml_@digest@_copy(value octx)
{
   CAMLparam1(octx);
   CAMLlocal1(ret);
   sph_@sph_name@_context * ctx_n;
   sph_@sph_name@_context * ctx_o;
   ret=CAML_ALLOC_SPH();
   ctx_o=H_CTX(octx);
   ctx_n=H_CTX(ret);
   *ctx_n=*ctx_o;
   CAMLreturn(ret);
}

CAMLprim value
cryptohash_ml_@digest@_to_hex(value s)
{
   CAMLparam1(s);
   CAMLlocal1(ret);
   const mlsize_t len = caml_string_length(s);
   const char hex[]="0123456789abcdef";
   const unsigned char * digest;
   char * buf;
   mlsize_t i;
   if ( len != @size@ ){
     caml_invalid_argument(CAML_LIBRARY_NAME ".to_hex");
   }
   ret=caml_alloc_string( @size@ *2 );
   digest=(unsigned char *)String_val(s);
   buf=String_val(ret);
   for (i = 0; i < len; i++) {
      buf[i+i] = hex[digest[i] >> 4];
      buf[i+i+1] = hex[digest[i] & 0x0f];
   }
   CAMLreturn(ret);
}

#define DIGIT(x)                                              \
   ((x) >= '0' && (x) <= '9' ?  (x) - '0' :                   \
    (x) >= 'a' && (x) <= 'f' ? (x) - 'a' + 10 :               \
    (x) >= 'A' && (x) <= 'F' ? (x) - 'A' + 10 :               \
    (caml_invalid_argument(CAML_LIBRARY_NAME ".from_hex"),0))

CAMLprim value
cryptohash_ml_@digest@_from_hex(value s)
{
   CAMLparam1(s);
   CAMLlocal1(ret);
   int i;
   unsigned char * digest;
   const char * buf;
   if ( caml_string_length(s) != (@size@ *2 )){
      caml_invalid_argument(CAML_LIBRARY_NAME ".from_hex");
   }
   ret = caml_alloc_string(@size@);
   buf = String_val(s);
   digest=(unsigned char*)String_val(ret);
   for ( i = 0 ; i < @size@ ; ++i ){
      const mlsize_t j = i * 2 ;
      digest[i]=(DIGIT(buf[j]) << 4) + DIGIT(buf[j+1]);
   }
   CAMLreturn(ret);
}
#undef DIGIT

CAMLprim value
cryptohash_ml_@digest@_file_fast(value name)
{
   CAMLparam1(name);
   value ret;
   const mlsize_t len = caml_string_length(name);
   char *name_dup;
   char digest[@size@];
   int x;

   if ( len == 0 || len != strlen(String_val(name)) ){
      ret=caml_copy_string("No such file or directory");
      caml_raise_sys_error(ret);
   }
   name_dup = caml_stat_alloc(len+1);
   memcpy(name_dup,String_val(name),len);
   name_dup[len]='\0';

   caml_enter_blocking_section();
   x=@digest@_file(name_dup, digest);
   caml_leave_blocking_section();
   caml_stat_free(name_dup);

   if (x) {
#define ERROR_MESSAGE ": I/O error"
      ret=caml_alloc_string(len + sizeof(ERROR_MESSAGE) - 1 );
      name_dup=String_val(ret);
      memcpy(name_dup,String_val(name),len);
      memcpy(name_dup + len,ERROR_MESSAGE,sizeof(ERROR_MESSAGE));
      caml_raise_sys_error(ret);
#undef ERROR_MESSAGE
   }

   ret = caml_alloc_string(@size@);
   memcpy(String_val(ret),digest,@size@);

   CAMLreturn(ret);
}


CAMLprim value
cryptohash_ml_@digest@_update_subbuffer(value octx,
                                        value data,
                                        value offset,
                                        value len)
{
   const size_t slen = Long_val(len);
   const void * buf = (char *)Data_bigarray_val(data) + Long_val(offset);
   sph_@sph_name@_context * ctx = H_CTX(octx);
   /* TODO: find appropriate value */
   if ( slen < UNIX_BUFFER_SIZE ){
     sph_@sph_name@(ctx,buf,slen);
   }
   else {
     sph_@sph_name@_context sctx;
     sctx = *ctx;
     Begin_roots2(octx,data);
     caml_enter_blocking_section();
     sph_@sph_name@(&sctx,buf,slen);
     caml_leave_blocking_section();
     memcpy(H_CTX(octx),&sctx,sizeof(sctx));
     End_roots();
   }
   return Val_unit;
}

#undef CAML_ALLOC_SPH
#undef H_CTX
