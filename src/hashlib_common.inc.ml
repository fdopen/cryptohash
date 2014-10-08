(* Copyright (c) 2014  Andreas Hauptmann
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
 *)

type ctx
type buf = (char,
            Bigarray.int8_unsigned_elt,
            Bigarray.c_layout) Bigarray.Array1.t

type t = string

external init:
  unit -> ctx =
  "cryptohash_ml_@digest@_init"

external unsafe_update_substring:
  ctx -> string -> int -> int -> unit =
  "cryptohash_ml_@digest@_update_substring" "noalloc"

external unsafe_update_subbytes:
  ctx -> string -> int -> int -> unit =
  "cryptohash_ml_@digest@_update_substring" "noalloc"

external unsafe_update_subbuffer:
  ctx -> buf -> int -> int -> unit =
  "cryptohash_ml_@digest@_update_subbuffer"

external finalize:
  ctx -> t =
  "cryptohash_ml_@digest@_finalize"

external copy :
  ctx -> ctx =
  "cryptohash_ml_@digest@_copy"

external to_hex:
  t -> string =
  "cryptohash_ml_@digest@_to_hex"

external from_hex:
  string -> t =
  "cryptohash_ml_@digest@_from_hex"

external file_fast:
  string -> t =
  "cryptohash_ml_@digest@_file_fast"

let to_bin = String.copy

let from_bin (s:string) : t =
  let len = String.length s in
  if len <> @size@ then
    invalid_arg "Cryptohash.from_bin";
  String.copy s

let update_substring ctx s pos len =
  if pos < 0 || len < 0 || pos > String.length s - len then
    invalid_arg "Cryptohash.update_substring"
  else if len = 0 then
    ()
  else
    unsafe_update_substring ctx s pos len

let update_subbytes ctx s pos len =
  update_substring ctx (Bytes.unsafe_to_string s) pos len

let update_string ctx s =
  unsafe_update_substring ctx s 0 (String.length s)

let update_bytes ctx s =
  update_string ctx (Bytes.unsafe_to_string s)

let string s =
  let ctx = init () in
  unsafe_update_substring ctx s 0 (String.length s);
  finalize ctx

let bytes b =
  string (Bytes.unsafe_to_string b)

let substring s pos len =
  if pos < 0 || len < 0 || pos > String.length s - len then
    invalid_arg "Cryptohash.substring";
  let ctx = init () in
  unsafe_update_substring ctx s pos len;
  finalize ctx

let subbytes s pos len =
  substring (Bytes.unsafe_to_string s) pos len

let subbuffer b pos len =
  if pos < 0 || len < 0 || pos > Bigarray.Array1.dim b - len then
    invalid_arg "Cryptohash.subbuffer";
  let ctx = init () in
  unsafe_update_subbuffer ctx b pos len;
  finalize ctx

let update_subbuffer ctx b pos len =
  if pos < 0 || len < 0 || pos > Bigarray.Array1.dim b - len then
    invalid_arg "Cryptohash.update_subbuffer"
  else if len = 0 then
    ()
  else
    unsafe_update_subbuffer ctx b pos len

let update_buffer ctx b =
  unsafe_update_subbuffer ctx b 0 (Bigarray.Array1.dim b)

let buffer b =
  let ctx = init () in
  unsafe_update_subbuffer ctx b 0 (Bigarray.Array1.dim b);
  finalize ctx

let channel chan len =
  let ctx = init () in
  if len <> 0 then (
    let blocksize = 16_384 in
    let buf = Bytes.create blocksize in
    if len < 0 then (
      let read = ref 1 in
      while !read > 0 do
        read := Pervasives.input chan buf 0 blocksize;
        if !read > 0 then
          unsafe_update_substring ctx buf 0 !read
      done
    )
    else (
      let toread = ref len in
      while !toread > 0 do
        let n = min !toread blocksize in
        let r = Pervasives.input chan buf 0 n in
        if r = 0 then
          raise End_of_file;
        toread := !toread - r;
        unsafe_update_substring ctx buf 0 r
      done
    )
  );
  finalize ctx

let file name =
  let channel_closed = ref false in
  let chan = open_in_bin name in
  try
    let digest = channel chan (-1) in
    channel_closed := true;
    close_in chan;
    digest
  with
  | x when !channel_closed = false ->
    close_in_noerr chan;
    raise x

let input chan =
  let b = Bytes.create @size@ in
  really_input chan b 0 @size@;
  Bytes.unsafe_to_string b

let output chan digest =
  output_string chan digest
