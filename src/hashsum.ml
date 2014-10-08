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

let md2 x =
  Cryptohash_md2.file_fast x |> Cryptohash_md2.to_hex

let md4 x =
  Cryptohash_md4.file_fast x |> Cryptohash_md4.to_hex

let md5 x =
  Cryptohash_md5.file_fast x |> Cryptohash_md5.to_hex

let sha1 x =
  Cryptohash_sha1.file_fast x |> Cryptohash_sha1.to_hex

let sha256 x =
  Cryptohash_sha256.file_fast x |> Cryptohash_sha256.to_hex

let sha224 x =
  Cryptohash_sha224.file_fast x |> Cryptohash_sha224.to_hex

let sha384 x =
  Cryptohash_sha384.file_fast x |> Cryptohash_sha384.to_hex

let sha512 x =
  Cryptohash_sha512.file_fast x |> Cryptohash_sha512.to_hex

let sha3_224 x =
  Cryptohash_sha3_224.file_fast x |> Cryptohash_sha3_224.to_hex

let sha3_256 x =
  Cryptohash_sha3_256.file_fast x |> Cryptohash_sha3_256.to_hex

let sha3_384 x =
  Cryptohash_sha3_384.file_fast x |> Cryptohash_sha3_384.to_hex

let sha3_512 x =
  Cryptohash_sha3_512.file_fast x |> Cryptohash_sha3_512.to_hex

let whirlpool x =
  Cryptohash_whirlpool.file_fast x |> Cryptohash_whirlpool.to_hex

let ripemd128 x =
  Cryptohash_ripemd128.file_fast x |> Cryptohash_ripemd128.to_hex

let ripemd160 x =
  Cryptohash_ripemd160.file_fast x |> Cryptohash_ripemd160.to_hex

let tiger x =
  Cryptohash_tiger.file_fast x |> Cryptohash_tiger.to_hex
let tiger2 x =
  Cryptohash_tiger2.file_fast x |> Cryptohash_tiger2.to_hex

let hash = ref md5
let files = ref []
let speclist =
  [("-md2", Arg.Unit ( fun () -> hash:= md2) , "compute md2 sum");
   ("-md4", Arg.Unit ( fun () -> hash:= md4) , "compute md4 sum");
   ("-md5", Arg.Unit ( fun () -> hash:= md5) , "compute md5 sum");
   ("-sha1", Arg.Unit ( fun () -> hash:= sha1) , "compute sha1 sum");
   ("-sha224", Arg.Unit ( fun () -> hash:= sha224) , "compute sum");
   ("-sha256", Arg.Unit ( fun () -> hash:=sha256 ) , "compute sha256 sum");
   ("-sha384", Arg.Unit ( fun () -> hash:=sha384 ) , "compute sha384 sum");
   ("-sha512", Arg.Unit ( fun () -> hash:=sha512 ) , "compute sha512 sum");
   ("-sha3-224", Arg.Unit ( fun () -> hash:=sha3_224 ) , "compute sha3-224 sum");
   ("-sha3-256", Arg.Unit ( fun () -> hash:=sha3_256 ) , "compute sha3-256 sum");
   ("-sha3-384", Arg.Unit ( fun () -> hash:=sha3_384 ) , "compute sha3-384 sum");
   ("-sha3-512", Arg.Unit ( fun () -> hash:=sha3_512 ) , "compute sha3-512 sum");
   ("-whirlpool", Arg.Unit ( fun () -> hash:=whirlpool) , "compute whirlpool sum");
   ("-ripemd128", Arg.Unit ( fun () -> hash:=ripemd128) , "compute ripemd128 sum");
   ("-ripemd160", Arg.Unit ( fun () -> hash:=ripemd160) , "compute ripemd160 sum");
   ("-tiger", Arg.Unit ( fun () -> hash:=tiger) , "compute tiger sum");
   ("-tiger2", Arg.Unit ( fun () -> hash:=tiger2) , "compute tiger2 sum");
  ]

let usage_msg = "Choose a hash function and specify your files"
let anon_func s =  files:= s :: !files

let () =
  let () = Arg.parse speclist anon_func usage_msg in
  let files = List.rev !files in
  if files = [] then (
    prerr_endline "no files given :(";
    exit(1);
  );
  List.iter (fun s ->
      let x = (!hash) s in
      Printf.printf
        "%s %s\n%!"
        x s ) files
