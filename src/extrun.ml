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

let () = Random.self_init ()
let ( |> ) x f = f x

let () =
  if Sys.os_type <> "Win32" then
    Sys.set_signal Sys.sigpipe Sys.Signal_ignore


let extract rex s =
  try
    let _ = Str.search_forward rex s 0 in
    Some(Str.matched_group 1 s)
  with
  | Not_found -> None

let openssl_rex = Str.regexp "\\=[ ]*\\([0-9a-fA-F]+\\)$"
let jacksum_rex = Str.regexp "^\\([0-9a-fA-F]+\\) "

let openssl_extract = extract openssl_rex
let jacksum_extract = extract jacksum_rex

let gpg_extract s =
  let slen = String.length s in
  let buf = Buffer.create slen in
  for i = 0 to pred slen do
    match s.[i] with
    | ' ' | '\t' | '\r' | '\n' -> ()
    | c -> Buffer.add_char buf c
  done;
  Some(Buffer.contents buf)

let md2 x =
  Cryptohash_md2.string x |> Cryptohash_md2.to_hex

let md4 x =
  Cryptohash_md4.string x |> Cryptohash_md4.to_hex

let md5 x =
  Cryptohash_md5.string x |> Cryptohash_md5.to_hex

let sha1 x =
  Cryptohash_sha1.string x |> Cryptohash_sha1.to_hex

let sha224 x =
  Cryptohash_sha224.string x |> Cryptohash_sha224.to_hex

let sha256 x =
  Cryptohash_sha256.string x |> Cryptohash_sha256.to_hex

let sha384 x =
  Cryptohash_sha384.string x |> Cryptohash_sha384.to_hex

let sha512 x =
  Cryptohash_sha512.string x |> Cryptohash_sha512.to_hex

let ripemd128 x =
  Cryptohash_ripemd128.string x |> Cryptohash_ripemd128.to_hex

let ripemd160 x =
  Cryptohash_ripemd160.string x |> Cryptohash_ripemd160.to_hex

let whirlpool x =
  Cryptohash_whirlpool.string x |> Cryptohash_whirlpool.to_hex

let tiger x =
  Cryptohash_tiger.string x |> Cryptohash_tiger.to_hex

let tiger2 x =
  Cryptohash_tiger2.string x |> Cryptohash_tiger2.to_hex

let sha3_224 x =
  Cryptohash_sha3_224.string x |> Cryptohash_sha3_224.to_hex

let sha3_256 x =
  Cryptohash_sha3_256.string x |> Cryptohash_sha3_256.to_hex

let sha3_384 x =
  Cryptohash_sha3_384.string x |> Cryptohash_sha3_384.to_hex

let sha3_512 x =
  Cryptohash_sha3_512.string x |> Cryptohash_sha3_512.to_hex

let random_string () =
  let n = Random.int 1_000_000 in
  let b = Bytes.create n in
  for i = 0 to pred n do
    Random.int 256 |>
    Char.chr |>
    Bytes.set b i
  done;
  Bytes.unsafe_to_string b


let win = match Sys.os_type with
| "Win32" -> true
| _ -> false

let paths = lazy (
  let rex =
    Str.regexp(
      Str.quote ( match win with
        | true -> ";"
        | false -> ":"))
  in
  try
    Str.split rex (Sys.getenv "PATH")
  with
  | Not_found -> [ "/bin" ; "/usr/bin" ]
)

let executable_exists s =
  let open Unix in
  try
    let () = access s [R_OK; X_OK; F_OK] in
    (stat s).st_kind = S_REG
  with
  | Unix_error _ -> false

let which prog =
  let module F = struct exception Found of string end in
  let f path =
    (match win with
     | true ->
       let s = Filename.concat path (prog ^ ".exe" ) in
       if executable_exists s then
         raise (F.Found s);
     | false -> () );
    let s = Filename.concat path prog in
    if executable_exists s then
      raise (F.Found s);
  in
  try
    Lazy.force paths |> List.iter f ;
    None
  with
  | F.Found x -> Some x


module type Tool =
sig
  val program: string
  val use_stdin: bool
  val extract: string -> string option
  val def_list: (string list * (string -> string)) list
end


let temp_file = ref None

let get_temp_file () =
  match !temp_file with
  | Some x -> x
  | None ->
    let s = Filename.temp_file "cryptohash_extrun" ".dat" in
    temp_file := Some(s);
    s

let write_to_tempfile s =
  let fln = get_temp_file () in
  let ch =
    open_out_gen
      [ Open_trunc ; Open_creat ; Open_binary; Open_wronly ]
      0o600
      fln
  in
  let ch_closed = ref false in
  try
    output_string ch s;
    ch_closed := true;
    close_out ch;
    fln
  with
  | x when !ch_closed = false ->
    close_out_noerr ch;
    raise x


let () =
  at_exit (fun () ->
      match !temp_file with
      | None -> ()
      | Some x ->
        try
          Sys.remove x
        with
        | _ -> ()
    )


let funcs = ref []
let skipped = ref 0
let not_skipped = ref 0
let errors = ref false

let false' = "/bin/false"
module MakeTest (T:Tool) =
struct
  let program = match which T.program with
  | None -> false'
  | Some x -> x

  let exec_error params =
    let sparam = String.concat " " params in
    Printf.eprintf
      "error while executing %s %s\n%!"
      program
      sparam

  let parse_error params =
    let sparam = String.concat " " params in
    Printf.eprintf
      "can't parse the output of %s %s\n%!"
      program
      sparam

  let compare_failure params =
    let sparam = String.concat " " params in
    Printf.eprintf
      "%s compare failed for %s\n%!"
      program
      sparam

  let rec run ~bytes ~n i = function
  | [] -> false,n,bytes
  | l  ->
    if i <= 0 then
      if List.length l = List.length T.def_list then
        true,n,bytes
      else
        false,n,bytes
    else
      let s = random_string () in
      let buf = Buffer.create 512 in
      let f (n,bytes,accu) ((params,h) as cur) =
        Buffer.clear buf;
        let stdout = `Buffer buf in
        let file, stdin = match T.use_stdin with
        | true -> "-", `String s
        | false -> write_to_tempfile s, `Null
        in
        let params =
          List.map (function | "@file@" -> file | x -> x ) params
        in
        if (try Run.run ~stdin ~stdout program params with _ -> -1) <> 0 then
          (
            exec_error params;
            n,bytes,accu
          )
        else
          match Buffer.contents buf |> T.extract with
          | None ->
            parse_error params;
            n,bytes,accu
          | Some dgst ->
            let dgst' = h s in
            if String.lowercase dgst = String.lowercase dgst' then
              (succ n),(bytes + String.length s),cur::accu
            else (
              compare_failure params;
              n,bytes,accu
            )
      in
      let n,bytes,l' = List.fold_left f (n,bytes,[]) l in
      run ~n ~bytes (pred i) l'

  let run i =
    if program == false' then (
      Printf.printf "%s not found, test skipped\n%!" T.program;
      incr skipped;
      true,0,0
    )
    else (
      let (ok,n,bytes) as whole = run ~n:0 ~bytes:0 i T.def_list in
      assert( not ok || n = i * (List.length T.def_list) );
      incr not_skipped;
      Printf.printf
        "%s: %d compared hashes (%d bytes)\n%!"
        T.program
        n
        bytes;
      (match ok with
      | true -> ()
      | false ->
        errors:=true;
        prerr_endline "there were errors");
      whole
    )

  let () = funcs := run :: !funcs
end

module Openssl = struct
  let program = "openssl"
  let use_stdin = true
  let extract = openssl_extract
  let def_list =
    [
      ["md4"],md4;
      ["md5"],md5;
      ["sha1"],sha1;
      ["sha224"],sha224;
      ["sha256"],sha256;
      ["sha384"],sha384;
      ["sha512"],sha512;
      ["rmd160"],ripemd160;
      ["whirlpool"],whirlpool ]
end

module Jacksum = struct
  let program = "jacksum"
  let use_stdin = false
  let extract = jacksum_extract
  let def_list = [
    ["-a";"md2";"-x";"@file@"],md2 ;
    ["-a";"md4";"-x";"@file@"],md4 ;
    ["-a";"md5";"-x";"@file@"],md5 ;
    ["-a";"rmd128";"-x";"@file@"],ripemd128 ;
    ["-a";"rmd160";"-x";"@file@"],ripemd160 ;
    ["-a";"sha1";"-x";"@file@"],sha1 ;
    ["-a";"sha224";"-x";"@file@"],sha224 ;
    ["-a";"sha256";"-x";"@file@"],sha256 ;
    ["-a";"sha384";"-x";"@file@"],sha384 ;
    ["-a";"sha512";"-x";"@file@"],sha512 ;
    ["-a";"tiger";"-x";"@file@"],tiger;
    ["-a";"tiger2";"-x";"@file@"],tiger2 ;
    ["-a";"whirlpool";"-x";"@file@"],whirlpool
  ]
end

module Gpg = struct
  let program = "gpg"
  let use_stdin = true
  let extract = gpg_extract
  let def_list = [
    ["--no-tty";"--batch";"--print-md";"md5"],md5;
    ["--no-tty";"--batch";"--print-md";"ripemd160"],ripemd160;
    ["--no-tty";"--batch";"--print-md";"sha1"],sha1;
    ["--no-tty";"--batch";"--print-md";"sha224"],sha224;
    ["--no-tty";"--batch";"--print-md";"sha256"],sha256;
    ["--no-tty";"--batch";"--print-md";"sha384"],sha384;
    ["--no-tty";"--batch";"--print-md";"sha512"],sha512;
  ]
end

module Md4sum = struct
  let program = "md4sum"
  let use_stdin = true
  let extract = jacksum_extract
  let def_list = [[], md4]
end

module Md5sum = struct
  let program = "md5sum"
  let use_stdin = true
  let extract = jacksum_extract
  let def_list = [[], md5]
end

module Sha1sum = struct
  let program = "sha1sum"
  let use_stdin = true
  let extract = jacksum_extract
  let def_list = [[], sha1]
end

module Sha224sum = struct
  let program = "sha224sum"
  let use_stdin = true
  let extract = jacksum_extract
  let def_list = [[], sha224]
end

module Sha256sum = struct
  let program = "sha256sum"
  let use_stdin = true
  let extract = jacksum_extract
  let def_list = [[], sha256]
end

module Sha384sum = struct
  let program = "sha384sum"
  let use_stdin = true
  let extract = jacksum_extract
  let def_list = [[], sha384]
end

module Sha512sum = struct
  let program = "sha512sum"
  let use_stdin = true
  let extract = jacksum_extract
  let def_list = [[], sha512]
end


module Rhash = struct
  let program = "rhash"
  let use_stdin = true
  let extract = jacksum_extract
  let def_list = [
    ["--md4";"@file@"],md4;
    ["--md5";"@file@"],md5;
    ["--sha1";"@file@"],sha1;
    ["--sha224";"@file@"],sha224;
    ["--sha256";"@file@"],sha256;
    ["--sha384";"@file@"],sha384;
    ["--sha512";"@file@"],sha512;
    ["--ripemd160";"@file@"],ripemd160;
    ["--sha3-224";"@file@"],sha3_224;
    ["--sha3-256";"@file@"],sha3_256;
    ["--sha3-384";"@file@"],sha3_384;
    ["--sha3-512";"@file@"],sha3_512;
  ]
end

module Openssl_test = MakeTest(Openssl)
module Jacksum_test = MakeTest(Jacksum)
module Gpg_test = MakeTest(Gpg)
module Md4sum_test = MakeTest(Md4sum)
module Md5sum_test = MakeTest(Md5sum)
module Sha1sum_test = MakeTest(Sha1sum)
module Sha224sum_test = MakeTest(Sha224sum)
module Sha256sum_test = MakeTest(Sha256sum)
module Sha384sum_test = MakeTest(Sha384sum)
module Sha512sum_test = MakeTest(Sha512sum)
module Rhash_test = MakeTest(Rhash)

let () =
  List.iter ( fun f ->
      f 10 |> ignore ) !funcs ;
  if !errors || !not_skipped = 0 then
    exit 1
  else
    exit 0
