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

module type DigestType =
sig
  type ctx
  type buf =
    (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t
  type t
  val init: unit -> ctx
  val update_substring: ctx -> string -> int -> int -> unit
  val update_subbuffer: ctx -> buf -> int -> int -> unit
  val update_string: ctx -> string -> unit
  val update_buffer: ctx -> buf -> unit
  val buffer: buf -> t
  val finalize: ctx -> t
  val copy : ctx -> ctx
  val string : string -> t
  val substring : string -> int -> int -> t
  val subbuffer: buf -> int -> int -> t
  val channel : in_channel -> int -> t
  val file : string -> t
  val file_fast : string -> t
  val output : out_channel -> t -> unit
  val input : in_channel -> t
  val to_bin : t -> Bytes.t
  val to_hex : t -> string
  val from_hex: string -> t
  val from_bin: Bytes.t -> t
end

module type DigestInfo =
sig
  val name: string
  val v_null: string  (* hash of vec1 *)
  val v2: string  (* hash of vec2 *)
  val v3: string
  val v4: string
  val b_null: Bytes.t (* binary representation of v_null *)
  val b2: Bytes.t
  val b3: Bytes.t
  val b4: Bytes.t
  val million: string (* hash of a million 'a' *)
  val delirious: string (* hash of string_delirious 16_777_216 times *)
end

type 'a catch_exn =
  | Ok of 'a
  | Exn of exn

let () = Random.self_init ()

(* See http://www.di-mgt.com.au/sha_testvectors.html *)
let vec1 = ""
let vec2 = "abc"
let vec3 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
let vec4 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno" ^
           "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"

let string_delirious =
  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"

let ba_of_string string =
  let s_len = String.length string in
  let ba = Bigarray.(Array1.create char c_layout s_len) in
  for i = 0 to pred s_len do
    ba.{i} <- string.[i]
  done;
  ba

let digit c =
  match c with
  | '0'..'9' -> Char.code c - Char.code '0'
  | 'A'..'F' -> Char.code c - Char.code 'A' + 10
  | 'a'..'f' -> Char.code c - Char.code 'a' + 10
  | _ -> raise (Invalid_argument "from_hexstring")

let from_hexstring s =
  let slen = String.length s in
  if slen mod 2 <> 0 then
    failwith "from_hexstring: invalid string";
  let buf = Bytes.create (slen/2) in
  let rec iter i z acc =
    if i >= slen then
      z
    else
      let v = digit(s.[i]) in
      if v < 0 then
        iter (succ i) z acc
      else
        let v = digit(s.[i]) in
        if z then (
          Bytes.set buf (i/2) (Char.chr (acc lor v));
          iter (succ i) (not z) 0
        )
        else
          iter (succ i) (not z) (v lsl 4)
  in
  if iter 0 false 0 then
    failwith "from_hexstring: invalid string";
  Bytes.unsafe_to_string buf


let with_tempfile ~f arg =
  let fln,ch =
    Filename.open_temp_file
      ~mode:[Open_binary]
      "cryptohash_test" ".dat"
  in
  let closed = ref false in
  let close ch =
    if !closed = false then (
      closed := true;
      close_out ch;
    )
  in
  let clean error =
    let exn = ref None in
    if !closed = false then (
      if error then
        close_out_noerr ch
      else
        try
          close_out ch
        with
        | x -> exn := Some x;
    );
    (try
      Sys.remove fln
    with
    | x ->
      (match !exn with
       | None -> exn:= Some(x)
       | Some _ -> () ));
    if error = false then (
      match !exn with
      | None -> ()
      | Some x -> raise x
    );
  in
  let x =
    try Ok(f ~close ~fln ~ch arg)
    with x -> Exn(x)
  in
  match x with
  | Ok x -> clean false; x
  | Exn x -> clean true; raise x

let with_bin_file ~f ~fln arg =
  let ch = open_in_bin fln in
  match (try Ok(f ~ch arg) with x -> Exn(x)) with
  | Ok x -> close_in ch; x
  | Exn x -> close_in_noerr ch; raise x


let bquot = Bytes.of_string ""
let string_of_file ~fln =
  let len = 8192 in
  let s = Bytes.create len in
  let rec f ~ch arg =
    let n = input ch s 0 len in
    if n = 0 then
      List.rev arg |> Bytes.concat bquot
    else
      let ns = Bytes.sub s 0 n in
      f ~ch (ns::arg)
  in
  with_bin_file ~f ~fln [] |> Bytes.unsafe_to_string


let split_string_random s =
  let l = String.length s in
  if l = 0 then
    "",""
  else if l = 1 then
    if Random.int 2 = 1 then
      s,""
    else
      "",s
  else
    let i = Random.int (succ l) in
    let s1 = String.sub s 0 i
    and s2 = String.sub s i (l - i ) in
    s1,s2



exception Internal_failure

let get_tests,add_tests =
  let all_tests = ref [] in
  let f () =
    let open OUnit2 in
    "all">::: (!all_tests)
  and g l = all_tests := l :: !all_tests in
  f,g


let o_skip_long =
  OUnit2.Conf.make_bool
    "disable_long"
    true
    "Don't run long tests."

let skip_long ctx =
  let open OUnit2 in
  skip_if (o_skip_long ctx) "Long test."

module MakeTest (D: DigestType ) (I: DigestInfo ) =
struct
  open OUnit2
  let name s = String.capitalize I.name ^ "_" ^ s

  let only_once ctx =
    if I.name <> "md5" then
      skip_long ctx

  let test_string string =
    let ctx = D.init () in
    D.update_string ctx string;
    let e1 = D.finalize ctx in
    let ba = ba_of_string string in
    D.update_buffer ctx ba;
    let e2 = D.finalize ctx in
    if e1 <> e2 then
      raise Internal_failure;
    let e3 = D.string string in
    if e1 <> e3 then
      raise Internal_failure;
    D.to_hex e1

  let refstring l =
    (name "refstring")>:::
    (List.map
       (fun (s,digest) ->
          let x = Printf.sprintf "%s->%s" s digest in
          x >::
          (fun _test_ctxt ->
             assert_equal
               (String.lowercase digest)
               (test_string s)))
       l)

  let million =
    (name "million_string")>::
    (fun oc ->
       assert_equal I.million (
         let () = only_once oc in
         let ctx = D.init () in
         let a = String.make 1_000 'a' in
         for _i = 1 to 1_000 do
           D.update_string ctx a
         done;
         let e1 = D.finalize ctx in
         let ba = ba_of_string a in
         for _i = 0 to 999 do
           D.update_buffer ctx ba
         done;
         let e2 = D.finalize ctx in
         if e1 <> e2 then
           raise Internal_failure;
         D.to_hex e1 ))

  let delirious =
    (name "delirious_string")>:
    (test_case ~length:OUnitTest.Huge
       (fun ctxt ->
          let () = skip_long ctxt in
          assert_equal I.delirious (
            let ctx = D.init () in
            for _i = 1 to 16_777_216 do
              D.update_string ctx string_delirious
            done;
            D.finalize ctx |> D.to_hex )))


  let collision l =
    (name "collision_test")>:::
    (List.map
       (fun (a,b) ->
          let a' = from_hexstring a |> D.string
          and b' = from_hexstring b |> D.string in
          let x =
            Printf.sprintf
              "digest %S <> digest %S"
              a b
          in
          x >::
          (fun _ctxt -> assert_equal a' b' ))
       l)

  let init_test =
    (name "init")>::
    (fun _test_ctxt ->
       assert_bool "" (
         let a = D.string "a"
         and b = D.string "b" in
         let a_hex = D.to_hex a
         and b_hex = D.to_hex b in
         let a' = D.from_hex a_hex
         and b' = D.from_hex b_hex
         and b'' = D.from_hex (String.uppercase b_hex)
         and b''' = D.from_hex (String.lowercase b_hex)
         in
         a <> b &&
         a_hex <> b_hex &&
         a' = a &&
         b' = b &&
         b'' = b &&
         b''' = b
       ))

  let copy_test =
    (name "copy_test")>::
    (fun otx ->
       assert_bool "i" (
         let () = only_once otx in
         let s1,s2 = split_string_random vec4 in
         let ctx = D.init () in
         D.update_string ctx s1;
         let ctx2 = D.copy ctx in
         D.update_string ctx s2;
         let e1 = D.finalize ctx in
         D.update_string ctx2 s2;
         let e2 = D.finalize ctx2 in
         e1 = e2 && e2 = D.from_bin I.b4 ))

  let hex_bin_test =
    (name "hex_bin_endian")>::
    (fun otx ->
       let () = only_once otx in
       assert_bool "" (
         let open I in
         let h x =
           D.from_bin x |> D.to_hex
         and b x =
           D.from_hex x |> D.to_bin
         in
         let b_null' = b v_null
         and b2' = b v2
         and b3' = b v3
         and b4' = b v4
         and v_null' = h b_null
         and v2' = h b2
         and v3' = h b3
         and v4' = h b4 in
         b_null' = b_null &&
         b2' = b2 &&
         b3' = b3 &&
         b4' = b4 &&
         v_null' = v_null &&
         v2' = v2 &&
         v3' = v3 &&
         v4' = v4 ))

  let file_test =
    (name "file_test")>::
    (fun otx ->
       let () = only_once otx in
       assert_bool "" (
         with_tempfile () ~f:(fun ~close ~fln ~ch () ->
             let a = String.make 1_000 'a' in
             for _i = 1 to 1_000 do
               output_string ch a;
             done;
             close ch;
             let s1 = D.file fln in
             let s2 = D.file_fast fln in
             let s3 = with_bin_file ~fln () ~f:(fun ~ch () ->
                 D.channel ch 1_000_000 )
             in
             let s4 = with_bin_file ~fln () ~f:(fun ~ch () ->
                 D.channel ch (-1) )
             in
             s1 = s2 &&
             s2 = s3 &&
             s3 = s4 &&
             D.to_hex s1 = I.million )))

  let channel_test_sub =
    (name "channel_sub")>::
    (fun _ctx ->
       assert_equal I.v4 (
         with_tempfile () ~f:(fun ~close ~fln ~ch () ->
             output_string ch vec4;
             output_string ch "";
             close ch;
             let len = String.length vec4 in
             with_bin_file ~fln len ~f:(fun ~ch n ->
                 D.channel ch n |> D.to_hex ))))

  let channel_test_range =
    (name "channel_range")>::
    (fun otx ->
       let () = only_once otx in
       assert_raises End_of_file (fun () ->
           with_tempfile () ~f:(fun ~close ~fln ~ch () ->
               output_string ch "a";
               close ch;
               with_bin_file ~fln () ~f:(fun ~ch () ->
                   D.channel ch 2 |> ignore ))))

  let channel_test_null =
    (name "channel_null")>:::
    (List.map
       ( fun n ->
          "n1">::
          (fun otx ->
             let () = only_once otx in
             assert_equal I.v_null (
               with_tempfile () ~f:(fun ~close ~fln ~ch () ->
                   close ch;
                   with_bin_file ~fln () ~f:(fun ~ch () ->
                       D.channel ch n |> D.to_hex )))))
       [ 0 ; (-1) ])

  let channel_test_null2 =
    (name "channel_null2")>::
    (fun otx ->
       let () = only_once otx in
       assert_equal I.v_null (
         with_tempfile () ~f:(fun ~close ~fln ~ch () ->
             output_string ch "a";
             close ch;
             with_bin_file ~fln () ~f:(fun ~ch () ->
                 D.channel ch 0 |> D.to_hex ))))

  let t_update_substring =
    (name "update_substring")>::
    (fun _ctx ->
       assert_equal I.v4 (
         let len = String.length vec4 in
         let s = "a" ^ vec4 ^ "b" in
         let ctx = D.init () in
         D.update_substring ctx s 1 len;
         D.finalize ctx |> D.to_hex ))


  let t_update_subbuffer =
    (name "update_subbuffer")>::
    (fun _ctx ->
       assert_equal I.v4 (
         let len = String.length vec4 in
         let s = "a" ^ vec4 ^ "b" in
         let ba = ba_of_string s in
         let ctx = D.init () in
         D.update_subbuffer ctx ba 1 len;
         D.finalize ctx |> D.to_hex ))


  let t_update_substring_range =
    (name "udpate_substring_range")>:::
    (List.map
       ( fun (string,start,len) ->
          "n">::
          (fun otx ->
             let () = only_once otx in
             assert_raises
               (Invalid_argument "Cryptohash.update_substring")
               (fun () ->
                  let ctx = D.init () in
                  D.update_substring ctx string start len;
                  D.finalize ctx |> D.to_hex )))
       [ ("a",-1,1);
         ("a",1,-1);
         ("abc",0,4);
         ("abcd",2,3) ])

  let t_update_subbuffer_range =
    (name "udpate_subbuffer_range")>:::
    (List.map
       ( fun (string,start,len) ->
          "n">::
          let ba = ba_of_string string in
          (fun otx ->
             let () = only_once otx in
             assert_raises
               (Invalid_argument "Cryptohash.update_subbuffer")
               (fun () ->
                  let ctx = D.init () in
                  D.update_subbuffer ctx ba start len;
                  D.finalize ctx |> D.to_hex )))
       [ ("a",-1,1);
         ("a",1,-1);
         ("abc",0,4);
         ("abcd",2,3) ])

  let t_substring =
    (name "substring")>::
    (fun otx ->
       let () = only_once otx in
       assert_equal I.v3 (
         let s = vec3 ^ "b" in
         String.length vec3 |> D.substring s 0 |> D.to_hex))

  let t_subbuffer =
    (name "subbuffer")>::
    (fun otx ->
       let () = only_once otx in
       assert_equal I.v3 (
         let s = vec3 ^ "b" in
         let b = ba_of_string s in
         String.length vec3 |> D.subbuffer b 0 |> D.to_hex))


  let t_substring_range =
    (name "substring_range")>:::
    (List.map
       (fun (string,start,len) ->
          "n">::
          (fun _ctx ->
             assert_raises
               (Invalid_argument "Cryptohash.substring")
               (fun () ->
                  D.substring string start len |> D.to_hex)))
       [ ("a",-1,1);
         ("a",1,-1);
         ("abc",0,4);
         ("abcd",2,3) ])

  let t_subbuffer_range =
    (name "subbufer_range")>:::
    (List.map
       (fun (string,start,len) ->
          let ba = ba_of_string string in
          "n">::
          (fun _ctx ->
             assert_raises
               (Invalid_argument "Cryptohash.subbuffer")
               (fun () ->
                  D.subbuffer ba start len |> D.to_hex)))
       [ ("a",-1,1);
         ("a",1,-1);
         ("abc",0,4);
         ("abcd",2,3) ])

  let t_buffer =
    (name "buffer")>::
    (fun _ctx ->
       assert_equal I.b4 (ba_of_string vec4 |> D.buffer |> D.to_bin))


  let input_output =
    (name "input_output")>::
    (fun otx ->
       let () = only_once otx in
       assert_bool "" (
         with_tempfile () ~f:(fun ~close ~fln ~ch () ->
             let b = D.string "~~" in
             D.output ch b;
             close ch;
             let b' =
               with_bin_file ~fln () ~f:(fun ~ch () ->
                   D.input ch)
             in
             b' = b)))

  let io_error_stub =
    (name "io_error_stub")>::
    (fun ctx ->
       let () = only_once ctx in
       let n = "/asöäüÖÄÜöööö" in
       let io_error_msg = n ^ ": I/O error" in
       assert_raises
         (Sys_error io_error_msg)
         (fun () -> D.file_fast n |> ignore))


  let rev_filename = Filename.concat "test_data" (I.name ^ ".bin")


  let channel_read =
    (name "channel_read")>::
    (fun ctx ->
       let () = only_once ctx in
       let fln = rev_filename in
       assert_bool "" (
         with_bin_file ~fln () ~f:(fun ~ch () ->
             let f x = D.from_bin x in
             f I.b_null = D.input ch &&
             f I.b2 = D.input ch &&
             f I.b3 = D.input ch &&
             f I.b4 = D.input ch )
       ))

  let channel_write =
    (name "channel_write")>::
    (fun ctx ->
       let () = skip_long ctx in
       assert_bool "" (
         with_tempfile () ~f:(fun ~close ~fln ~ch () ->
             let f x = D.from_bin x in
             f I.b_null |> D.output ch;
             f I.b2 |> D.output ch;
             f I.b3 |> D.output ch;
             f I.b4 |> D.output ch;
             close ch;
             string_of_file ~fln = string_of_file ~fln:rev_filename )))

(*
  let () =
    let fln = "/tmp/" ^ I.name ^ ".bin" in
    let ch = open_out_bin fln in
    let f s =
      D.from_bin s |> D.output ch
    in
    f I.b_null;
    f I.b2;
    f I.b3;
    f I.b4;
    close_out ch
*)

  let () =
    let t = I.name>:::([
        init_test;
        hex_bin_test;
        file_test;
        t_update_substring;
        t_update_subbuffer;
        t_update_substring_range;
        t_update_subbuffer_range;
        t_substring;
        t_subbuffer;
        t_substring_range;
        t_subbuffer_range;
        t_buffer;
        input_output;
        channel_test_sub;
        channel_test_range;
        channel_test_null;
        channel_test_null2;
        channel_read;
        channel_write;
        copy_test;
        io_error_stub;
        refstring (
          [ vec1, I.v_null ;
            vec2, I.v2 ;
            vec3, I.v3 ;
            vec4, I.v4 ] );
        million;
        delirious;
      ])
    in
    add_tests t
end

(* test data from non-nist hashes are from rhash and jacksum *)
let b = Bytes.of_string
module Md2_data = struct
  let name = "md2"
  let v_null = "8350e5a3e24c153df2275c9f80692773"
  let v2 = "da853b0d3f88d99b30283a69e6ded6bb"
  let v3 = "0dff6b398ad5a62ac8d97566b80c3a7f"
  let v4 = "2c194d0376411dc0b8485d3abe2a4b6b"
  let b_null = b "\131P\229\163\226L\021=\242'\\\159\128i's"
  let b2 = b "\218\133;\r?\136\217\1550(:i\230\222\214\187"
  let b3 = b "\r\255k9\138\213\166*\200\217uf\184\012:\127"
  let b4 = b ",\025M\003vA\029\192\184H]:\190*Kk"
  let million = "8c0a09ff1216ecaf95c8130953c62efd"
  let delirious = "596d0463369fda2f80ed901edd462eff"
end

module Md4_data = struct
  let name = "md4"
  let v_null = "31d6cfe0d16ae931b73c59d7e0c089c0"
  let v2 = "a448017aaf21d8525fc10ae87aa6729d"
  let v3 = "4691a9ec81b1a6bd1ab8557240b245c5"
  let v4 = "2102d1d94bd58ebf5aa25c305bb783ad"
  let b_null = b "1\214\207\224\209j\2331\183<Y\215\224\192\137\192"
  let b2 = b "\164H\001z\175!\216R_\193\n\232z\166r\157"
  let b3 = b "F\145\169\236\129\177\166\189\026\184Ur@\178E\197"
  let b4 = b "!\002\209\217K\213\142\191Z\162\\0[\183\131\173"
  let million = "bbce80cc6bb65e5c6745e30d4eeca9a4"
  let delirious = "699057dc7272ba3db0e32f09b8ab8442"
end

module Md5_data = struct
  let name = "md5"
  let v_null = "d41d8cd98f00b204e9800998ecf8427e"
  let v2 = "900150983cd24fb0d6963f7d28e17f72"
  let v3 = "8215ef0796a20bcaaae116d3876c664a"
  let v4 = "03dd8807a93175fb062dfb55dc7d359c"
  let b_null = b "\212\029\140\217\143\000\178\004\233\128\t\152\236\248B~"
  let b2 = b "\144\001P\152<\210O\176\214\150?}(\225\127r"
  let b3 = b "\130\021\239\007\150\162\011\202\170\225\022\211\135lfJ"
  let b4 = b "\003\221\136\007\1691u\251\006-\251U\220}5\156"
  let million = "7707d6ae4e027c70eea2a935c2296f21"
  let delirious = "d338139169d50f55526194c790ec0448"
end

module Sha1_data = struct
  let name = "sha1"
  let v_null = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
  let v2 = "a9993e364706816aba3e25717850c26c9cd0d89d"
  let v3 = "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
  let v4 = "a49b2446a02c645bf419f995b67091253a04a259"
  let b_null = b "\2189\163\238^kK\r2U\191\239\149`\024\144\175\216\007\t"
  let b2 = b "\169\153>6G\006\129j\186>%qxP\194l\156\208\216\157"
  let b3 = b "\132\152>D\028;\210n\186\174J\161\249Q)\229\229Fp\241"
  let b4 = b "\164\155$F\160,d[\244\025\249\149\182p\145%:\004\162Y"
  let million = "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
  let delirious = "7789f0c9ef7bfc40d93311143dfbe69e2017f592"
end

module Sha224_data = struct
  let name = "sha224"
  let v_null = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
  let v2 = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
  let v3 = "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
  let v4 = "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"
  let b_null = b @@ "\209J\002\140*:+\201Ga\002\187(\1304\196\021\162\176\031\130" ^
               "\142\166*\197\179\228/"
  let b2 = b @@ "#\t}\"4\005\216\"\134B\164w\189\162U\179*\173\188\228\189\160\179" ^
           "\247\227l\157\167"
  let b3 = b @@ "u8\139\022Q'v\204]\186]\161\253\137\001P\176\198E\\\180\245\139" ^
           "\025RR%%"
  let b4 = b @@"\201|\169\165Y\133\012\233z\004\169m\239m\153\169\224\224\226\171" ^
           "\020\230\184\223&_\192\179"
  let million = "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"
  let delirious = "b5989713ca4fe47a009f8621980b34e6d63ed3063b2a0a2c867d8a85"
end

module Sha256_data = struct
  let name = "sha256"
  let v_null = "e3b0c44298fc1c149afbf4c8996fb924" ^
               "27ae41e4649b934ca495991b7852b855"
  let v2 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  let v3 = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
  let v4 = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
  let b_null = b @@ "\227\176\196B\152\252\028\020\154\251\244\200\153o\185$'" ^
               "\174A\228d\155\147L\164\149\153\027xR\184U"
  let b2 = b @@ "\186x\022\191\143\001\207\234AA@\222]\174\"#\176\003a\163\150" ^
           "\023z\156\180\016\255a\242\000\021\173"
  let b3 = b @@ "$\141ja\210\0068\184\229\192&\147\012>`9\163<\228Yd\255!g\246" ^
           "\236\237\212\025\219\006\193"
  let b4 = b @@ "\207[\022\167x\175\131\128\003l\229\158{\004\1467\011$\155\017" ^
           "\232\240zQ\175\172E\003z\254\233\209"
  let million =
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
  let delirious =
    "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e"
end

module Sha384_data = struct
  let name = "sha384"
  let v_null =
    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743" ^
    "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
  let v2=
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163" ^
    "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
  let v3=
    "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05ab" ^
    "fe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"
  let v4=
    "09330c33f71147e83d192fc782cd1b4753111b173b3b05d2" ^
    "2fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
  let b_null = b @@ "8\176`\167Q\172\1508L\2172~\177\177\227j!\253\183\017\020\190" ^
               "\007CL\012\199\191c\246\225\218'N\222\191\231oe\251\213\026" ^
               "\210\241H\152\185["
  let b2 = b @@
    "\203\000u?E\163^\139\181\160=i\154\198P\007',2\171\014\222\209c" ^
    "\026\139`ZC\255[\237\128\134\007+\161\231\204#X\186\236\1614\200%\167"
  let b3 = b @@
    "3\145\253\221\252\141\19997\007\166[\027G\t9|\248\177\209b\175" ^
    "\005\171\254\143E\r\229\243k\198\176EZ\133 \188No_\233[\031\227\200E+"
  let b4 = b @@
    "\t3\0123\247\017G\232=\025/\199\130\205\027GS\017\027\023;;\005\210/" ^
    "\160\128\134\227\176\247\018\252\199\199\026U~-\185f\195\233\250\145t`9"
  let million =
    "9d0e1809716474cb086e834e310a4a1ced149e9c00f24852" ^
    "7972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
  let delirious=
    "5441235cc0235341ed806a64fb354742b5e5c02a3c5cb71b" ^
    "5f63fb793458d8fdae599c8cd8884943c04f11b31b89f023"
end

module Sha512_data = struct
  let name = "sha512"
  let v_null =
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" ^
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
  let v2 =
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" ^
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
  let v3 =
    "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335" ^
    "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
  let v4 =
    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018" ^
    "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
  let b_null = b @@
    "\207\131\2255~\239\184\189\241T(P\214m\128\007\214 \228\005\011W\021\220" ^
    "\131\244\169!\211l\233\206G\208\209<]\133\242\176\255\131\024\210\135~" ^
    "\236/c\1851\189GAz\129\16582z\249'\218>"
  let b2 = b @@ "\221\1755\161\147az\186\204AsI\174 A1\018\230\250N\137\169~\162" ^
           "\n\158\238\230KU\211\154!\146\153*'O\193\1686\186<#\163\254\235" ^
           "\189EMD#d<\232\014*\154\201O\165L\164\159"
  let b3 = b @@ " J\143\198\221\168/\n\012\237{\235\142\b\164\022W\193n\244h" ^
           "\178(\168'\155\2271\167\003\1955\150\253\021\193;\027\007\249" ^
           "\170\029;\234Wx\156\1601\173\133\199\167\029\215\003T\236c" ^
           "\0188\2024E"
  let b4 = b @@
    "\142\149\155u\218\227\019\218\140\244\247(\020\252\020?\143wy\198\235" ^
    "\159\127\161r\153\174\173\182\136\144\024P\029(\158I\000\247\2283\027" ^
    "\153\222\196\181C:\199\211)\238\182\221&T^\150\229[\135K\233\t"
  let million =
    "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb" ^
    "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
  let delirious =
    "b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d" ^
    "77be6091b819ed352c2967a2e2d4fa5050723c9630691f1a05a7281dbe6c1086"
end

module Sha3_224_data = struct
  let name = "sha3_224"
  let v_null = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
  let v2 = "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
  let v3 = "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33"
  let v4 = "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc"
  let b_null = b
    "kN\003B6g\219\183;n\021EO\014\177\171\212Y\127\154\027\007\142?[Zk\199"
  let b2 = b @@ "\230B\130L?\140\242J\208\1464\238}<vo\201\163\165\022\141\012" ^
           "\148\173s\180o\223"
  let b3 = b @@ "\138$\016\139\021J\218!\201\253UtIDy\186\\~z" ^
           "\183n\242d\234\208\252\2063"
  let b4 = b @@ "T>hh\225fl\026d60\223w6z\229\166*\133\007\nQ\193L\191f\\\188"
  let million = "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c"
  let delirious = "c6d66e77ae289566afb2ce39277752d6da2a3c46010f1e0a0970ff60"
end

module Sha3_256_data = struct
  let name = "sha3_256"
  let v_null =
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
  let v2 = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
  let v3 = "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
  let v4 = "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18"
  let b_null = b @@ "\167\255\198\248\191\030\215fQ\193GV\160a\214b\245\128" ^
               "\255M\228;I\250\130\216\nK\128\248CJ"
  let b2 = b @@ ":\152]\167O\226%\178\004\\\023-k\211\144\189\133_" ^
           "\bn>\157R[F\191\226E\017C\0212"
  let b3 = b @@ "A\192\219\162\169\214$\bI\016\003v\168#^,\130\225\185" ^
           "\153\138\153\158!\2192\221\151Im3v"
  let b4 = b @@ "\145o`a\254\135\151A\202di\1809q\223\219(\177\163-\195l" ^
           "\179%N\129+\226z\173\029\024"
  let million =
    "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"
  let delirious =
    "ecbbc42cbf296603acb2c6bc0410ef4378bafb24b710357f12df607758b33e2b"
end

module Sha3_384_data = struct
  let name = "sha3_384"
  let v_null = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61" ^
           "995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
  let v2 = "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c25" ^
           "96da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
  let v3 = "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e42" ^
           "9bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22"
  let v4 = "79407d3b5916b59c3e30b09822974791c313fb9ecc849e40" ^
           "6f23592d04f625dc8c709b98b43b3852b337216179aa7fc7"
  let b_null = b @@
    "\012c\167[\132^O}\001\016}\133.L$\133\197\026P\170\170\148" ^
    "\252a\153^q\187\238\152:*\195q81&J\219G\251k\209\224X\213\240\004"
  let b2 = b @@ "\236\001I\130\136Qo\201&E\159X\226\198\173\141\249\180s\203\015" ^
           "\192\140%\150\218|\240\228\155\228\178\152\216\140\234\146z\199" ^
           "\2459\241\237\242(7m%"
  let b3 = b @@ "\153\028fWU\235:Kk\189\251u\199\138I.\140V\162,\\M~B\155\253" ^
           "\1882\185\212\173Z\160J\031\007nb\254\161\158\239Q\172\208e|\""
  let b4 = b @@ "y@};Y\022\181\156>0\176\152\"\151G\145\195\019\251\158\204\132" ^
           "\158@o#Y-\004\246%\220\140p\155\152\180;8R\1797!ay\170\127\199"
  let million = "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e" ^
                "948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340"
  let delirious = "a04296f4fcaae14871bb5ad33e28dcf69238b04204d9941b" ^
                  "8782e816d014bcb7540e4af54f30d578f1a1ca2930847a12"
end




module Sha3_512_data = struct
  let name = "sha3_512"
  let v_null =
    "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6" ^
    "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
  let v2 = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e" ^
           "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
  let v3 = "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636d" ^
           "ee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"
  let v4 = "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa" ^
           "73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185"
  let b_null = b @@
    "\166\159s\204\162:\154\197\200\181g\220\024Zun\151\201\130\022O\226XY" ^
    "\224\209\220\193G\\\128\166\021\178\018:\241\245\249L\017\227\233@,:" ^
    "\197X\245\000\025\157\149\182\211\227\001u\133\134(\029\205&"
  let b2 = b @@
    "\183Q\133\011\026W\022\138V\147\205\146Kk\tn\b\246!\130tD\247\r\136O]" ^
    "\002@\210q.\016\225\022\233\025*\243\201\026~\197vG\227\147@W4\011L\244" ^
    "\b\213\165e\146\248'N\236S\240"
  let b3 = b @@
    "\004\163q\232N\207\181\184\183|\180\134\016\252\168\024-\212W\206o2j\015" ^
    "\211\215\236/\030\145cm\238i\031\190\012\152S\002\186\027\r\141\199\140" ^
    "\bcF\1813\180\156\003\r\153\162}\175\0179\214\231^"
  let b4 = b @@
    "\175\235\178\239T.ey\197\012\173\006\210\229x\249\248\221h\129\215\220" ^
    "\130M&6\015\238\191\024\164\250s\227&\017\"\148\142\252\253I.t\232.!" ^
    "\137\237\015\180@\209\135\243\130'\012\180U\242\029\209\133"
  let million =
    "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859" ^
    "ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"
  let delirious =
    "235ffd53504ef836a1342b488f483b396eabbfe642cf78ee0d31feec788b23d0" ^
    "d18d5c339550dd5958a500d4b95363da1b5fa18affc1bab2292dc63b7d85097c"
end

module Whirlpool_data = struct
  let name = "whirlpool"
  let v_null =
    "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7" ^
    "3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"
  let v2 = "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c" ^
           "7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5"
  let v3 = "526b2394d85683e24b29acd0fd37f7d5027f61366a1407262dc2a6a345d9e240" ^
           "c017c1833db1e6db6a46bd444b0c69520c856e7c6e9c366d150a7da3aeb160d1"
  let v4 = "14aa95962750ed385bed2b9f43fbad41483a8910221723a5f15a0614e74fb12fe" ^
           "7d5523abd8ab0c09cb77852159deef4e9eb9808e54a0b83f26865d121af3c0b"
  let b_null = b @@
    "\025\250a\215U\"\164f\155D\227\156\029.\023&\1970#!0\212\007\248\154\254" ^
    "\224\150I\151\247\167>\131\190i\139(\143\235\207\136\227\224<O\007W\234" ^
    "\137d\229\155c\2177\b\1778\204B\166n\179"
  let b2 = b @@
    "N$H\164\198\244\134\187\022\182V,s\180\002\011\243\004>:s\027\206r\026" ^
    "\225\179\003\217~mLq\129\238\189\182\197~'}\0144\149q\020\203\214\199" ^
    "\151\252\157\149\216\181\130\210%) v\212\238\245"
  let b3 = b @@
    "Rk#\148\216V\131\226K)\172\208\2537\247\213\002\127a6j\020\007&-\194" ^
    "\166\163E\217\226@\192\023\193\131=\177\230\219jF\189DK\012iR\012\133n" ^
    "|n\1566m\021\n}\163\174\177`\209"
  let b4 = b @@
    "\020\170\149\150'P\2378[\237+\159C\251\173AH:\137\016\"\023#\165\241Z" ^
    "\006\020\231O\177/\231\213R:\189\138\176\192\156\183xR\021\157\238\244" ^
    "\233\235\152\b\229J\011\131\242he\209!\175<\011"
  let million =
    "0c99005beb57eff50a7cf005560ddf5d29057fd86b20bfd62deca0f1ccea4af51" ^
    "fc15490eddc47af32bb2b66c34ff9ad8c6008ad677f77126953b226e4ed8b01"
  let delirious =
    "44645ed72030b7978456b5a2d8d1cf4c295575d7925e5f4da1781863aeb4f43b3" ^
    "3eab1fbcf0725353762d9153f237f03a9713f0f7da9a19431f26cf0088af117"
end

module Ripemd128_data = struct
  let name = "ripemd128"
  let v_null = "cdf26213a150dc3ecb610f18f6b38b46"
  let v2 = "c14a12199c66e4ba84636b0f69144c77"
  let v3 = "a1aa0689d0fafa2ddc22e88b49133a06"
  let v4 = "d4ecc913e1df776bf48de9d55b1f2546"
  let b_null = b @@ "\205\242b\019\161P\220>\203a\015\024\246\179\139F"
  let b2 = b @@ "\193J\018\025\156f\228\186\132ck\015i\020Lw"
  let b3 = b @@ "\161\170\006\137\208\250\250-\220\"\232\139I\019:\006"
  let b4 = b @@ "\212\236\201\019\225\223wk\244\141\233\213[\031%F"
  let million = "4a7f5723f954eba1216c9d8f6320431f"
  let delirious = "9111078494b8918cbdbb8b2cfcbdbd91"
end

module Ripemd160_data = struct
  let name = "ripemd160"
  let v_null = "9c1185a5c5e9fc54612808977ee8f548b2258d31"
  let v2 = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
  let v3 = "12a053384a9c0c88e405a06c27dcf49ada62eb2b"
  let v4 = "6f3fa39b6b503c384f919a49a7aa5c2c08bdfb45"
  let b_null = b @@ "\156\017\133\165\197\233\252Ta(\b\151~\232\245H\178%\1411"
  let b2 = b @@ "\142\178\b\247\224]\152z\155\004J\142\152\198\176\135\241Z\011\252"
  let b3 = b @@ "\018\160S8J\156\012\136\228\005\160l'\220\244\154\218b\235+"
  let b4 = b @@ "o?\163\155kP<8O\145\154I\167\170\\,\b\189\251E"
  let million = "52783243c1697bdbe16d37f97f68f08325dc1528"
  let delirious = "29b6df855772aa9a95442bf83b282b495f9f6541"
end

module Tiger_data = struct
  let name = "tiger"
  let v_null = "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3"
  let v2 = "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93"
  let v3 = "0f7bf9a19b9c58f2b7610df7e84f0ac3a71c631e7b53f78e"
  let v4 = "ecce1e3610505fce94f732ee25e8cb7afaf7fcc8888866fd"
  let b_null = b @@ "2\147\172c\012\019\240$_\146\187\177vn\022\022zNXI-\222s\243"
  let b2 = b
    "*\171\020\132\232\193X\242\191\184\197\255A\181zRQ)\019\028\149{_\147"
  let b3 = b
    "\015{\249\161\155\156X\242\183a\r\247\232O\n\195\167\028c\030{S\247\142"
  let b4 = b @@ "\236\206\0306\016P_\206\148\2472\238%" ^
           "\232\203z\250\247\252\200\136\136f\253"
  let million = "6db0e2729cbead93d715c6a7d36302e9b3cee0d2bc314b41"
  let delirious = "d1f09303fb2a1c1f6d5ba78d6eef1d88d0b14883b1e70006"
end

module Tiger2_data = struct
  let name = "tiger2"
  let v_null = "4441be75f6018773c206c22745374b924aa8313fef919f41"
  let v2 = "f68d7bc5af4b43a06e048d7829560d4a9415658bb0b1f3bf"
  let v3 = "a6737f3997e8fbb63d20d2df88f86376b5fe2d5ce36646a9"
  let v4 = "2933e3294e58dd6af7b1a2f59c9cd031c1f7bc9cb0d9ae2f"
  let b_null = b @@ "DA\190u\246\001\135s\194\006\194'E7K\146J\1681?\239\145\159A"
  let b2 = b @@ "\246\141{\197\175KC\160n\004\141x)V\rJ\148\021e\139\176\177\243\191"
  let b3 = b @@ "\166s\1279\151\232\251\182= \210\223\136\248cv\181\254-\\\227fF\169"
  let b4= b
    ")3\227)NX\221j\247\177\162\245\156\156\2081\193\247\188\156\176\217\174/"
  let million = "e068281f060f551628cc5715b9d0226796914d45f7717cf4"
  let delirious = "184be3d4dc9420e7eb56812a97b3f37527eaaa1197fcbaaa"
end

(*
module _data = struct
  let name =
  let v_null =
  let v2 =
  let v3 =
  let v4 =
  let b_null =
  let b2 =
  let b3 = b
  let b4=
  let million =
  let delirious =
end
*)
(*let () =
    let open Cryptohash_tiger in
    let g s = from_hex s |> to_bin in
    Printf.printf
      "let b_null = %S \nlet b2 = %S \nlet b3 = %S\nlet b4=%S\n"
      (g v_null)
      (g v2)
      (g v3)
      (g v4) *)

module MD2_test = MakeTest(Cryptohash_md2)(Md2_data)
module MD4_test = MakeTest(Cryptohash_md4)(Md4_data)
module MD5_test = MakeTest(Cryptohash_md5)(Md5_data)

module SHA1_test = MakeTest(Cryptohash_sha1)(Sha1_data)
module SHA224_test = MakeTest(Cryptohash_sha224)(Sha224_data)
module SHA256_test = MakeTest(Cryptohash_sha256)(Sha256_data)

module SHA384_test = MakeTest(Cryptohash_sha384)(Sha384_data)
module SHA512_test = MakeTest(Cryptohash_sha512)(Sha512_data)

module Sha3_224_test = MakeTest(Cryptohash_sha3_224)(Sha3_224_data)
module Sha3_256_test = MakeTest(Cryptohash_sha3_256)(Sha3_256_data)
module Sha3_384_test = MakeTest(Cryptohash_sha3_384)(Sha3_384_data)
module Sha3_512_test = MakeTest(Cryptohash_sha3_512)(Sha3_512_data)

module Whirlpool_test = MakeTest(Cryptohash_whirlpool)(Whirlpool_data)

module Ripemd128_test = MakeTest(Cryptohash_ripemd128)(Ripemd128_data)
module Ripemd160_test = MakeTest(Cryptohash_ripemd160)(Ripemd160_data)

module Tiger_test = MakeTest(Cryptohash_tiger)(Tiger_data)
module Tiger2_test = MakeTest(Cryptohash_tiger2)(Tiger2_data)

open OUnit2

(* additional tests from the saphir project *)
let () =
  let open MD2_test in
  add_tests (
    "md2_custom">:::(
      [
        (refstring
           [
             "a", "32ec01ec4a6dac72c0ab96fb34c0b5d1";
             "message digest", "ab4f496bfb2a530b219ff33031fe06b0";
             "abcdefghijklmnopqrstuvwxyz", "4e8ddff3650292ab5a4108c3aa47940b";
             "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
             "da33def2a42df13975352846c30338cd";
             "1234567890123456789012345678901234567890"^
             "1234567890123456789012345678901234567890",
             "d5976f79d83d3a0dc9806c3c66f3efd8" ]);
      ]))

let () =
  let open MD4_test in
  add_tests (
    "md4_tests">:::(
      [
        (refstring [
            "a", "bde52cb31de33e46245e05fbdbd6fb24";
            "message digest", "d9130a8164549fe818874806e1c7014b";
            "abcdefghijklmnopqrstuvwxyz","d79e1c308aa5bbcdeea8ed63df412da9";
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "043f8582f241db351ce627e153e7f0e4";
            "1234567890123456789012345678901234567890"^
            "1234567890123456789012345678901234567890",
            "e33b4ddc9c38f2199c3e7b164fcc0536"
          ]);
        collision [
          "839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20a083b69" ^
          "f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edd45e51fe39708" ^
          "bf9427e9c3e8b9",
          "839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20a083b69" ^
          "f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edc45e51fe39708" ^
          "bf9427e9c3e8b9";
          "839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20a083b69" ^
          "f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edd45e51fe39740" ^
          "c213f769cfb8a7",
          "839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20a083b69" ^
          "f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edc45e51fe39740" ^
          "c213f769cfb8a7"
        ] ]))

let () =
  let open MD5_test in
  add_tests (
    "md5_tests">:::(
      [
        (refstring [
            "a", "0cc175b9c0f1b6a831c399e269772661";
            "message digest", "f96b697d7cb7938d525a2f31aaf161d0";
            "abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b";
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu" ^
            "vwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f";
            "1234567890123456789012345678901234567890123456789" ^
            "0123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a" ]);
        collision [
          "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8f" ^
          "b7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbd" ^
          "f280373c5b960b1dd1dc417b9ce4d897f45a6555d535739ac7f0ebfd0c3" ^
          "029f166d109b18f75277f7930d55ceb22e8adba79cc155ced74cbdd5fc5" ^
          "d36db19b0ad835cca7e3",
          "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8f" ^
          "b7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd" ^
          "7280373c5b960b1dd1dc417b9ce4d897f45a6555d535739a47f0ebfd0c3" ^
          "029f166d109b18f75277f7930d55ceb22e8adba794c155ced74cbdd5fc5" ^
          "d36db19b0a5835cca7e3" ;

          "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8f" ^
          "b7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbd" ^
          "f280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd0" ^
          "2396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8" ^
          "839396f9652b6ff72a70",
          "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8f" ^
          "b7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd" ^
          "7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd0" ^
          "2396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8" ^
          "839396f965ab6ff72a70";
        ]]))

let () =
  let open Whirlpool_test in
  add_tests (
    "whirlpool_testt">:::([
        (refstring [
            ("a",
             "8ACA2602792AEC6F11A67206531FB7D7F0DFF59413145E6973C45001D0087B42"^
             "D11BC645413AEFF63A42391A39145A591A92200D560195E53B478584FDAE231A");
            ("message digest",
             "378C84A4126E2DC6E56DCC7458377AAC838D00032230F53CE1F5700C0FFB4D3B"^
             "8421557659EF55C106B4B52AC5A4AAA692ED920052838F3362E86DBD37A8903E");
            ("abcdefghijklmnopqrstuvwxyz",
             "F1D754662636FFE92C82EBB9212A484A8D38631EAD4238F5442EE13B8054E41B"^
             "08BF2A9251C30B6A0B8AAE86177AB4A6F68F673E7207865D5D9819A3DBA4EB3B");
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
             "DC37E008CF9EE69BF11F00ED9ABA26901DD7C28CDEC066CC6AF42E40F82F3A1E"^
             "08EBA26629129D8FB7CB57211B9281A65517CC879D7B962142C65F5A7AF01467");
            ("123456789012345678901234567890"^
             "12345678901234567890123456789012345678901234567890",
             "466EF18BABB0154D25B9D38A6414F5C08784372BCCB204D6549C4AFADB601429"^
             "4D5BD8DF2A6C44E538CD047B2681A51A2C60481E88C5A20B2C2A80CF3A9A083B");
            ("abcdbcdecdefdefgefghfghighijhijk",
             "2A987EA40F917061F5D6F0A0E4644F488A7A5A52DEEE656207C562F988E95C69"^
             "16BDC8031BC5BE1B7B947639FE050B56939BAAA0ADFF9AE6745B7B181C3BE3FD");
          ])]))


exception Do_exit of int
let mexit i =
  if i <> 0 then (
    prerr_endline "test case failure";
  );
  raise (Do_exit i)

let main () =
  let t = get_tests () in
  OUnit2.run_test_tt_main ~exit:mexit t |> ignore

let () =
  try
    main ();
    raise (Do_exit 0)
  with
  | Do_exit i ->
    let compact =
      let x = ref false in
      for i = 1 to Array.length Sys.argv - 2 do
        if Sys.argv.(i) = "-runner" && Sys.argv.(succ i) = "sequential" then
          x:= true;
      done;
      !x
    in
    (match compact with
     | false -> ()
     | true -> Gc.compact ();  Gc.compact (); );
    exit i
