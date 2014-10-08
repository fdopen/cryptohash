(** context type - opaque *)
type ctx

(** buffer type *)
type buf = (char,
            Bigarray.int8_unsigned_elt,
            Bigarray.c_layout) Bigarray.Array1.t

(** digest type - opaque *)
type t

(** Create a new context *)
val init: unit -> ctx

(** Return the digest of the given string. *)
val string : string -> t

(** Return the digest of the given byte sequence. *)
val bytes : Bytes.t -> t

(** Return the digest of the given buffer.
    All functions with parameters of type [buf] may release
    the runtime lock, if the buffer is large enough. *)
val buffer: buf -> t

(** @Digest@.unsafe_update_substring ctx s ~pos ~len updates the context
    with the substring of s starting at character number pos and
    containing len characters. Unsafe: No range checking! *)
val unsafe_update_substring: ctx -> string -> int -> int -> unit
val unsafe_update_subbytes: ctx -> Bytes.t -> int -> int -> unit
val unsafe_update_subbuffer: ctx -> buf -> int -> int -> unit

(** @Digest@.update_substring ctx s ofs len updates the context with the
    substring of s starting at character number ofs and containing len
    characters.
    Raise [Invalid_argument], if ofs and len do not designate a valid substring
    of s.
 *)
val update_substring: ctx -> string -> int -> int -> unit
val update_subbytes: ctx -> Bytes.t -> int -> int -> unit
val update_subbuffer: ctx -> buf -> int -> int -> unit

(** @Digest@.update_string ctx s updates the context with s. *)
val update_string: ctx -> string -> unit
val update_bytes:  ctx -> Bytes.t -> unit
val update_buffer: ctx -> buf -> unit

(** Return the final digest and reset the context *)
val finalize: ctx -> t

(** Return a copy of the context *)
val copy : ctx -> ctx

(** @Digest@.substring s ofs len returns the digest of the substring of
    s starting at character number ofs and containing len characters.
    Raise [Invalid_argument], if ofs and len do not designate a valid substring
    of s.
*)
val substring: string -> int -> int -> t
val subbytes: Bytes.t -> int -> int -> t
val subbuffer: buf -> int -> int -> t

(** If len is nonnegative, @Digest@.channel ic len reads len characters from
channel ic and returns their digest, or raises End_of_file if end-of-file is
reached before len characters are read. If len is negative, @Digest@.channel ic
len reads all characters from ic until end-of-file is reached and return their
digest. *)
val channel : in_channel -> int -> t

(** Return the digest of the file whose name is given. *)
val file : string -> t

(** Return the digest of the file whose name is given using fast C function.
    This function releases the OCaml runtime lock, so other OCaml threads can
    run in parallel. *)
val file_fast : string -> t

(** Write a digest on the given output channel. *)
val output : out_channel -> t -> unit

(** Read a digest from the given input channel. *)
val input : in_channel -> t

(** return a binary representation of the given digest *)
val to_bin : t -> string

(** return a printable hexadecimal representation of the given digest *)
val to_hex : t -> string

(** reversal of to_hex.
    Raises [Invalid_argument], if the parameter not a valid hexstring *)
val from_hex: string -> t

(** reversal of to_bin.
    Raises [Invalid_argument], if the parameter not a valid binary.
    representation *)
val from_bin: string -> t
