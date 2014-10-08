# Cryptohash

Cryptohash provides OCaml bindings to various cryptographic hash functions.

The following functions are supported:

* SHA-1
* SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512)
* SHA-3 (SHA3-224, SHA3-256, SHA3-384, SHA3-512) (not yet final, might change)
* Whirlpool
* Ripemd-160 and Ripemd-128
* MD2, MD4, and MD5
* Tiger and Tiger2

The hash algorithms are implemented in C for performance reasons.
Currently, the implementation provided by the [project
saphir](http://www.saphir2.com/sphlib/) is used (sphlib-3, slightly
modified for the latest change in the sha-3 draft)

Both sphlib and the bindings are distributed under a MIT style
license. Consult the LICENSE* files in the root folder for details.

The bindings follow the interface of the [Digest
module](http://caml.inria.fr/pub/docs/manual-ocaml/libref/Digest.html)
included in the OCaml standard library and
[ocaml-sha](https://github.com/vincenthz/ocaml-sha).

Usually, the bindings are independent of each other. There are
separate libraries and findlib packages for each hash function. You
need the findlib package `cryptohash.sha512` for sha-512,
`cryptohash.sha3-224` for sha3-224 and so forth.

## Installation

### Requirements

* findlib > 1.5 (for building and possibly the bytes module)
* oUnit >= 2 (build only)
* omake (build only)
* ocaml >= 4
* camlp4 (only for ocaml 3.X)

### Building the library

If you checkout from git, you first need to create the configure
script:

```bash
cd src
autoconf
```

Then run omake from the root folder:

```bash
omake all
```

You can disable or enable native code generation with:

```bash
omake all NATIVE_ENABLED=false
omake all NATIVE_ENABLED=true
```

The default depend on your omake configuration.

### Building documentation

```bash
omake doc
```

### Test cases

A small selection of test cases are run during the build process.

All test cases can be run with the `test` target:
```bash
omake test
```

`omake test` creates and run a test program that compares the result
of its own computations with public test vectors.

Another possibility is it to specify the target `exttest`:
```bash
omake exttest
```

The tool generated by `exttest` searches for external commands in your
PATH that can be used to compute hash digests (openssl, gpg, md5sum ,
sha256sum, jacksum , rhash, sha1sum, ...). Then it generates random
data, compute its checksums and tests if the external tools report the
same checksum.


### Installation

```bash
omake install
```

## Documentation

Documentation can be found in the mli files and the html files
generated by ocamldoc.

## Differences to ocaml-sha

Cryptohash was intend as replacement for ocaml-sha. There are however small differences:

* Some execeptions have been changed. The bindings now always follow the convention of `Digest`.
  `Invalid_arg` is thrown, if you don't designate a valid substring / subbuffer;
  `Sys_error` is thrown in case of an i/o error.
* `finalize` resets the context.
* the type `buf` was changed from
```ocaml
  type buf = (int,Bigarray.int8_unsigned_elt,Bigarray.c_layout) Bigarray.Array1.t
```
  to
```ocaml
  type buf = (char,Bigarray.int8_unsigned_elt,Bigarray.c_layout) Bigarray.Array1.t
```
* `zero` has been removed.
* `input` and `output` now have the same semantic as `Digest.input` and `Digest.output`

For details, consult the documentation.