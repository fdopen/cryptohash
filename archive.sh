#!/bin/sh

set -e
set -u

cd "$(dirname "$0")"

VERSION="$(grep '\s*VERSION=' OMakefile | sed -r 's#.*=([^\s]+)#\1#')"
NAME="$(grep '\s*PROJNAME=' OMakefile | sed -r 's#.*=([^\s]+)#\1#')"

rm -f _oasis src/configure
cd src
autoconf
cd ..
omake _oasis
oasis setup
omake distclean


ADIRNAME="${NAME}-${VERSION}"
TDIR="$(mktemp -d)"
trap "rm -rf \"${TDIR}\"" EXIT

ADIR="${TDIR}/${ADIRNAME}"
mkdir "${ADIR}"
tar -cf- . | (cd "${ADIR}" && tar -xf- )
find "${ADIR}" -type f \( -name '*.omc' -o -name '*~' -o -name '*.log' -o -name '*.lock' -o -name '.omakedb*' \) -delete
tar -C "${TDIR}" --format=ustar --numeric-owner -cf "${ADIR}.tar" "${ADIRNAME}"
gzip --stdout --keep --best "${ADIR}.tar"  > "${ADIRNAME}.tar.gz"
rm -rf "${TDIR}"
