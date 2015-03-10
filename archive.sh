#!/bin/sh

set -e
set -u

VERSION="$(grep '\s*VERSION=' OMakefile | sed -r 's#.*=([^\s]+)#\1#')"
NAME="$(grep '\s*PROJNAME=' OMakefile | sed -r 's#.*=([^\s]+)#\1#')"
pkg="${NAME}-${VERSION}"

curdir="$(readlink -f "$0")"
curdir="$(dirname "$curdir")"
cd "$curdir"
omake distclean

mtmpf="$(mktemp -d)"
trap "rm -rf \"${mtmpf}\"" EXIT

if which gtar >/dev/null 2>&1 ; then
    tar=gtar
else
    tar=tar
fi

stash="$(git stash create)"
git archive --format=tar ${stash:-HEAD} | ( cd "$mtmpf" ; tar -xf- )

cd src
autoreconf -fi
cp -p config.h.in configure "${mtmpf}/src"
cd ..
omake _oasis
oasis setup
cp -p setup.ml _oasis "$mtmpf"

if which gfind >/dev/null 2>&1 ; then
    find=gfind
else
    find=find
fi

cd "$mtmpf"

$find . -type f ! -executable ! -perm 644 -exec chmod 644 {} \+
$find . -type f -executable ! -perm 755 -exec chmod 755 {} \+
$find . -type d ! -perm 755 -exec chmod 755 {} \+

$tar --transform "s|^.|${pkg}|" --format=ustar --numeric-owner -cf- . | \
    gzip -9 > "${curdir}/${pkg}.tar.gz"

omake all >/dev/null 2>&1
omake quick-test
