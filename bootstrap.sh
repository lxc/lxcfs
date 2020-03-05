# SPDX-License-Identifier: LGPL-2.1-or-later

set -x
set -e

test -d autom4te.cache && rm -rf autom4te.cache
libtoolize || exit 1
aclocal -I m4 || exit 1
autoheader || exit 1
autoconf || exit 1
automake --add-missing --copy || exit 1
