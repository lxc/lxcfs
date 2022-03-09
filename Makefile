# SPDX-License-Identifier: LGPL-2.1-or-later

meson:
	[ -d build ] || meson setup build/

all: meson
	ninja -C build

dist: meson
	meson dist -C build/ --formats=gztar
	cp build/meson-dist/*.tar.gz .

install:
	DESTDIR=$(DESTDIR) ninja -C build install
