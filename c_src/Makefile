CXXFLAGS=
LDFLAGS=

../_build/lib/libmacaroons.a:
	autoreconf -i libmacaroons
	cd libmacaroons && ./configure --enable-fast-install \
	                               --with-pic \
	                               --enable-static \
	                               --enable-shared= \
	                               --prefix=$(shell pwd)/../_build

	make -C libmacaroons install
