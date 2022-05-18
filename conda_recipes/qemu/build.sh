## Clang doesn't have this option level, but the default behaviour is close:
#sed -ie 's|-Wimplicit-fallthrough=2|-Wimplicit-fallthrough|' configure

# This seems to be the target that Anaconda has built deps for:
MACOSX_DEPLOYMENT_TARGET=11.1

# Configure has no option for this, to pick up conda's GNU version:
LIBTOOL=${BUILD_PREFIX}/bin/libtool

#env

./configure --prefix=${PREFIX} \
	    --target-list="x86_64-softmmu" \
	    --disable-bsd-user \
	    --disable-linux-user \
	    --cc=${BUILD_PREFIX}/bin/clang \
	    --host-cc=${BUILD_PREFIX}/bin/clang \
	    --cxx=${BUILD_PREFIX}/bin/clang++ \
	    --objcc=${BUILD_PREFIX}/bin/clang \
	    --make=${BUILD_PREFIX}/bin/make \
	    --meson=${BUILD_PREFIX}/bin/meson \
	    --ninja=${BUILD_PREFIX}/bin/ninja \
	    --enable-cocoa \
	    --disable-curses \
	    --disable-gnutls \
	    --disable-gtk \
	    --disable-guest-agent \
	    --disable-libssh \
	    --disable-nettle \
	    --disable-rdma \
	    --enable-slirp=system \
	    --enable-virtfs \
	    --enable-vnc \
	    --disable-xen \
	    --extra-cflags=-DNCURSES_WIDECHAR=1 \
	    --smbd=${PREFIX}/bin/smbd || exit 1  # avoid OS SMB, from homebrew

make || exit $?

make install

