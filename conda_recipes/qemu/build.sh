set -x
## Clang doesn't have this option level, but the default behaviour is close:
#sed -ie 's|-Wimplicit-fallthrough=2|-Wimplicit-fallthrough|' configure

if [ "$OSX_ARCH" = "arm64" ]; then
    # This seems to be the target that Anaconda has built deps for on M1:
    MACOSX_DEPLOYMENT_TARGET=11.1
elif [ "$OSX_ARCH" = "x86_64" ]; then
    # Some Cocoa-related libs require 10.13 features, QEMU 7 uses a definition
    # from the 10.14 SDK when compiled with clang 14 and there's no need to use
    # the VM on MacOS <10.14 anyway:
    # MACOSX_DEPLOYMENT_TARGET=10.13
    MACOSX_DEPLOYMENT_TARGET=10.14
fi

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
            --disable-auth-pam \
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
            --disable-vnc-sasl \
	    --disable-xen \
	    --smbd=${PREFIX}/bin/smbd || exit 1  # avoid OS SMB, from homebrew

make || exit $?

make check

make install
