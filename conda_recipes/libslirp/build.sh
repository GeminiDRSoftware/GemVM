#! /bin/sh

if [ "$OSX_ARCH" ]; then
    # Specify conda-forge ld64 version; without this clang passes it an invalid
    # option when using an SDK older than 10.14:
    ldver=$(ld -v 2>&1 | grep -e "ld64-[0-9]" \
		       | sed -Ee 's|.*ld64-([0-9]+).*|\1|')
    LDFLAGS="-mlinker-version=$ldver $LDFLAGS"
fi

meson --prefix="${PREFIX}" --libdir=lib build
ninja -C build/
ninja -C build/ install
