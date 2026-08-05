#!/bin/bash
if [ $# -lt 1 ]; then
        echo "Usage: /path/to/install"
        exit 1
fi
local_install_prefix="${1}"
export LEANCRYPTO_CFLAGS="-I$PWD/bundled_leancrypto/install/include"
export LEANCRYPTO_LIBS="$PWD/bundled_leancrypto/install/lib/libleancrypto.a"
export JITTERENTROPY_CFLAGS="-I$PWD/bundled_libjitterentropy/install/include"
export JITTERENTROPY_LIBS="$PWD/bundled_libjitterentropy/install/lib/libjitterentropy.a -lpthread -lrt"
export LDFLAGS="-Wl,-z,relro -Wl,--as-needed -Wl,-z,now"
export CFLAGS="-O2 -flto=auto -ffat-lto-objects -fexceptions -g -grecord-gcc-switches -pipe -Wall -Werror=format-security"
export CXXFLAGS="$CFLAGS"
export FIPS_MODULE_NAME="test"
./configure \
      --build=x86_64-redhat-linux-gnu \
      --host=x86_64-redhat-linux-gnu \
      --program-prefix= \
      --disable-dependency-tracking \
      --prefix=$local_install_prefix \
      --exec-prefix=$local_install_prefix \
      --bindir=$local_install_prefix/bin \
      --sbindir=$local_install_prefix/sbin \
      --sysconfdir=$local_install_prefix/etc \
      --datadir=$local_install_prefix/share \
      --includedir=$local_install_prefix/include \
      --libdir=$local_install_prefix/lib64 \
      --libexecdir=$local_install_prefix/libexec \
      --localstatedir=$local_install_prefix/var \
      --sharedstatedir=$local_install_prefix/var/lib \
      --mandir=$local_install_prefix/share/man \
      --infodir=$local_install_prefix/share/info \
      --enable-fips140-mode \
      --with-fips140-module-name="$FIPS_MODULE_NAME" \
      --with-fips140-module-version=3.8.10 \
      --disable-gost \
      --enable-sha1-support \
      --disable-static \
      --disable-openssl-compatibility \
      --disable-non-suiteb-curves \
      --with-system-priority-file=$local_install_prefix/etc/crypto-policies/back-ends/gnutls.config \
      --with-default-trust-store-pkcs11="pkcs11:" \
      --without-tpm \
      --with-tpm2 \
      --enable-ktls \
      --htmldir=$local_install_prefix/share/doc/manual \
      --with-unbound-root-key-file=$local_install_prefix/var/lib/unbound/root.key \
      --enable-libdane \
      --with-zlib --with-brotli --with-zstd \
      --with-leancrypto \
      --with-jitterentropy \
      --disable-rpath \
      --with-default-priority-string="@SYSTEM"
make
make install
mkdir -p $local_install_prefix/lib64/fipscheck
./lib/fipshmac $local_install_prefix/lib64/libgnutls.so.30 >INSTALLED/lib64/fipscheck/.libgnutls.so.30.hmac
