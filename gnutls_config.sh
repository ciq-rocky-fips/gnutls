#!/bin/bash
if [ $# -lt 1 ]; then
        echo "Usage: /path/to/install"
        exit 1
fi
local_install_prefix="${1}"

#Uncomment the two below for a debug build.
#export CFLAGS=-g
#export CXXFLAGS=-g
autoreconf -fi

./configure --build=x86_64-redhat-linux-gnu \
	--host=x86_64-redhat-linux-gnu \
	--program-prefix= --disable-dependency-tracking \
	--prefix=$local_install_prefix \
	--exec-prefix=$local_install_prefix \
	--bindir=$local_install_prefix/bin \
	--sbindir=$local_install_prefix/sbin \
	--sysconfdir=$local_install_prefix/etc \
	--datadir=$local_install_prefix/share \
	--includedir=$local_install_prefix/include \
	--libdir=$local_install_prefix/usr/lib64 \
	--libexecdir=$local_install_prefix/libexec \
	--localstatedir=$local_install_prefix/var \
	--sharedstatedir=$local_install_prefix/var/lib \
	--mandir=$local_install_prefix/share/man \
	--infodir=$local_install_prefix/share/info \
	--enable-fips140-mode \
	--with-fips140-module-name= \
	--with-fips140-module-version=1.0-f7641ffb9a8fb7aa \
	--enable-sha1-support \
	--disable-gost \
	--disable-static \
	--disable-openssl-compatibility \
	--disable-non-suiteb-curves \
	--with-system-priority-file=$local_install_prefix/etc/crypto-policies/back-ends/gnutls.config \
	--with-default-trust-store-pkcs11=pkcs11: \
	--with-trousers-lib=/usr/lib64/libtspi.so.1 \
	--htmldir=$local_install_prefix/share/doc/manual \
	--disable-guile \
	--with-unbound-root-key-file=$local_install_prefix/var/lib/unbound/root.key \
	--enable-dane \
	--disable-rpath \
	--with-default-priority-string=@SYSTEM
