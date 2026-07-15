export LDFLAGS="-Wl,-z,relro -Wl,--as-needed -Wl,-z,now"
export CFLAGS="-O2 -flto=auto -ffat-lto-objects -fexceptions -g -grecord-gcc-switches -pipe -Wall -Werror=format-security"
export CXXFLAGS="$CFLAGS"
meson setup \
	-Dprefix="$PWD/install" \
	-Dlibdir="$PWD/install/lib" \
	-Ddefault_library=static \
	-Dascon=disabled \
	-Dascon_keccak=disabled \
	-Dbike_5=disabled \
	-Dbike_3=disabled \
	-Dbike_1=disabled \
	-Dkyber_x25519=disabled \
	-Ddilithium_ed25519=disabled \
	-Dx509_parser=disabled \
	-Dx509_generator=disabled \
	-Dpkcs7_parser=disabled \
	-Dpkcs7_generator=disabled \
	-Dsha2-256=disabled \
	-Dchacha20=disabled \
	-Dchacha20_drng=disabled \
	-Ddrbg_hash=disabled \
	-Ddrbg_hmac=disabled \
	-Dhash_crypt=disabled \
	-Dhmac=disabled \
	-Dhkdf=disabled \
	-Dkdf_ctr=disabled \
	-Dkdf_fb=disabled \
	-Dkdf_dpi=disabled \
	-Dpbkdf2=disabled \
	-Dkmac_drng=disabled \
	-Dcshake_drng=disabled \
	-Dhotp=disabled \
	-Dtotp=disabled \
	-Daes_block=disabled \
	-Daes_cbc=disabled \
	-Daes_ctr=disabled \
	-Daes_kw=disabled \
	-Dapps=disabled _build
meson compile -v -C _build
meson install -C _build
