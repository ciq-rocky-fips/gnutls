#!/bin/bash

if [ $# -lt 2 ]; then
	echo "Usage: /path/to/gnutls-cli /path/to/certtool"
	exit 1
fi

#
# Hmmm. Check if we are root or just fail on the mv failure ?
#
#is_root=$(eval "id 2>&1 |sed -e 's/\(^uid=0(root)\).*/\1/g'")
#if [ "$is_root" != "uid=0(root)" ]; then
#	printf "TEST FAIL. Must be run as root credentials\n"
#	exit 1
#fi

GNUTLSCLI="${1}"
CERTTOOL="${2}"
base_log_name="POST.init"
failed=0
unset GNUTLS_SKIP_FIPS_INTEGRITY_CHECKS
export GNUTLS_FORCE_FIPS_MODE=1

fail_test()
{
	printf 'Failed: %s [\n' "$1"
	cat -
	echo "]"
}

testit()
{
	local name
	local cmdline_args
	local fn_test
	local output
	local status

	name="$1"
	shift
	fn_test="$1"
	shift
	cmdline_args="$@"
	output=$(eval "${fn_test} ${cmdline_args} 2>&1")
	status=$?
	if [ $status -eq 0 ]; then
		echo "$name"
		echo "$output" | grep -v "$GNUTLSCLI"
	else
		echo "$output" | fail_test "$name"
	fi
	return $status
}

get_abs_library_path()
{
	local name
	local ldd_out
	local rel_path_name
	local abs_path_name
	local status

	name="$1"

	# Get the pathname of the $name shared library.
	ldd_out=$(eval "ldd $GNUTLSCLI")
	status=$?
	if [ $status -ne 0 ]; then
		printf "TEST FAIL ld of %s failed with exit code %d\n" "$GNUTLSCLI" "$status"
		return 1
	fi

	rel_path_name=$(echo "$ldd_out" | grep lib${name}.so | sed -e 's/^.*=> \([^ ]*\).*$/\1/g')
	#
	# Resolve all sybolic links
	abs_path_name=$(realpath -e "$rel_path_name")
	status=$?
	if [ $status -ne 0 ]; then
		printf "realpath -e "$rel_path_name" failed\n"
		return 1
	fi
	printf "$abs_path_name"
	return 0;
}

save_orig_library_path()
{
	local name
	local abs_path_name
	local status
	local sum_orig
	local sum_copy
	name="$1"

	# Get the pathname of the $name shared library.
	abs_path_name=$(eval "get_abs_library_path $name")
	status=$?
	if [ $status -ne 0 ]; then
		printf "get_abs_library_path $name failed: $abs_path_name\n"
		return 1
	fi
#
#	Now do the rename. First move the original file.
#
	mv -f "${abs_path_name}" "${abs_path_name}.fips_fail_test_bak"
	status=$?
	if [ $status -ne 0 ]; then
		printf "mv -f ${abs_path_name} ${abs_path_name}.fips_fail_test_bak failed\n"
		printf "This script must be run as root in order to modify system libraries\n"
		return 1
	fi
#
#	Now make a copy under the original name.
#	WARNING. IF THIS FAILS SYSTEM MAY BE IN AN INCONSISTENT STATE !!!!!
#
	cp -a -n "${abs_path_name}.fips_fail_test_bak" "${abs_path_name}"
	status=$?
	if [ $status -ne 0 ]; then
		printf "cp -a -n ${abs_path_name}.fips_fail_test_bak ${abs_path_name} failed\n"
		printf "SYSTEM IN INCONSISTENT STATE. REPAIR BY HAND !!!!!\n"
		exit 1
	fi
#
# Ensure files are identical
#
	sum_orig=$(eval "sha512hmac ${abs_path_name}.fips_fail_test_bak | cut -d ' ' -f1")
	sum_copy=$(eval "sha512hmac ${abs_path_name} | cut -d ' ' -f1")
	if [ "$sum_orig" != "$sum_copy" ]; then
		printf "sha512hmac of ${abs_path_name}.fips_fail_test_bak and ${abs_path_name} are not identical\n"
		printf "SYSTEM IN INCONSISTENT STATE. REPAIR BY HAND !!!!!\n"
		exit 1
	fi
	return 0;
}

restore_orig_library_path()
{
	local name
	local abs_path_name
	local status

	name="$1"

	# Get the pathname of the $name shared library.
	abs_path_name=$(eval "get_abs_library_path $name")
	status=$?
	if [ $status -ne 0 ]; then
		printf "get_abs_library_path $name failed: $abs_path_name\n"
		return 1
	fi
#
#	Replace the original file. Both original and destination
#	MUST already exist.
#
	if [ ! -f "${abs_path_name}" ]; then
		printf "${abs_path_name} DOES NOT EXIST.\n"
		printf "SYSTEM IN INCONSISTENT STATE. REPAIR BY HAND !!!!!\n"
		exit 1
	fi
	if [ ! -f "${abs_path_name}.fips_fail_test_bak" ]; then
		printf "${abs_path_name}.fips_fail_test_bak DOES NOT EXIST\n"
		printf "SYSTEM IN INCONSISTENT STATE. REPAIR BY HAND !!!!!\n"
		exit 1
	fi
	mv -f "${abs_path_name}.fips_fail_test_bak" "${abs_path_name}"
	status=$?
	if [ $status -ne 0 ]; then
		printf "mv -f ${abs_path_name}.fips_fail_test_bak ${abs_path_name} failed\n"
		printf "SYSTEM IN INCONSISTENT STATE. REPAIR BY HAND !!!!!\n"
		return 1
	fi
	return 0;
}

inject_fail_library_software_integrity_test()
{
	local name
	local cmd
	local out
	local save_status
	local restore_status
	local status

	name="$1"
	export GNUTLS_FIPS_LOGGING=stderr
	export GNUTLS_FIPS_LOGGING_NAMES="$base_log_name:POST.lib-mac:POST.lib-mac-${name}:SHA256.POST:SHA256.mac"
	export GNUTLS_FIPS_FAIL_TESTS="CHECK_LIB_HMAC.${name}"
	save_orig_library_path "$name"
	save_status=$?
	if [ $save_status -ne 0 ]; then
		printf "TEST FAIL inject_fail_library_software_integrity_test - unable to save library\n"
		exit 1
	fi
	cmd='$GNUTLSCLI --fips140-mode 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	status=$?
	restore_orig_library_path "$name"
	restore_status=$?
	if [ $restore_status -ne 0 ]; then
		printf "TEST FAIL inject_fail_library_software_integrity_test - unable to restore library\n"
		exit 1
	fi
	if [ $status -eq 0 ]; then
		printf "TEST FAIL inject_fail_library_software_integrity_test: %s" "$out"
		return 1
	fi
	#
	# Remove any :SUCCESS lines from library macs not currently being tested.
	#
	printf "%s" "$out" | grep -v "GNUTLS:.*POST.lib-mac:.*:SUCCESS" | grep -v -i "GNUTLS:.*SHA256\..*:[^m][^a][^c].*:SUCCESS"
	return 0
}

printf "Inject fail library software integrity tests\n"
printf "============================================\n\n"

for name in "gnutls" "nettle" "hogweed" "gmp"
do
	testit "Inject fail library software integrity test for $name" inject_fail_library_software_integrity_test "$name" || failed=$((failed+1))
	echo ""
	#
	# Fail early if any library software integrity tests failed.
	#
	if [ "$failed" -ne 0 ]; then
		exit 1
	fi
done

generic_kat_fail_test()
{
	local name
	local type_arg
	local fail_operation
	local filter_out
	local cmd
	local out
	local status

	name="$1"
	type_arg="$2"
	fail_operation="$3"
	filter_out="$4"
	export GNUTLS_FIPS_LOGGING=stderr
	export GNUTLS_FIPS_LOGGING_NAMES="$base_log_name:${name}.POST:${name}.${type_arg}:${name}.${fail_operation}"
	#
	# Cheat to get all the correct failure modes for encrypt/decrypt.
	#
	export GNUTLS_FIPS_FAIL_TESTS="${name}.${fail_operation}"
	if [ "${fail_operation}" = "encrypt" ]; then
		export GNUTLS_FIPS_FAIL_TESTS="${name}.${fail_operation}:${name}.encrypt-aead"
	elif [ "${fail_operation}" = "decrypt" ]; then
		export GNUTLS_FIPS_FAIL_TESTS="${name}.${fail_operation}:${name}.decrypt-aead"
	fi
	cmd='$GNUTLSCLI --fips140-mode 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	status=$?
	if [ $status -eq 0 ]; then
		printf "TEST FAILED generic_kat_fail_test: %s" "$out"
		return 1
	fi
	#
	# Remove any :SUCCESS lines from names and operations not currently being tested for failure.
	#
	if [ "${filter_out}" = "" ]; then
		printf "%s" "$out" | grep -v "GNUTLS:.*${name}.${type_arg}:.*:SUCCESS"
	else
		printf "%s" "$out" | grep -v "GNUTLS:.*${name}.${type_arg}:.*:SUCCESS" | grep -v "${filter_out}"
	fi
	return 0
}

printf "Inject fail encrypt/decrypt cipher KAT tests\n"
printf "============================================\n\n"

cipher_tests=("AES-128-CBC" "AES-192-CBC" "AES-256-CBC"
		"AES-128-GCM" "AES-192-GCM" "AES-256-GCM"
		"AES-256-XTS" "AES-256-CFB8")

for name in "${cipher_tests[@]}"
do
	testit "Cipher encrypt fail KAT test for $name" generic_kat_fail_test "$name" "cipher" "encrypt" "" || failed=$((failed+1))
	echo ""
	testit "Cipher decrypt fail KAT test for $name" generic_kat_fail_test "$name" "cipher" "decrypt" "" || failed=$((failed+1))
	echo ""
done

printf "Inject fail duplicate key KAT test\n"
printf "==================================\n\n"

testit "Cipher duplicate key fail KAT test for AES-256-XTS" generic_kat_fail_test "AES-256-XTS" "cipher" "duplicate_aes_key" "" || failed=$((failed+1))
echo ""

printf "Inject fail digest KAT tests\n"
printf "============================\n\n"

digest_tests=("SHA3-224" "SHA3-256" "SHA3-384" "SHA3-512")
for name in "${digest_tests[@]}"
do
	testit "Digest fail KAT test for $name" generic_kat_fail_test "$name" "digest" "digest" "" || failed=$((failed+1))
	echo ""
done

printf "Inject fail MAC KAT tests\n"
printf "=========================\n\n"

mac_tests=("SHA1" "SHA224" "SHA256" "SHA384" "SHA512" "AES-CMAC-256")
for name in "${mac_tests[@]}"
do
	testit "MAC fail KAT test for $name" generic_kat_fail_test "$name" "mac" "hmac" "" || failed=$((failed+1))
	echo ""
done

printf "Inject fail public key KAT tests\n"
printf "================================\n\n"

#
# These are so custom we need to do individual tests.
#
# First ECDH.
#
testit "Public Key derivation fail KAT test for ECDH" generic_kat_fail_test "ECDH" "shared-secret-computation" "ecdh_derive" "" || failed=$((failed+1))
echo ""

#
# Next DH.
#
testit "Public Key derivation fail KAT test for DH" generic_kat_fail_test "DH" "shared-secret-computation" "dh_derive" "" || failed=$((failed+1))
echo ""

#
# Next RSA.
#
testit "Public Key sign known key fail KAT test for RSA" generic_kat_fail_test "RSA" "sign" "sign_known_sig" "" || failed=$((failed+1))
echo ""
testit "Public Key verify known key fail KAT test for RSA" generic_kat_fail_test "RSA" "verify" "verify_known_sig" "" || failed=$((failed+1))
echo ""

#
# Next EC/ECDSA
#
testit "Public Key sign known key fail KAT test for EC/ECDSA" generic_kat_fail_test "EC/ECDSA" "sign" "sign_known_sig" "" || failed=$((failed+1))
echo ""
testit "Public Key sign fail KAT test for EC/ECDSA" generic_kat_fail_test "EC/ECDSA" "sign" "verify" "'known.*sig'" || failed=$((failed+1))
echo ""
testit "Public Key verify fail KAT test for EC/ECDSA" generic_kat_fail_test "EC/ECDSA" "verify" "verify" "'known.*sig'" || failed=$((failed+1))
echo ""

printf "Inject fail DRBG KAT tests\n"
printf "==========================\n\n"

testit "Generate fail KAT test for DRBG-AES entropy" generic_kat_fail_test "DRBG-AES" "entropy" "entropy" "" || failed=$((failed+1))
echo ""
testit "Generate fail KAT test for DRBG-AES random-large-size" generic_kat_fail_test "DRBG-AES" "random" "random-large-size" "" || failed=$((failed+1))
echo ""
testit "Generate fail KAT test for DRBG-AES generate-large-size" generic_kat_fail_test "DRBG-AES" "generate" "generate-large-size" "" || failed=$((failed+1))
echo ""
testit "Generate fail KAT test for DRBG-AES reseed-detect" generic_kat_fail_test "DRBG-AES" "reseed-detect" "reseed-detect" "" || failed=$((failed+1))
echo ""
testit "Generate fail KAT test for DRBG-AES reseed-count" generic_kat_fail_test "DRBG-AES" "reseed-count" "reseed-count" "" || failed=$((failed+1))
echo ""

printf "Key derivation fail KAT tests for SHA256\n"
printf "========================================\n\n"

testit "Key derivation extract fail KAT test for SHA256" generic_kat_fail_test "SHA256" "hkdf" "hkdf-extract" "'mac test'" || failed=$((failed+1))
echo ""
testit "Key derivation expand fail KAT test for SHA256" generic_kat_fail_test "SHA256" "hkdf" "hkdf-expand" "'mac test'" || failed=$((failed+1))
echo ""
testit "Key derivation password-based-2 fail KAT test for SHA256" generic_kat_fail_test "SHA256" "pbkdf2" "pbkdf2" "'hkdf test\|mac test'" || failed=$((failed+1))
echo ""

printf "TLS 1.2/1.3 fail KAT tests\n"
printf "==========================\n\n"

testit "TLS 1.2 fail KAT test" generic_kat_fail_test "TLS1_2" "TLS1_2-PRF" "TLS1_2-PRF" "" || failed=$((failed+1))
echo ""

testit "TLS 1.3 fail KAT test" generic_kat_fail_test "TLS1_3" "TLS1_3-PRF" "TLS1_3-PRF" "" || failed=$((failed+1))
echo ""

printf "Starting PCT tests (this can take a while)\n"
printf "==========================================\n\n"

certtool_pct_fail_test()
{
	local name
	local fail_operation
	local filter_out
	local cmd
	local out
	local status
	local extra_certtool_args

	name="$1"
	fail_operation="$2"
	filter_out="$3"
	export GNUTLS_FIPS_LOGGING=stderr
	#
	# Trick we need as certtool uses ECDSA on the command line
	# but the internal library name is EC/ECDSA.
	#
	if [ "$name" = "ECDSA" ]; then
		export GNUTLS_FIPS_LOGGING_NAMES="$base_log_name:EC/ECDSA.PCT"
		export GNUTLS_FIPS_FAIL_TESTS="EC/ECDSA.${fail_operation}"
		extra_certtool_args="--curve=SECP521R1"
	elif [ "$name" = "ECDH" ]; then
		#
		# Trick we need as ECDH PCT test uses ECDSA with a specific curve.
		#
		export GNUTLS_FIPS_LOGGING_NAMES="$base_log_name:${name}.PCT"
		export GNUTLS_FIPS_FAIL_TESTS="ECDH.${fail_operation}"
		extra_certtool_args="--curve=SECP256R1"
		# And use ECDSA for certtool.
		name="ECDSA"
	else
		export GNUTLS_FIPS_LOGGING_NAMES="$base_log_name:${name}.PCT"
		export GNUTLS_FIPS_FAIL_TESTS="${name}.${fail_operation}"
	fi
	cmd='$CERTTOOL -p ${extra_certtool_args} --key-type=${name} 2>&1 1>/dev/null'
	eval echo "$cmd"
	out=$(eval "$cmd")
	status=$?
	if [ $status -eq 0 ]; then
		printf "TEST FAILED certtool_pct_fail_test: %s" "$out"
		return 1
	fi
	# Tidy up output so we only see test results.
	if [ "${filter_out}" = "" ]; then
		printf "%s" "$out" | grep -v "Generating a" | grep -v "Note that DSA keys" | grep -v -e '^$'
	else
		printf "%s" "$out" | grep -v "Generating a" | grep -v "Note that DSA keys" | grep -v -e '^$' | grep -v "${filter_out}"
	fi
	return 0
}

testit "PCT verify fail test for ECDH" certtool_pct_fail_test "ECDH" "pct-verify" "" || failed=$((failed+1))
echo ""

testit "PCT verify fail test for ECDSA" certtool_pct_fail_test "ECDSA" "pct-verify" "" || failed=$((failed+1))
echo ""

testit "PCT verify fail test for RSA" certtool_pct_fail_test "RSA" "pct-verify" "" || failed=$((failed+1))
echo ""

benchmark_pct_fail_test()
{
	local name
	local fail_operation
	local cmd
	local out
	local status

	name="$1"
	fail_operation="$2"
	export GNUTLS_FIPS_LOGGING=stderr
	export GNUTLS_FIPS_LOGGING_NAMES="$base_log_name:${name}.PCT"
	export GNUTLS_FIPS_FAIL_TESTS="${name}.${fail_operation}"
	cmd='$GNUTLSCLI --benchmark-tls-kx 2>&1 1>/dev/null'
	eval echo "$cmd"
	out=$(eval "$cmd")
	status=$?
	if [ $status -eq 0 ]; then
		printf "TEST FAILED benchmark_pct_fail_test: %s" "$out"
		return 1
	fi
	out=$(eval 'echo "$out" | cat -n | sort -uk2 | sort -nk1 | cut -f2-')
	# Tidy up output so we only see test results.
	printf "%s" "$out" | grep -v -e '^$' | grep -v 'server' | grep -v "Handshake failed"
	return 0
}

testit "PCT fail test for DH" benchmark_pct_fail_test "DH" "pct-generation" || failed=$((failed+1))
echo ""

exit $failed
