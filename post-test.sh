#!/bin/bash

if [ $# -lt 2 ]; then
	echo "Usage: /path/to/gnutls-cli /path/to/certtool"
	exit 1
fi

GNUTLSCLI="${1}"
CERTTOOL="${2}"
base_log_name="POST.init"
unset GNUTLS_SKIP_FIPS_INTEGRITY_CHECKS
export GNUTLS_FORCE_FIPS_MODE=1
failed=0

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
	if [ $status = 0 ]; then
		echo "$name"
		echo "$output" | grep -v "$GNUTLSCLI"
	else
		echo "$output" | fail_test "$name"
	fi
	return $status
}

library_software_integrity_test()
{
	local name
	local cmd
	local out
	local status

	name="$1"
	export GNUTLS_FIPS_LOGGING=stderr
	export GNUTLS_FIPS_LOGGING_NAMES="$base_log_name:POST.lib-mac-${name}:SHA256.POST:SHA256.mac"
	cmd='$GNUTLSCLI --fips140-mode 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	status=$?
	if [ $status != 0 ]; then
		printf "TEST FAIL library_software_integrity_test: %s" "$out"
		return 1
	fi
	#
	# Ensure we only see SHA256.*:mac success lines even though all SHA256 tests
	# are now logged.
	#
	printf "%s" "$out" | grep "GNUTLS:.*:SUCCESS" | grep -v -i "GNUTLS:.*SHA256\..*:[^m][^a][^c].*"
	return 0
}

printf "Software library integrity tests\n"
printf "================================\n\n"

for name in "gnutls" "nettle" "hogweed" "gmp"
do
	testit "Library software integrity test for $name" library_software_integrity_test "$name" || failed=$((failed+1))
	echo ""
done

generic_kat_test()
{
	local name
	local subname
	local filter_out
	local cmd
	local out
	local status

	name="$1"
	subname="$2"
	filter_out="$3"
	export GNUTLS_FIPS_LOGGING=stderr
	export GNUTLS_FIPS_LOGGING_NAMES="$base_log_name:${name}.POST:${name}.${subname}"
	cmd='$GNUTLSCLI --fips140-mode 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	status=$?
	if [ $status != 0 ]; then
		printf "TEST FAIL generic_kat_test: %s" "$out"
		return 1
	fi
	# Were there any "FAILED" lines ?
	printf "%s" "$out" | grep "GNUTLS:.*:FAILED"
	status=$?
	if [ $status = 0 ]; then
		printf "TEST FAIL generic_kat_test: %s" "$out"
		return 1
	fi
	# Remove duplicate lines
	out=$(eval 'echo "$out" | cat -n | sort -uk2 | sort -nk1 | cut -f2-')
	#
	# Remove any unrealated name.POST messages.
	#
	if [ "${subname}" != "*" ]; then
		if [ "${filter_out}" != "" ]; then
			printf "%s" "$out" | grep "GNUTLS:.*:SUCCESS" | grep -i -e "POST.init" -e "${name}.${subname}" -e "${name}.POST:${subname}" | grep -v "${filter_out}"
		else
			printf "%s" "$out" | grep "GNUTLS:.*:SUCCESS" | grep -i -e "POST.init" -e "${name}.${subname}" -e "${name}.POST:${subname}"
		fi
	else
		if [ "${filter_out}" != "" ]; then
			printf "%s" "$out" | grep "GNUTLS:.*:SUCCESS" | grep -v "${filter_out}"
		else
			printf "%s" "$out" | grep "GNUTLS:.*:SUCCESS"
		fi
	fi
	return 0
}

printf "Cipher KAT tests\n"
printf "================\n\n"

cipher_tests=("AES-128-CBC" "AES-192-CBC" "AES-256-CBC"
		"AES-128-GCM" "AES-192-GCM" "AES-256-GCM"
		"AES-256-XTS" "AES-256-CFB8")

for name in "${cipher_tests[@]}"
do
	testit "Cipher KAT test for $name" generic_kat_test "$name" "cipher" "'duplicate_aes_key'" || failed=$((failed+1))
	echo ""
done

printf "Duplicate key KAT test\n"
printf "======================\n\n"

testit "Duplicate key KAT test for AES-256-XTS" generic_kat_test "AES-256-XTS" "cipher" "'encrypt\|decrypt'" || failed=$((failed+1))
echo ""

printf "Digest KAT tests\n"
printf "================\n\n"

digest_tests=("SHA3-224" "SHA3-256" "SHA3-384" "SHA3-512")
for name in "${digest_tests[@]}"
do
	testit "Digest KAT test for $name" generic_kat_test "$name" "digest" "" || failed=$((failed+1))
	echo ""
done

printf "MAC KAT tests\n"
printf "=============\n\n"

mac_tests=("SHA1" "SHA224" "SHA256" "SHA384" "SHA512" "AES-CMAC-256")
for name in "${mac_tests[@]}"
do
	testit "MAC KAT test for $name" generic_kat_test "$name" "mac" "" || failed=$((failed+1))
	echo ""
done

printf "Public key KAT tests\n"
printf "====================\n\n"

pk_tests=("ECDH" "DH" "RSA" "EC/ECDSA")
for name in "${pk_tests[@]}"
do
	testit "Public Key KAT test for $name" generic_kat_test "$name" '"*"' "" || failed=$((failed+1))
	echo ""
done

printf "Random generator KAT tests\n"
printf "==========================\n\n"

rand_tests=("DRBG-AES")
for name in "${rand_tests[@]}"
do
	testit "Random generator KAT test for $name" generic_kat_test "$name" '"*"' "" || failed=$((failed+1))
	echo ""
done

printf "Key derivation KAT tests\n"
printf "========================\n\n"

kdf_tests=("SHA256")
for name in "${kdf_tests[@]}"
do
	testit "Key derivation KAT test for $name" generic_kat_test "$name" "hkdf" "" || failed=$((failed+1))
	echo ""
	testit "Key derivation password-based-2 KAT test for $name" generic_kat_test "$name" "pbkdf2" "" || failed=$((failed+1))
	echo ""
done

printf "TLS 1.2/1.3 KAT tests\n"
printf "=====================\n\n"

testit "TLS1.2 KAT test" generic_kat_test "TLS1_2" "TLS1_2-PRF" "" || failed=$((failed+1))
echo ""

testit "TLS1.3 KAT test" generic_kat_test "TLS1_3" "TLS1_3-PRF" "" || failed=$((failed+1))
echo ""

printf "Starting PCT tests (this can take a while)\n"
printf "==========================================\n\n"

certtool_pct_test()
{
	local name
	local cmd
	local out
	local status
	local extra_certtool_args

	name="$1"
	export GNUTLS_FIPS_LOGGING=stderr
	#
	# Trick we need as certtool uses ECDSA on the command line
	# but the internal library name is EC/ECDSA.
	#
	extra_certtool_args=""
	if [ "$name" = "ECDSA" ]; then
		export GNUTLS_FIPS_LOGGING_NAMES="$base_log_name:EC/ECDSA.PCT"
		extra_certtool_args="--curve=SECP521R1"
	elif [ "$name" = "ECDH" ]; then
		#
		# Trick we need as ECDH PCT test uses ECDSA with a specific curve.
		#
		export GNUTLS_FIPS_LOGGING_NAMES="$base_log_name:${name}.PCT"
		extra_certtool_args="--curve=SECP256R1"
		# And use ECDSA for certtool.
		name="ECDSA"
	else
		export GNUTLS_FIPS_LOGGING_NAMES="$base_log_name:${name}.PCT"
	fi
	cmd='$CERTTOOL -p ${extra_certtool_args} --key-type=${name} 2>&1 1>/dev/null'
	eval echo "$cmd"
	out=$(eval "$cmd")
	status=$?
	if [ $status != 0 ]; then
		printf "TEST FAIL certtool_pct_test: %s" "$out"
		return 1
	fi
	printf "%s" "$out" | grep "GNUTLS:.*:SUCCESS"
	return 0
}

certtool_tests=("ECDH" "ECDSA" "RSA")
for name in "${certtool_tests[@]}"
do
	testit "PCT test for $name" certtool_pct_test "$name" || failed=$((failed+1))
	echo ""
done

benchmark_pct_test()
{
	local name
	local cmd
	local out
	local status

	name="$1"
	export GNUTLS_FIPS_LOGGING=stderr
	export GNUTLS_FIPS_LOGGING_NAMES="$base_log_name:${name}.PCT"
	cmd='$GNUTLSCLI --benchmark-tls-kx 2>&1 1>/dev/null | cat -n | sort -uk2 | sort -nk1 | cut -f2-'
	eval echo "$cmd"
	out=$(eval "$cmd")
	status=$?
	if [ $status != 0 ]; then
		printf "TEST FAIL benchmark_pct_test: %s" "$out"
		return 1
	fi
	printf "%s" "$out" | grep "GNUTLS:.*:SUCCESS"
	return 0
}

benchmark_tests=("DH")
for name in "${benchmark_tests[@]}"
do
	testit "PCT test for $name" benchmark_pct_test "$name" || failed=$((failed+1))
	echo ""
done

exit $failed
