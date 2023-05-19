/*
 * Copyright (C) 2013-2018 Red Hat
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#include "gnutls_int.h"
#include "errors.h"
#include <cipher_int.h>
#include <datum.h>
#include <gnutls/crypto.h>
#include <gnutls/self-test.h>
#include "errors.h"
#include <random.h>
#include <crypto.h>
#include <nettle/sha2.h>
#include <nettle/sha3.h>

#include "fipslog.h"

#define STR(tag, tag_size, val) \
	.tag = (uint8_t*)val, \
	.tag_size = (sizeof(val)-1)

#define V(x) (x), (sizeof(x)/sizeof(x[0]))

/* This does check the AES and SHA implementation against test vectors.
 * This should not run under valgrind in order to use the native
 * cpu instructions (AES-NI or padlock).
 */

struct cipher_vectors_st {
	const uint8_t *key;
	unsigned int key_size;

	const uint8_t *plaintext;
	unsigned int plaintext_size;
	const uint8_t *ciphertext;	/* also of plaintext_size */

	const uint8_t *iv;
	unsigned int iv_size;

	const uint8_t *internal_iv;
	unsigned int internal_iv_size;
};

struct cipher_aead_vectors_st {
	unsigned compat_apis;
	const uint8_t *key;
	unsigned int key_size;

	const uint8_t *auth;
	unsigned int auth_size;

	const uint8_t *plaintext;
	unsigned int plaintext_size;
	const uint8_t *ciphertext;	/* also of plaintext_size */

	unsigned int iv_size;
	const uint8_t *iv;
	const uint8_t *tag;
	unsigned tag_size;
	unsigned tag_prepended;
};

const struct cipher_aead_vectors_st chacha_poly1305_vectors[] = {
	{
	 .compat_apis = 1,
	 STR(key, key_size,
	     "\x1c\x92\x40\xa5\xeb\x55\xd3\x8a\xf3\x33\x88\x86\x04\xf6\xb5\xf0\x47\x39\x17\xc1\x40\x2b\x80\x09\x9d\xca\x5c\xbc\x20\x70\x75\xc0"),
	 .auth = (void*)"\xf3\x33\x88\x86\x00\x00\x00\x00\x00\x00\x4e\x91",
	 .auth_size = 12,
	 .plaintext = (void*)"\x49\x6e\x74\x65\x72\x6e\x65\x74\x2d\x44\x72\x61\x66\x74\x73\x20\x61\x72\x65\x20\x64\x72\x61\x66\x74\x20\x64\x6f\x63\x75\x6d\x65\x6e\x74\x73\x20\x76\x61\x6c\x69\x64\x20\x66\x6f\x72\x20\x61\x20\x6d\x61\x78\x69\x6d\x75\x6d\x20\x6f\x66\x20\x73\x69\x78\x20\x6d\x6f\x6e\x74\x68\x73\x20\x61\x6e\x64\x20\x6d\x61\x79\x20\x62\x65\x20\x75\x70\x64\x61\x74\x65\x64\x2c\x20\x72\x65\x70\x6c\x61\x63\x65\x64\x2c\x20\x6f\x72\x20\x6f\x62\x73\x6f\x6c\x65\x74\x65\x64\x20\x62\x79\x20\x6f\x74\x68\x65\x72\x20\x64\x6f\x63\x75\x6d\x65\x6e\x74\x73\x20\x61\x74\x20\x61\x6e\x79\x20\x74\x69\x6d\x65\x2e\x20\x49\x74\x20\x69\x73\x20\x69\x6e\x61\x70\x70\x72\x6f\x70\x72\x69\x61\x74\x65\x20\x74\x6f\x20\x75\x73\x65\x20\x49\x6e\x74\x65\x72\x6e\x65\x74\x2d\x44\x72\x61\x66\x74\x73\x20\x61\x73\x20\x72\x65\x66\x65\x72\x65\x6e\x63\x65\x20\x6d\x61\x74\x65\x72\x69\x61\x6c\x20\x6f\x72\x20\x74\x6f\x20\x63\x69\x74\x65\x20\x74\x68\x65\x6d\x20\x6f\x74\x68\x65\x72\x20\x74\x68\x61\x6e\x20\x61\x73\x20\x2f\xe2\x80\x9c\x77\x6f\x72\x6b\x20\x69\x6e\x20\x70\x72\x6f\x67\x72\x65\x73\x73\x2e\x2f\xe2\x80\x9d",
	 .plaintext_size = 265,
	 .ciphertext = (void*)"\x64\xa0\x86\x15\x75\x86\x1a\xf4\x60\xf0\x62\xc7\x9b\xe6\x43\xbd\x5e\x80\x5c\xfd\x34\x5c\xf3\x89\xf1\x08\x67\x0a\xc7\x6c\x8c\xb2\x4c\x6c\xfc\x18\x75\x5d\x43\xee\xa0\x9e\xe9\x4e\x38\x2d\x26\xb0\xbd\xb7\xb7\x3c\x32\x1b\x01\x00\xd4\xf0\x3b\x7f\x35\x58\x94\xcf\x33\x2f\x83\x0e\x71\x0b\x97\xce\x98\xc8\xa8\x4a\xbd\x0b\x94\x81\x14\xad\x17\x6e\x00\x8d\x33\xbd\x60\xf9\x82\xb1\xff\x37\xc8\x55\x97\x97\xa0\x6e\xf4\xf0\xef\x61\xc1\x86\x32\x4e\x2b\x35\x06\x38\x36\x06\x90\x7b\x6a\x7c\x02\xb0\xf9\xf6\x15\x7b\x53\xc8\x67\xe4\xb9\x16\x6c\x76\x7b\x80\x4d\x46\xa5\x9b\x52\x16\xcd\xe7\xa4\xe9\x90\x40\xc5\xa4\x04\x33\x22\x5e\xe2\x82\xa1\xb0\xa0\x6c\x52\x3e\xaf\x45\x34\xd7\xf8\x3f\xa1\x15\x5b\x00\x47\x71\x8c\xbc\x54\x6a\x0d\x07\x2b\x04\xb3\x56\x4e\xea\x1b\x42\x22\x73\xf5\x48\x27\x1a\x0b\xb2\x31\x60\x53\xfa\x76\x99\x19\x55\xeb\xd6\x31\x59\x43\x4e\xce\xbb\x4e\x46\x6d\xae\x5a\x10\x73\xa6\x72\x76\x27\x09\x7a\x10\x49\xe6\x17\xd9\x1d\x36\x10\x94\xfa\x68\xf0\xff\x77\x98\x71\x30\x30\x5b\xea\xba\x2e\xda\x04\xdf\x99\x7b\x71\x4d\x6c\x6f\x2c\x29\xa6\xad\x5c\xb4\x02\x2b\x02\x70\x9b",
	 STR(iv, iv_size,
	     "\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08"),
	 .tag_size = 16,
	 .tag = (void *)
	 "\xee\xad\x9d\x67\x89\x0c\xbb\x22\x39\x23\x36\xfe\xa1\x85\x1f\x38"},
};

const struct cipher_aead_vectors_st aes128_gcm_vectors[] = {
	{
	 .compat_apis = 1,
	 STR(key, key_size,
	     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	 .auth = NULL,
	 .auth_size = 0,
	 .plaintext = NULL,
	 .plaintext_size = 0,
	 .ciphertext = NULL,
	 STR(iv, iv_size,
	     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	 .tag_size = 16,
	 .tag = (void *)
	 "\x58\xe2\xfc\xce\xfa\x7e\x30\x61\x36\x7f\x1d\x57\xa4\xe7\x45\x5a"},
	{
	 .compat_apis = 1,
	 STR(key, key_size,
	     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	 .auth = NULL,
	 .auth_size = 0,
	 STR(plaintext, plaintext_size,
	     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	 .ciphertext = (void *)
	 "\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78",
	 STR(iv, iv_size,
	     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	 .tag_size = 16,
	 .tag = (void *)
	 "\xab\x6e\x47\xd4\x2c\xec\x13\xbd\xf5\x3a\x67\xb2\x12\x57\xbd\xdf"},
	{
	 .compat_apis = 1,
	 STR(key, key_size,
	     "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"),
	 .auth = (void *)
	 "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\xab\xad\xda\xd2",
	 .auth_size = 20,
	 STR(plaintext, plaintext_size,
	     "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39"),
	 .ciphertext = (void *)
	 "\x42\x83\x1e\xc2\x21\x77\x74\x24\x4b\x72\x21\xb7\x84\xd0\xd4\x9c\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0\x35\xc1\x7e\x23\x29\xac\xa1\x2e\x21\xd5\x14\xb2\x54\x66\x93\x1c\x7d\x8f\x6a\x5a\xac\x84\xaa\x05\x1b\xa3\x0b\x39\x6a\x0a\xac\x97\x3d\x58\xe0\x91",
	 STR(iv, iv_size,
	     "\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88"),
	 .tag_size = 16,
	 .tag = (void *)
	 "\x5b\xc9\x4f\xbc\x32\x21\xa5\xdb\x94\xfa\xe9\x5a\xe7\x12\x1a\x47"}
};

const struct cipher_aead_vectors_st aes192_gcm_vectors[] = {
	{
	 .compat_apis = 1,
	 STR(key, key_size,
	     "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08\xfe\xff\xe9\x92\x86\x65\x73\x1c"),
	 .auth = NULL,
	 .auth_size = 0,
	 STR(plaintext, plaintext_size,
	     "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39\x1a\xaf\xd2\x55"),
	 .ciphertext =
	 (uint8_t *)
	 "\x39\x80\xca\x0b\x3c\x00\xe8\x41\xeb\x06\xfa\xc4\x87\x2a\x27\x57\x85\x9e\x1c\xea\xa6\xef\xd9\x84\x62\x85\x93\xb4\x0c\xa1\xe1\x9c\x7d\x77\x3d\x00\xc1\x44\xc5\x25\xac\x61\x9d\x18\xc8\x4a\x3f\x47\x18\xe2\x44\x8b\x2f\xe3\x24\xd9\xcc\xda\x27\x10\xac\xad\xe2\x56",
	 STR(iv, iv_size,
	     "\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88"),
	 .tag_size = 16,
	 .tag =
	 (void *)
	 "\x99\x24\xa7\xc8\x58\x73\x36\xbf\xb1\x18\x02\x4d\xb8\x67\x4a\x14"},

};

const struct cipher_aead_vectors_st aes256_gcm_vectors[] = {
	{
	 .compat_apis = 1,
	 STR(key, key_size,
	     "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"),
	 .auth = NULL,
	 .auth_size = 0,
	 STR(plaintext, plaintext_size,
	     "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39\x1a\xaf\xd2\x55"),
	 .ciphertext =
	 (uint8_t *)
	 "\x52\x2d\xc1\xf0\x99\x56\x7d\x07\xf4\x7f\x37\xa3\x2a\x84\x42\x7d\x64\x3a\x8c\xdc\xbf\xe5\xc0\xc9\x75\x98\xa2\xbd\x25\x55\xd1\xaa\x8c\xb0\x8e\x48\x59\x0d\xbb\x3d\xa7\xb0\x8b\x10\x56\x82\x88\x38\xc5\xf6\x1e\x63\x93\xba\x7a\x0a\xbc\xc9\xf6\x62\x89\x80\x15\xad",
	 STR(iv, iv_size,
	     "\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88"),
	 .tag_size = 16,
	 .tag =
	 (void *)
	 "\xb0\x94\xda\xc5\xd9\x34\x71\xbd\xec\x1a\x50\x22\x70\xe3\xcc\x6c"},

};

const struct cipher_aead_vectors_st aes256_ccm_vectors[] = {
	{
	 .compat_apis = 0,
	 STR(key, key_size,
	     "\xfb\x76\x15\xb2\x3d\x80\x89\x1d\xd4\x70\x98\x0b\xc7\x95\x84\xc8\xb2\xfb\x64\xce\x60\x97\x8f\x4d\x17\xfc\xe4\x5a\x49\xe8\x30\xb7"),
	 .auth = NULL,
	 .auth_size = 0,
	 STR(plaintext, plaintext_size,
	     "\xa8\x45\x34\x8e\xc8\xc5\xb5\xf1\x26\xf5\x0e\x76\xfe\xfd\x1b\x1e"),
	 .ciphertext = (void *)
	     "\xcc\x88\x12\x61\xc6\xa7\xfa\x72\xb9\x6a\x17\x39\x17\x6b\x27\x7f",
	 STR(iv, iv_size,
	     "\xdb\xd1\xa3\x63\x60\x24\xb7\xb4\x02\xda\x7d\x6f"),
	 .tag_size = 16,
	 .tag = (void *)
	     "\x34\x72\xe1\x14\x5f\x2c\x0c\xbe\x14\x63\x49\x06\x2c\xf0\xe4\x23"},
	{
	 .compat_apis = 0,
	 STR(key, key_size,
	     "\xfb\x76\x15\xb2\x3d\x80\x89\x1d\xd4\x70\x98\x0b\xc7\x95\x84\xc8\xb2\xfb\x64\xce\x60\x97\x87\x8d\x17\xfc\xe4\x5a\x49\xe8\x30\xb7"),
	 STR(auth, auth_size, "\x36"),
	 STR(plaintext, plaintext_size,
	     "\xa9"),
	 .ciphertext = (void *)
	     "\x9d",
	 STR(iv, iv_size,
	     "\xdb\xd1\xa3\x63\x60\x24\xb7\xb4\x02\xda\x7d\x6f"),
	 .tag_size = 16,
	 .tag = (void *)
	     "\x32\x61\xb1\xcf\x93\x14\x31\xe9\x9a\x32\x80\x67\x38\xec\xbd\x2a"},
};

const struct cipher_aead_vectors_st aes128_ccm_vectors[] = {
	{
	 .compat_apis = 0,
	 STR(key, key_size,
	     "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF"),
	 STR(auth, auth_size, "\x08\xD0\x84\x21\x43\x01\x00\x00\x00\x00\x48\xDE\xAC\x02\x05\x00\x00\x00\x55\xCF\x00\x00\x51\x52\x53\x54"),
	 .plaintext = NULL,
	 .plaintext_size = 0,
	 STR(iv, iv_size,
	     "\xAC\xDE\x48\x00\x00\x00\x00\x01\x00\x00\x00\x05\x02"),
	 .tag_size = 8,
	 .tag = (void *)
	     "\x22\x3B\xC1\xEC\x84\x1A\xB5\x53"},
	{
	 .compat_apis = 0,
	 STR(key, key_size,
	     "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"),
	 STR(auth, auth_size, "\x00\x01\x02\x03\x04\x05\x06\x07"),
	 STR(plaintext, plaintext_size,
	     "\x20\x21\x22\x23"),
	 .ciphertext = (void *)
	     "\x71\x62\x01\x5b",
	 STR(iv, iv_size,
	     "\x10\x11\x12\x13\x14\x15\x16"),
	 .tag_size = 4,
	 .tag = (void *)
	     "\x4d\xac\x25\x5d"},
	/* from rfc3610 */
	{
	 .compat_apis = 0,
	 STR(key, key_size,
	     "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF"),
	 STR(auth, auth_size, "\x00\x01\x02\x03\x04\x05\x06\x07"),
	 STR(plaintext, plaintext_size,
	     "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E"),
	 .ciphertext = (void *)
	     "\x01\x35\xD1\xB2\xC9\x5F\x41\xD5\xD1\xD4\xFE\xC1\x85\xD1\x66\xB8\x09\x4E\x99\x9D\xFE\xD9\x6C",
	 STR(iv, iv_size,
	     "\x00\x00\x00\x09\x08\x07\x06\xA0\xA1\xA2\xA3\xA4\xA5"),
	 .tag_size = 10,
	 .tag = (void *)
	     "\x04\x8C\x56\x60\x2C\x97\xAC\xBB\x74\x90"},
	{
	 .compat_apis = 0,
	 STR(key, key_size,
	     "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF"),
	 STR(auth, auth_size, "\x00\x01\x02\x03\x04\x05\x06\x07"),
	 STR(plaintext, plaintext_size,
	     "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E"),
	 .ciphertext = (void *)
	     "\x58\x8C\x97\x9A\x61\xC6\x63\xD2\xF0\x66\xD0\xC2\xC0\xF9\x89\x80\x6D\x5F\x6B\x61\xDA\xC3\x84",
	 STR(iv, iv_size,
	     "\x00\x00\x00\x03\x02\x01\x00\xA0\xA1\xA2\xA3\xA4\xA5"),
	 .tag_size = 8,
	 .tag = (void *)
	     "\x17\xE8\xD1\x2C\xFD\xF9\x26\xE0"},
};

const struct cipher_vectors_st aes128_cbc_vectors[] = {
	{
	 STR(key, key_size,
	     "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"),
	 STR(plaintext, plaintext_size,
	     "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"),
	 .ciphertext = (uint8_t *)
	 "\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d",
	 STR(iv, iv_size,
	     "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"),
	 },
	{
	 STR(key, key_size,
	     "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"),
	 STR(plaintext, plaintext_size,
	     "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"),
	 .ciphertext =
	 (uint8_t *)
	 "\x50\x86\xcb\x9b\x50\x72\x19\xee\x95\xdb\x11\x3a\x91\x76\x78\xb2",
	 STR(iv, iv_size,
	     "\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d"),
	 },
};

const struct cipher_vectors_st aes192_cbc_vectors[] = {
	{
	 STR(key, key_size,
	     "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b"),
	 STR(plaintext, plaintext_size,
	     "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"),
	 .ciphertext = (uint8_t *)
	 "\x4f\x02\x1d\xb2\x43\xbc\x63\x3d\x71\x78\x18\x3a\x9f\xa0\x71\xe8",
	 STR(iv, iv_size,
	     "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"),
	 },
	{
	 STR(key, key_size,
	     "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b"),
	 STR(plaintext, plaintext_size,
	     "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"),
	 .ciphertext = (uint8_t *)
	 "\xb4\xd9\xad\xa9\xad\x7d\xed\xf4\xe5\xe7\x38\x76\x3f\x69\x14\x5a",
	 STR(iv, iv_size,
	     "\x4F\x02\x1D\xB2\x43\xBC\x63\x3D\x71\x78\x18\x3A\x9F\xA0\x71\xE8"),
	 },
};

const struct cipher_vectors_st aes256_cbc_vectors[] = {
	{
	 STR(key, key_size,
	     "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4"),
	 STR(plaintext, plaintext_size,
	     "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"),
	 .ciphertext = (uint8_t *)
	 "\xF5\x8C\x4C\x04\xD6\xE5\xF1\xBA\x77\x9E\xAB\xFB\x5F\x7B\xFB\xD6",
	 STR(iv, iv_size,
	     "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"),
	 },
	{
	 STR(key, key_size,
	     "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4"),
	 STR(plaintext, plaintext_size,
	     "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"),
	 .ciphertext = (uint8_t *)
	 "\x9c\xfc\x4e\x96\x7e\xdb\x80\x8d\x67\x9f\x77\x7b\xc6\x70\x2c\x7d",
	 STR(iv, iv_size,
	     "\xF5\x8C\x4C\x04\xD6\xE5\xF1\xBA\x77\x9E\xAB\xFB\x5F\x7B\xFB\xD6"),
	 },
};

const struct cipher_vectors_st tdes_cbc_vectors[] = {
/* First 2 from https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/des/Triple-Des-3-Key-192-64.unverified.test-vectors */
	{
	 STR(key, key_size,
	     "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17"),
	 STR(plaintext, plaintext_size,
	     "\x98\x26\x62\x60\x55\x53\x24\x4D"),
	 .ciphertext = (uint8_t *)
	 "\x00\x11\x22\x33\x44\x55\x66\x77",
	 STR(iv, iv_size, "\x00\x00\x00\x00\x00\x00\x00\x00"),
	 },
	{
	 STR(key, key_size,
	     "\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48\x2B\xD6\x45\x9F\x82\xC5\xB3\x00"),
	 STR(plaintext, plaintext_size,
	     "\x85\x98\x53\x8A\x8E\xCF\x11\x7D"),
	 .ciphertext = (uint8_t *)
	 "\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
	 STR(iv, iv_size, "\x00\x00\x00\x00\x00\x00\x00\x00"),
	 },
};

const struct cipher_vectors_st arcfour_vectors[] = { /* RFC6229 */
	{
	 STR(key, key_size,
	     "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18"),
	 STR(plaintext, plaintext_size,
	     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	 .ciphertext = (uint8_t *)
	     "\x05\x95\xe5\x7f\xe5\xf0\xbb\x3c\x70\x6e\xda\xc8\xa4\xb2\xdb\x11",
	 .iv = NULL,
	 .iv_size = 0
	},
	{
	 STR(key, key_size,
	     "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"),
	 STR(plaintext, plaintext_size,
	     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	 .ciphertext = (uint8_t *)
	     "\xea\xa6\xbd\x25\x88\x0b\xf9\x3d\x3f\x5d\x1e\x4c\xa2\x61\x1d\x91",
	 .iv = NULL,
	 .iv_size = 0
	},
	{
	 STR(key, key_size,
	     "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"),
	 STR(plaintext, plaintext_size,
	     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	 .ciphertext = (uint8_t *)
	 "\x9a\xc7\xcc\x9a\x60\x9d\x1e\xf7\xb2\x93\x28\x99\xcd\xe4\x1b\x97",
	 .iv = NULL,
	 .iv_size = 0
	},
};

const struct cipher_vectors_st aes128_cfb8_vectors[] = { /* NIST 800-38a */
	{
	 STR(key, key_size,
	     "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"),
	 STR(plaintext, plaintext_size,
	     "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
             "\xae\x2d"),
	 .ciphertext = (uint8_t *)
	     "\x3b\x79\x42\x4c\x9c\x0d\xd4\x36\xba\xce\x9e\x0e\xd4\x58\x6a\x4f"
             "\x32\xb9",
	 STR(iv, iv_size,
	     "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"),
	 /* the least significant 16 bytes of ciphertext */
	 STR(internal_iv, internal_iv_size,
	     "\x42\x4c\x9c\x0d\xd4\x36\xba\xce\x9e\x0e\xd4\x58\x6a\x4f\x32\xb9"),
	 },
};

const struct cipher_vectors_st aes192_cfb8_vectors[] = { /* NIST 800-38a */
	{
	 STR(key, key_size,
	     "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
             "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b"),
	 STR(plaintext, plaintext_size,
	     "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
             "\xae\x2d"),
	 .ciphertext = (uint8_t *)
	     "\xcd\xa2\x52\x1e\xf0\xa9\x05\xca\x44\xcd\x05\x7c\xbf\x0d\x47\xa0"
             "\x67\x8a",
	 STR(iv, iv_size,
	     "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"),
	 /* the least significant 16 bytes of ciphertext */
	 STR(internal_iv, internal_iv_size,
	     "\x52\x1e\xf0\xa9\x05\xca\x44\xcd\x05\x7c\xbf\x0d\x47\xa0\x67\x8a"),
	 },
};

const struct cipher_vectors_st aes256_cfb8_vectors[] = { /* NIST 800-38a */
	{
	 STR(key, key_size,
	     "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
             "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4"),
	 STR(plaintext, plaintext_size,
	     "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
             "\xae\x2d"),
	 .ciphertext = (uint8_t *)
	     "\xdc\x1f\x1a\x85\x20\xa6\x4d\xb5\x5f\xcc\x8a\xc5\x54\x84\x4e\x88"
             "\x97\x00",
	 STR(iv, iv_size,
	     "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"),
	 /* the least significant 16 bytes of ciphertext */
	 STR(internal_iv, internal_iv_size,
	     "\x1a\x85\x20\xa6\x4d\xb5\x5f\xcc\x8a\xc5\x54\x84\x4e\x88\x97\x00"),
	 },
};

/* GOST 28147-89 vectors come from the testsuite contributed to OpenSSL by
 * Sergey E. Leontiev. CryptoPro-B test vector is just truncated.
 * TC26Z is calculated using Nettle */
const struct cipher_vectors_st gost28147_cpa_cfb_vectors[] = {
	{
	 STR(key, key_size,
	     "\x8d\x5a\x2c\x83\xa7\xc7\x0a\x61\xd6\x1b\x34\xb5\x1f\xdf\x42\x68"
	     "\x66\x71\xa3\x5d\x87\x4c\xfd\x84\x99\x36\x63\xb6\x1e\xd6\x0d\xad"),
	 STR(plaintext, plaintext_size,
	     "\xd2\xfd\xf8\x3a\xc1\xb4\x39\x23\x2e\xaa\xcc\x98\x0a\x02\xda\x33"),
	 .ciphertext = (uint8_t *)
		 "\x88\xb7\x75\x16\x74\xa5\xee\x2d\x14\xfe\x91\x67\xd0\x5c\xcc\x40",
	 STR(iv, iv_size,
	     "\x46\x60\x6f\x0d\x88\x34\x23\x5a"),
	},
};

const struct cipher_vectors_st gost28147_cpb_cfb_vectors[] = {
	{
	 STR(key, key_size,
	     "\x48\x0c\x74\x1b\x02\x6b\x55\xd5\xb6\x6d\xd7\x1d\x40\x48\x05\x6b"
	     "\x6d\xeb\x3c\x29\x0f\x84\x80\x23\xee\x0d\x47\x77\xe3\xfe\x61\xc9"),
	 STR(plaintext, plaintext_size,
	     "\x8c\x9c\x44\x35\xfb\xe9\xa5\xa3\xa0\xae\x28\x56\x91\x10\x8e\x1e"
	     "\xd2\xbb\x18\x53\x81\x27\x0d\xa6\x68\x59\x36\xc5\x81\x62\x9a\x8e"
	     "\x7d\x50\xf1\x6f\x97\x62\x29\xec\x80\x51\xe3\x7d\x6c\xc4\x07\x95"
	     "\x28\x63\xdc\xb4\xb9\x2d\xb8\x13\xb1\x05\xb5\xf9\xeb\x75\x37"),
	 .ciphertext = (uint8_t *)
		 "\x23\xc6\x7f\x20\xa1\x23\x58\xbc\x7b\x05\xdb\x21\x15\xcf\x96\x41"
		 "\xc7\x88\xef\x76\x5c\x49\xdb\x42\xbf\xf3\xc0\xf5\xbd\x5d\xd9\x8e"
		 "\xaf\x3d\xf4\xe4\xda\x88\xbd\xbc\x47\x5d\x76\x07\xc9\x5f\x54\x1d"
		 "\x1d\x6a\xa1\x2e\x18\xd6\x60\x84\x02\x18\x37\x92\x92\x15\xab",
	 STR(iv, iv_size,
	     "\x1f\x3f\x82\x1e\x0d\xd8\x1e\x22"),
	},
};

const struct cipher_vectors_st gost28147_cpc_cfb_vectors[] = {
	{
	 STR(key, key_size,
	     "\x77\xc3\x45\x8e\xf6\x42\xe7\x04\x8e\xfc\x08\xe4\x70\x96\xd6\x05"
	     "\x93\x59\x02\x6d\x6f\x97\xca\xe9\xcf\x89\x44\x4b\xde\x6c\x22\x1d"),
	 STR(plaintext, plaintext_size,
	     "\x07\x9c\x91\xbe"),
	 .ciphertext = (uint8_t *)
		 "\x19\x35\x81\x34",
	 STR(iv, iv_size,
	     "\x43\x7c\x3e\x8e\x2f\x2a\x00\x98"),
	},
};

const struct cipher_vectors_st gost28147_cpd_cfb_vectors[] = {
	{
	 STR(key, key_size,
	     "\x38\x9f\xe8\x37\xff\x9c\x5d\x29\xfc\x48\x55\xa0\x87\xea\xe8\x40"
	     "\x20\x87\x5b\xb2\x01\x15\x55\xa7\xe3\x2d\xcb\x3d\xd6\x59\x04\x73"),
	 STR(plaintext, plaintext_size,
	     "\x2f\x31\xd8\x83\xb4\x20\xe8\x6e\xda"),
	 .ciphertext = (uint8_t *)
		 "\x6d\xa4\xed\x40\x08\x88\x71\xad\x16",
	 STR(iv, iv_size,
	     "\xc5\xa2\xd2\x1f\x2f\xdf\xb8\xeb"),
	},
};

const struct cipher_vectors_st gost28147_tc26z_cfb_vectors[] = {
	{
	 STR(key, key_size,
	     "\x8d\x5a\x2c\x83\xa7\xc7\x0a\x61\xd6\x1b\x34\xb5\x1f\xdf\x42\x68"
	     "\x66\x71\xa3\x5d\x87\x4c\xfd\x84\x99\x36\x63\xb6\x1e\xd6\x0d\xad"),
	 STR(plaintext, plaintext_size,
	     "\xd2\xfd\xf8\x3a\xc1\xb4\x39\x23\x2e\xaa\xcc\x98\x0a\x02\xda\x33"),
	 .ciphertext = (uint8_t *)
		 "\xed\xa7\xf1\x41\x01\x9c\xbd\xcd\x44\x6b\x00\x96\x87\xf7\xc7\xe6",
	 STR(iv, iv_size,
	     "\x46\x60\x6f\x0d\x88\x34\x23\x5a"),
	},
};

const struct cipher_vectors_st gost28147_tc26z_cnt_vectors[] = {
	{
	 STR(key, key_size,
	     "\x59\x9f\x84\xba\xc3\xf3\xd2\xf1\x60\xe1\xe3\xf2\x6a\x96\x1a\xf9"
	     "\x9c\x48\xb2\x4e\xbc\xbb\xbf\x7c\xd8\xf3\xac\xcd\x96\x8d\x28\x6a"),
	 STR(plaintext, plaintext_size,
	     "\x90\xa2\x39\x66\xae\x01\xb9\xa3\x52\x4e\xc8\xed\x6c\xdd\x88\x30"),
	 .ciphertext = (uint8_t *)
		 "\xe8\xb1\x4f\xc7\x30\xdc\x25\xbb\x36\xba\x64\x3c\x17\xdb\xff\x99",
	 STR(iv, iv_size,
	     "\x8d\xaf\xa8\xd1\x58\xed\x05\x8d"),
	}
};

const struct cipher_vectors_st aes128_xts_vectors[] = {
	{
	 STR(key, key_size,
	     "\xa1\xb9\x0c\xba\x3f\x06\xac\x35\x3b\x2c\x34\x38\x76\x08\x17\x62"
             "\x09\x09\x23\x02\x6e\x91\x77\x18\x15\xf2\x9d\xab\x01\x93\x2f\x2f"),
	 STR(plaintext, plaintext_size,
	     "\xeb\xab\xce\x95\xb1\x4d\x3c\x8d\x6f\xb3\x50\x39\x07\x90\x31\x1c"),
	 .ciphertext = (uint8_t *)
	     "\x77\x8a\xe8\xb4\x3c\xb9\x8d\x5a\x82\x50\x81\xd5\xbe\x47\x1c\x63",
	 STR(iv, iv_size,
	     "\x4f\xae\xf7\x11\x7c\xda\x59\xc6\x6e\x4b\x92\x01\x3e\x76\x8a\xd5"),
	 },
	{
	 STR(key, key_size,
	     "\x75\x03\x72\xc3\xd8\x2f\x63\x38\x28\x67\xbe\x66\x62\xac\xfa\x4a"
             "\x25\x9b\xe3\xfa\x9b\xc6\x62\xa1\x15\x4f\xfa\xae\xd8\xb4\x48\xa5"),
	 STR(plaintext, plaintext_size,
	     "\xd8\xe3\xa5\x65\x59\xa4\x36\xce\x0d\x8b\x21\x2c\x80\xa8\x8b\x23"
             "\xaf\x62\xb0\xe5\x98\xf2\x08\xe0\x3c\x1f\x2e\x9f\xa5\x63\xa5\x4b"),
	 .ciphertext = (uint8_t *)
	     "\x49\x5f\x78\x55\x53\x5e\xfd\x13\x34\x64\xdc\x9a\x9a\xbf\x8a\x0f"
             "\x28\xfa\xcb\xce\x21\xbd\x3c\x22\x17\x8e\xc4\x89\xb7\x99\xe4\x91",
	 STR(iv, iv_size,
	     "\x93\xa2\x92\x54\xc4\x7e\x42\x60\x66\x96\x21\x30\x7d\x4f\x5c\xd3"),
	 },
};

const struct cipher_vectors_st aes256_xts_vectors[] = {
	{
	 STR(key, key_size,
             "\x1e\xa6\x61\xc5\x8d\x94\x3a\x0e\x48\x01\xe4\x2f\x4b\x09\x47\x14"
             "\x9e\x7f\x9f\x8e\x3e\x68\xd0\xc7\x50\x52\x10\xbd\x31\x1a\x0e\x7c"
             "\xd6\xe1\x3f\xfd\xf2\x41\x8d\x8d\x19\x11\xc0\x04\xcd\xa5\x8d\xa3"
             "\xd6\x19\xb7\xe2\xb9\x14\x1e\x58\x31\x8e\xea\x39\x2c\xf4\x1b\x08"),
	 STR(plaintext, plaintext_size,
	     "\x2e\xed\xea\x52\xcd\x82\x15\xe1\xac\xc6\x47\xe8\x10\xbb\xc3\x64"
             "\x2e\x87\x28\x7f\x8d\x2e\x57\xe3\x6c\x0a\x24\xfb\xc1\x2a\x20\x2e"),
	 .ciphertext = (uint8_t *)
	     "\xcb\xaa\xd0\xe2\xf6\xce\xa3\xf5\x0b\x37\xf9\x34\xd4\x6a\x9b\x13"
             "\x0b\x9d\x54\xf0\x7e\x34\xf3\x6a\xf7\x93\xe8\x6f\x73\xc6\xd7\xdb",
	 STR(iv, iv_size,
	     "\xad\xf8\xd9\x26\x27\x46\x4a\xd2\xf0\x42\x8e\x84\xa9\xf8\x75\x64"),
	 },
};

const struct cipher_aead_vectors_st aes128_siv_vectors[] = {
	{
	 STR(key, key_size,
	     "\x7f\x7e\x7d\x7c\x7b\x7a\x79\x78\x77\x76\x75\x74\x73\x72\x71\x70"
	     "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"),
	 STR(auth, auth_size,
	     "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
	     "\xde\xad\xda\xda\xde\xad\xda\xda\xff\xee\xdd\xcc\xbb\xaa\x99\x88"
	     "\x77\x66\x55\x44\x33\x22\x11\x00"),
	 STR(plaintext, plaintext_size,
	     "\x74\x68\x69\x73\x20\x69\x73\x20\x73\x6f\x6d\x65\x20\x70\x6c\x61"
	     "\x69\x6e\x74\x65\x78\x74\x20\x74\x6f\x20\x65\x6e\x63\x72\x79\x70"
	     "\x74\x20\x75\x73\x69\x6e\x67\x20\x53\x49\x56\x2d\x41\x45\x53"),
	 .ciphertext = (uint8_t *)
	     "\xa4\xff\xb8\x7f\xdb\xa9\x7c\x89\x44\xa6\x23\x25\xf1\x33\xb4\xe0"
	     "\x1c\xa5\x52\x76\xe2\x26\x1c\x1a\x1d\x1d\x42\x48\xd1\xda\x30\xba"
	     "\x52\xb9\xc8\xd7\x95\x5d\x65\xc8\xd2\xce\x6e\xb7\xe3\x67\xd0",
	 STR(iv, iv_size,
	     "\x02\x03\x04"),
	 .tag_size = 16,
	 .tag = (void *)
	     "\xf1\xdb\xa3\x3d\xe5\xb3\x36\x9e\x88\x3f\x67\xb6\xfc\x82\x3c\xee",
	 .tag_prepended = 1,
	}
};

const struct cipher_aead_vectors_st aes256_siv_vectors[] = {
	{
	 STR(key, key_size,
	     "\xc2\x7d\xf2\xfd\xae\xc3\x5d\x4a\x2a\x41\x2a\x50\xc3\xe8\xc4\x7d"
	     "\x2d\x56\x8e\x91\xa3\x8e\x54\x14\x8a\xbd\xc0\xb6\xe8\x6c\xaf\x87"
	     "\x69\x5c\x0a\x8a\xdf\x4c\x5f\x8e\xb2\xc6\xc8\xb1\x36\x52\x98\x64"
	     "\xf3\xb8\x4b\x3a\xe8\xe3\x67\x6c\xe7\x60\xc4\x61\xf3\xa1\x3e\x83"),
	 STR(auth, auth_size,
	     "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
	     "\xde\xad\xda\xda\xde\xad\xda\xda\xff\xee\xdd\xcc\xbb\xaa\x99\x88"
	     "\x77\x66\x55\x44\x33\x22\x11\x00"),
	 STR(plaintext, plaintext_size,
	     "\x74\x68\x69\x73\x20\x69\x73\x20\x73\x6f\x6d\x65\x20\x70\x6c\x61"
	     "\x69\x6e\x74\x65\x78\x74\x20\x74\x6f\x20\x65\x6e\x63\x72\x79\x70"
	     "\x74\x20\x75\x73\x69\x6e\x67\x20\x53\x49\x56\x2d\x41\x45\x53"),
	 .ciphertext = (uint8_t *)
	     "\x50\x93\x3d\xa8\x04\x7b\xc3\x06\xfa\xba\xf0\xc3\xd9\xfa\x84\x71"
	 "\xc7\x0a\x7d\xef\x39\xa2\xf9\x1d\x68\xa2\x02\x1c\x99\xac\x7e\x2a\x24"
	 "\x53\x5a\x13\x4b\xa2\x3e\xc1\x57\x87\xce\xbe\x5c\x53\xcc",
	 STR(iv, iv_size,
	     "\x09\xf9\x11\x02\x9d\x74\xe3\x5b\xd8\x41\x56\xc5\x63\x56\x88\xc0"),
	 .tag_size = 16,
	 .tag = (void *)
	     "\x5a\x97\x9b\x0d\xa5\x8f\xde\x80\x51\x62\x1a\xe6\xbf\x96\xfe\xda",
	 .tag_prepended = 1,
	}
};

const struct cipher_vectors_st chacha20_32_vectors[] = { /* RFC8439 */
	{
	 STR(key, key_size,
	     "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"),
	 STR(plaintext, plaintext_size,
	     "\x4c\x61\x64\x69\x65\x73\x20\x61\x6e\x64\x20\x47\x65\x6e\x74\x6c\x65\x6d\x65\x6e\x20\x6f\x66\x20\x74\x68\x65\x20\x63\x6c\x61\x73\x73\x20\x6f\x66\x20\x27\x39\x39\x3a\x20\x49\x66\x20\x49\x20\x63\x6f\x75\x6c\x64\x20\x6f\x66\x66\x65\x72\x20\x79\x6f\x75\x20\x6f\x6e\x6c\x79\x20\x6f\x6e\x65\x20\x74\x69\x70\x20\x66\x6f\x72\x20\x74\x68\x65\x20\x66\x75\x74\x75\x72\x65\x2c\x20\x73\x75\x6e\x73\x63\x72\x65\x65\x6e\x20\x77\x6f\x75\x6c\x64\x20\x62\x65\x20\x69\x74\x2e"),
	 .ciphertext = (uint8_t *)
	     "\x6e\x2e\x35\x9a\x25\x68\xf9\x80\x41\xba\x07\x28\xdd\x0d\x69\x81\xe9\x7e\x7a\xec\x1d\x43\x60\xc2\x0a\x27\xaf\xcc\xfd\x9f\xae\x0b\xf9\x1b\x65\xc5\x52\x47\x33\xab\x8f\x59\x3d\xab\xcd\x62\xb3\x57\x16\x39\xd6\x24\xe6\x51\x52\xab\x8f\x53\x0c\x35\x9f\x08\x61\xd8\x07\xca\x0d\xbf\x50\x0d\x6a\x61\x56\xa3\x8e\x08\x8a\x22\xb6\x5e\x52\xbc\x51\x4d\x16\xcc\xf8\x06\x81\x8c\xe9\x1a\xb7\x79\x37\x36\x5a\xf9\x0b\xbf\x74\xa3\x5b\xe6\xb4\x0b\x8e\xed\xf2\x78\x5e\x42\x87\x4d",
	 STR(iv, iv_size,
	     "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00")
	},
};

static int test_cipher(gnutls_cipher_algorithm_t cipher,
		       const struct cipher_vectors_st *vectors,
		       size_t vectors_size, unsigned flags)
{
	gnutls_cipher_hd_t hd;
	int ret;
	unsigned int i;
	uint8_t tmp[384];
	uint8_t fail_tmp[384];
	gnutls_datum_t key, iv = {NULL, 0};

	for (i = 0; i < vectors_size; i++) {
		key.data = (void *) vectors[i].key;
		key.size = vectors[i].key_size;

		if (vectors[i].iv != NULL) {
			iv.data = (void *) vectors[i].iv;
			iv.size = gnutls_cipher_get_iv_size(cipher);
		}

		if (iv.size != vectors[i].iv_size)
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

		if (iv.size > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "IV-encrypt")) {
			if (iv.size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, iv.data, iv.size);
			/* Flip one IV bit. */
			fail_tmp[0] ^= 0x1;
			iv.data = (void *)fail_tmp;
		}

		ret = gnutls_cipher_init(&hd, cipher, &key, &iv);
		if (ret < 0) {
			_gnutls_debug_log("error initializing: %s\n",
					  gnutls_cipher_get_name(cipher));
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		if (fips_request_failure(gnutls_cipher_get_name(cipher), "encrypt")) {
			if (vectors[i].plaintext_size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, vectors[i].plaintext, vectors[i].plaintext_size);
			/* Flip one plaintext bit. */
			fail_tmp[0] ^= 0x1;
			ret =
			    gnutls_cipher_encrypt2(hd,
					   fail_tmp,
					   vectors[i].plaintext_size,
					   tmp, sizeof(tmp));
		} else {
			ret =
			    gnutls_cipher_encrypt2(hd,
					   vectors[i].plaintext,
					   vectors[i].plaintext_size,
					   tmp, sizeof(tmp));
		}
		if (ret < 0)
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

		if (memcmp
		    (tmp, vectors[i].ciphertext,
		     vectors[i].plaintext_size) != 0) {
			_gnutls_debug_log("%s test vector %d failed!\n",
					  gnutls_cipher_get_name(cipher),
					  i);
			FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher", "encrypt test vector %d", i);
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		} else {
			FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher", "encrypt test vector %d", i);
		}

		/* check in-place encryption */
		if (cipher != GNUTLS_CIPHER_ARCFOUR_128) { /* arcfour is stream */
			gnutls_cipher_set_iv(hd, (void*)vectors[i].iv, vectors[i].iv_size);

			memcpy(tmp, vectors[i].plaintext, vectors[i].plaintext_size);
			if (fips_request_failure(gnutls_cipher_get_name(cipher), "encrypt-in-place")) {
				/* Flip one plaintext bit. */
				tmp[0] ^= 0x1;
			}
			ret = gnutls_cipher_encrypt(hd, tmp, vectors[i].plaintext_size);
			if (ret < 0)
				return
				    gnutls_assert_val
				    (GNUTLS_E_SELF_TEST_ERROR);

			if (memcmp(tmp, vectors[i].ciphertext, vectors[i].plaintext_size) != 0) {
				_gnutls_debug_log("%s vector %d in-place encryption failed!\n", gnutls_cipher_get_name(cipher), i);
				FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher", "vector %d in-place encryption", i);
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			} else {
				FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher", "vector %d in-place encryption", i);
			}
		}

		/* check the internal IV */
		if (vectors[i].internal_iv_size > 0) {
			ret = _gnutls_cipher_get_iv(hd, tmp, sizeof(tmp));
			if (ret < 0)
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

			if (fips_request_failure(gnutls_cipher_get_name(cipher), "internal-IV-check")) {
				/* Flip one IV bit. */
				tmp[0] ^= 0x1;
			}
			if (memcmp(tmp, vectors[i].internal_iv, ret) != 0) {
				_gnutls_debug_log("%s vector %d internal IV check failed!\n",
						  gnutls_cipher_get_name(cipher),
						  i);
				FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher", "vector %d internal IV check", i);
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			} else {
				FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher", "vector %d internal IV check", i);
			}
		}

		gnutls_cipher_deinit(hd);
	}

	iv.size = gnutls_cipher_get_iv_size(cipher);

	for (i = 0; i < vectors_size; i++) {
		key.data = (void *) vectors[i].key;
		key.size = vectors[i].key_size;

		iv.data = (void *) vectors[i].iv;

		if (iv.size > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "IV-decrypt")) {
			if (iv.size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, iv.data, iv.size);
			/* Flip one IV bit. */
			fail_tmp[0] ^= 0x1;
			iv.data = (void *)fail_tmp;
		}

		ret = gnutls_cipher_init(&hd, cipher, &key, &iv);
		if (ret < 0)
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

		if (fips_request_failure(gnutls_cipher_get_name(cipher), "decrypt")) {
			if (vectors[i].plaintext_size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, vectors[i].ciphertext, vectors[i].plaintext_size);
			/* Flip one ciphertext bit. */
			fail_tmp[0] ^= 0x1;
			ret =
			    gnutls_cipher_decrypt2(hd,
					   fail_tmp,
					   vectors[i].plaintext_size, tmp,
					   sizeof(tmp));
		} else {
			ret =
			    gnutls_cipher_decrypt2(hd,
					   vectors[i].ciphertext,
					   vectors[i].plaintext_size, tmp,
					   sizeof(tmp));
		}
		if (ret < 0) {
			_gnutls_debug_log
			    ("%s decryption of test vector %d failed!\n",
			     gnutls_cipher_get_name(cipher), i);
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		if (memcmp
		    (tmp, vectors[i].plaintext,
		     vectors[i].plaintext_size) != 0) {
			_gnutls_debug_log("%s test vector %d failed!\n",
					  gnutls_cipher_get_name(cipher),
					  i);
			FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher", "decrypt test vector %d", i);
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		} else {
			FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher", "decrypt test vector %d", i);
		}

		/* check in-place decryption */
		if (cipher != GNUTLS_CIPHER_ARCFOUR_128) { /* arcfour is stream */
			gnutls_cipher_set_iv(hd, (void*)vectors[i].iv, vectors[i].iv_size);

			memcpy(tmp, vectors[i].ciphertext, vectors[i].plaintext_size);
			if (fips_request_failure(gnutls_cipher_get_name(cipher), "decrypt-in-place")) {
				/* Flip one ciphertext bit. */
				tmp[0] ^= 0x1;
			}
			ret = gnutls_cipher_decrypt(hd, tmp, vectors[i].plaintext_size);
			if (ret < 0)
				return
				    gnutls_assert_val
				    (GNUTLS_E_SELF_TEST_ERROR);

			if (memcmp(tmp, vectors[i].plaintext, vectors[i].plaintext_size) != 0) {
				_gnutls_debug_log("%s vector %d in-place decryption failed!\n", gnutls_cipher_get_name(cipher), i);
				FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher", "vector %d in-place decryption", i);
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			} else {
				FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher", "vector %d in-place decryption", i);
			}
		}

		gnutls_cipher_deinit(hd);
	}

	_gnutls_debug_log
	    ("%s self check succeeded\n",
	     gnutls_cipher_get_name(cipher));

	return 0;
}

static int test_cipher_all_block_sizes(gnutls_cipher_algorithm_t cipher,
				       const struct cipher_vectors_st *vectors,
				       size_t vectors_size, unsigned flags)
{
	gnutls_cipher_hd_t hd;
	int ret;
	unsigned int i;
	uint8_t tmp[384];
	uint8_t fail_tmp[384];
	gnutls_datum_t key, iv = {NULL, 0};
	size_t block;
	size_t offset;

	for (i = 0; i < vectors_size; i++) {
		for (block = 1; block <= vectors[i].plaintext_size; block++) {
			key.data = (void *) vectors[i].key;
			key.size = vectors[i].key_size;

			iv.data = (void *) vectors[i].iv;
			iv.size = gnutls_cipher_get_iv_size(cipher);

			if (iv.size != vectors[i].iv_size)
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

			if (iv.size > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "IV-encrypt-all-block")) {
				if (iv.size > sizeof(fail_tmp)) {
					return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
				}
				memcpy(fail_tmp, iv.data, iv.size);
				/* Flip one IV bit. */
				fail_tmp[0] ^= 0x1;
				iv.data = (void *)fail_tmp;
			}

			ret = gnutls_cipher_init(&hd, cipher, &key, &iv);
			if (ret < 0) {
				_gnutls_debug_log("error initializing: %s\n",
						  gnutls_cipher_get_name(cipher));
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}

			for (offset = 0;
			     offset < vectors[i].plaintext_size;
			     offset += block) {
				/* If request fail, only flip a bit on the first part of the plaintext. */
				if (offset == 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "encrypt-all-block")) {
					size_t elen = MIN(block, vectors[i].plaintext_size - offset);
					if (elen >  sizeof(fail_tmp)) {
						return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
					}
					memcpy(fail_tmp, vectors[i].plaintext + offset, elen);
					/* Flip one plaintext bit. */
					fail_tmp[0] ^= 0x1;
					ret =
					    gnutls_cipher_encrypt2(hd,
							   fail_tmp,
							   elen,
							   tmp + offset,
							   sizeof(tmp) - offset);
				} else {
					ret =
					    gnutls_cipher_encrypt2(hd,
							   vectors[i].plaintext + offset,
							   MIN(block, vectors[i].plaintext_size - offset),
							   tmp + offset,
							   sizeof(tmp) - offset);
				}
				if (ret < 0)
					return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}

			if (memcmp
			    (tmp, vectors[i].ciphertext,
			     vectors[i].plaintext_size) != 0) {
				_gnutls_debug_log("%s encryption of test vector %d failed with block size %d/%d!\n",
						  gnutls_cipher_get_name(cipher),
						  i, (int)block, (int)vectors[i].plaintext_size);
				FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
					"encryption of test vector %d with block size %d/%d",
					i, (int)block, (int)vectors[i].plaintext_size);
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			} else {
				FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher",
					"encryption of test vector %d with block size %d/%d",
					i, (int)block, (int)vectors[i].plaintext_size);
			}

			gnutls_cipher_deinit(hd);
		}
	}

	for (i = 0; i < vectors_size; i++) {
		for (block = 1; block <= vectors[i].plaintext_size; block++) {
			key.data = (void *) vectors[i].key;
			key.size = vectors[i].key_size;

			iv.data = (void *) vectors[i].iv;
			iv.size = gnutls_cipher_get_iv_size(cipher);

			if (iv.size > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "IV-decrypt-all-block")) {
				if (iv.size > sizeof(fail_tmp)) {
					return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
				}
				memcpy(fail_tmp, iv.data, iv.size);
				/* Flip one IV bit. */
				fail_tmp[0] ^= 0x1;
				iv.data = (void *)fail_tmp;
			}

			ret = gnutls_cipher_init(&hd, cipher, &key, &iv);
			if (ret < 0)
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

			for (offset = 0;
			     offset + block <= vectors[i].plaintext_size;
			     offset += block) {
				/* If request fail, only flip a bit on the first part of the ciphertext. */
				if (offset == 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "decrypt-all-block")) {
					size_t elen = MIN(block, vectors[i].plaintext_size - offset);
					if (elen >  sizeof(fail_tmp)) {
						return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
					}
					memcpy(fail_tmp, vectors[i].ciphertext + offset, elen);
					/* Flip one ciphertext bit. */
					fail_tmp[0] ^= 0x1;
					ret =
					    gnutls_cipher_decrypt2(hd,
							   fail_tmp,
							   elen,
							   tmp + offset,
							   sizeof(tmp) - offset);
				} else {
					ret =
					    gnutls_cipher_decrypt2(hd,
							   vectors[i].ciphertext + offset,
							   MIN(block, vectors[i].plaintext_size - offset),
							   tmp + offset,
							   sizeof(tmp) - offset);
				}
				if (ret < 0)
					return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}

			if (memcmp
			    (tmp, vectors[i].plaintext,
			     vectors[i].plaintext_size) != 0) {
				_gnutls_debug_log("%s decryption of test vector %d failed with block size %d!\n",
						  gnutls_cipher_get_name(cipher),
						  i, (int)block);
				FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
					   "decryption of test vector %d with block size %d",
					   i, (int)block);
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			} else {
				FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher",
					   "decryption of test vector %d with block size %d",
					   i, (int)block);
			}

			gnutls_cipher_deinit(hd);
		}
	}

	_gnutls_debug_log
	    ("%s self check succeeded\n",
	     gnutls_cipher_get_name(cipher));

	return 0;
}

/* AEAD modes (compat APIs) */
static int test_cipher_aead_compat(gnutls_cipher_algorithm_t cipher,
			    const struct cipher_aead_vectors_st *vectors,
			    size_t vectors_size)
{
	gnutls_cipher_hd_t hd;
	int ret;
	unsigned int i;
	uint8_t tmp[384];
	uint8_t tmp2[384];
	uint8_t fail_tmp[384];
	gnutls_datum_t key, iv;
	unsigned tag_size;

	_gnutls_debug_log("compat: running tests for: %s\n",
				  gnutls_cipher_get_name(cipher));

	for (i = 0; i < vectors_size; i++) {
		memset(tmp, 0, sizeof(tmp));
		key.data = (void *) vectors[i].key;
		key.size = vectors[i].key_size;

		iv.data = (void *) vectors[i].iv;
		iv.size = vectors[i].iv_size;
		tag_size = vectors[i].tag_size;


		if (tag_size > gnutls_cipher_get_tag_size(cipher)) {
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		if (iv.size > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "IV-encrypt-compat")) {
			if (iv.size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, iv.data, iv.size);
			/* Flip one IV bit. */
			fail_tmp[0] ^= 0x1;
			iv.data = (void *)fail_tmp;
		}

		ret = gnutls_cipher_init(&hd, cipher, &key, &iv);
		if (ret < 0) {
			if (vectors[i].compat_apis == 0) {
				return 0; /* expected */
			} else {
				_gnutls_debug_log("compat: error initializing: %s\n",
					  gnutls_cipher_get_name(cipher));
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
		}

		if (vectors[i].compat_apis == 0) {
			_gnutls_debug_log("compat: initialized but shouldn't: %s\n",
				  gnutls_cipher_get_name(cipher));
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		if (vectors[i].auth_size) {
			if (fips_request_failure(gnutls_cipher_get_name(cipher), "auth-encrypt-compat")) {
				if (vectors[i].auth_size > sizeof(fail_tmp)) {
					return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
				}
				memcpy(fail_tmp, vectors[i].auth, vectors[i].auth_size);
				/* Flip one bit in the auth. */
				fail_tmp[0] ^= 0x1;
				ret = gnutls_cipher_add_auth(hd, fail_tmp, vectors[i].auth_size);
			} else {
				ret = gnutls_cipher_add_auth(hd, vectors[i].auth, vectors[i].auth_size);
			}
			if (ret < 0)
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		if (vectors[i].plaintext_size > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "encrypt-compat")) {
			if (vectors[i].plaintext_size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, vectors[i].plaintext, vectors[i].plaintext_size);
			/* Flip one bit in the plaintext. */
			fail_tmp[0] ^= 0x1;
			ret = gnutls_cipher_encrypt2(hd, fail_tmp, vectors[i].plaintext_size,
					     tmp, sizeof(tmp));
		} else {
			ret = gnutls_cipher_encrypt2(hd, vectors[i].plaintext, vectors[i].plaintext_size,
					     tmp, sizeof(tmp));
		}
		if (ret < 0)
			return
			    gnutls_assert_val
			    (GNUTLS_E_SELF_TEST_ERROR);

		ret = gnutls_cipher_tag(hd, tmp+vectors[i].plaintext_size, tag_size);
		if (ret < 0)
			return
			    gnutls_assert_val
			    (GNUTLS_E_SELF_TEST_ERROR);

		if (memcmp(tmp+vectors[i].plaintext_size, vectors[i].tag, tag_size) != 0) {
			_gnutls_debug_log
			    ("compat: %s test vector %d failed (tag)!\n",
			     gnutls_cipher_get_name(cipher), i);
			FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
				"compat - encrypt test vector %d", i);
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		} else {
			FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher",
				"compat - encrypt test vector %d", i);
		}

		if (vectors[i].plaintext_size > 0) {
			if (memcmp
			    (tmp, vectors[i].ciphertext,
			     vectors[i].plaintext_size) != 0) {
				_gnutls_debug_log
				    ("compat - %s test vector %d failed!\n",
				     gnutls_cipher_get_name(cipher), i);

				FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
					"compat - encrypt test vector %d", i);
				return
				    gnutls_assert_val
				    (GNUTLS_E_SELF_TEST_ERROR);
			} else {
				FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher",
					"compat - encrypt test vector %d", i);
			}
		}

		if (vectors[i].plaintext_size > 0) {
			/* check inplace encryption */
			if (vectors[i].iv_size > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "IV-encrypt-in-place-compat")) {
				if (iv.size > sizeof(fail_tmp)) {
					return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
				}
				memcpy(fail_tmp, vectors[i].iv, vectors[i].iv_size);
				/* Flip one IV bit. */
				fail_tmp[0] ^= 0x1;
				gnutls_cipher_set_iv(hd, (void*)fail_tmp, vectors[i].iv_size);
			} else {
				gnutls_cipher_set_iv(hd, (void*)vectors[i].iv, vectors[i].iv_size);
			}
			memcpy(tmp2, vectors[i].plaintext, vectors[i].plaintext_size);

			if (fips_request_failure(gnutls_cipher_get_name(cipher), "encrypt-in-place-compat")) {
				/* Flip one bit in the plaintext. */
				tmp2[0] ^= 0x1;
			}

			ret = gnutls_cipher_encrypt(hd, tmp2, vectors[i].plaintext_size);
			if (ret < 0)
				return
				    gnutls_assert_val
				    (GNUTLS_E_SELF_TEST_ERROR);

			if (memcmp(tmp, tmp2, vectors[i].plaintext_size) != 0) {
				_gnutls_debug_log("compat: %s vector %d in-place encryption failed!\n", gnutls_cipher_get_name(cipher), i);
				FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
					"compat - vector %d in-place encryption", i);
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			} else {
				FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher",
					"compat - vector %d in-place encryption", i);
			}

			/* check decryption with separate buffers */
			gnutls_cipher_set_iv(hd, (void*)vectors[i].iv, vectors[i].iv_size);

			if (vectors[i].auth_size) {
				ret = gnutls_cipher_add_auth(hd, vectors[i].auth, vectors[i].auth_size);
				if (ret < 0)
					return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}

			if (fips_request_failure(gnutls_cipher_get_name(cipher), "decrypt-separate-compat")) {
				/* Flip one bit in the ciphertext. */
				tmp[0] ^= 0x1;
			}

			ret =
			    gnutls_cipher_decrypt2(hd, tmp, vectors[i].plaintext_size,
						   tmp2, sizeof(tmp2));
			if (ret < 0)
				return
				    gnutls_assert_val
				    (GNUTLS_E_SELF_TEST_ERROR);

			if (memcmp(tmp2, vectors[i].plaintext, vectors[i].plaintext_size) != 0) {
				_gnutls_debug_log("compat: %s test vector %d failed (decryption)!\n",
					gnutls_cipher_get_name(cipher), i);
				FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
					"compat - test vector %d (decryption)", i);
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			} else {
				FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher",
					"compat - test vector %d (decryption)", i);
			}

			/* check in-place decryption */
			if (vectors[i].plaintext_size > 0) {
				if (vectors[i].iv_size > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "IV-decrypt-in-place-compat")) {
					if (vectors[i].iv_size > sizeof(fail_tmp)) {
						return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
					}
					memcpy(fail_tmp, vectors[i].iv, vectors[i].iv_size);
					/* Flip one IV bit. */
					fail_tmp[0] ^= 0x1;
					gnutls_cipher_set_iv(hd, (void*)fail_tmp, vectors[i].iv_size);
				} else {
					gnutls_cipher_set_iv(hd, (void*)vectors[i].iv, vectors[i].iv_size);
				}

				if (vectors[i].auth_size) {
					ret = gnutls_cipher_add_auth(hd, vectors[i].auth, vectors[i].auth_size);
					if (ret < 0)
						return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
				}

				memcpy(tmp2, tmp, vectors[i].plaintext_size);

				if (fips_request_failure(gnutls_cipher_get_name(cipher), "decrypt-in-place-compat")) {
					/* Flip one bit in the ciphertext. */
					tmp2[0] ^= 0x1;
				}

				ret = gnutls_cipher_decrypt(hd, tmp2, vectors[i].plaintext_size);
				if (ret < 0)
					return
					    gnutls_assert_val
					    (GNUTLS_E_SELF_TEST_ERROR);

				if (memcmp(tmp2, vectors[i].plaintext, vectors[i].plaintext_size) != 0) {
					_gnutls_debug_log("compat: %s vector %d in-place decryption failed!\n", gnutls_cipher_get_name(cipher), i);
					FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
						"compat - vector %d in-place decryption", i);
					return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
				} else {
					FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher",
						"compat - vector %d in-place decryption", i);
				}
			}
		}

		gnutls_cipher_deinit(hd);
	}

	_gnutls_debug_log
	    ("%s compat self check succeeded\n",
	     gnutls_cipher_get_name(cipher));

	return 0;

}

#define IOV_PARTS 8
/* AEAD modes - scatter read */
static int test_cipher_aead_scatter(gnutls_cipher_algorithm_t cipher,
				    const struct cipher_aead_vectors_st *vectors,
				    size_t vectors_size, unsigned flags)
{
	gnutls_aead_cipher_hd_t hd;
	int ret;
	unsigned int i, z;
	uint8_t tmp[384];
	uint8_t fail_tmp[384];
	gnutls_datum_t key, iv;
	size_t s;
	unsigned tag_size;
	giovec_t auth_iov[IOV_PARTS];
	int auth_iov_len;
	int iov_len;
	giovec_t iov[IOV_PARTS];
	const uint8_t *tag;
	uint8_t *ciphertext;

	_gnutls_debug_log("running scatter (iovec) tests for: %s\n",
				  gnutls_cipher_get_name(cipher));

	for (i = 0; i < vectors_size; i++) {
		memset(tmp, 0, sizeof(tmp));
		key.data = (void *) vectors[i].key;
		key.size = vectors[i].key_size;

		iv.data = (void *) vectors[i].iv;
		iv.size = vectors[i].iv_size;
		if (iv.size > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "IV-encrypt-scatter")) {
			if (iv.size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, iv.data, iv.size);
			/* Flip one IV bit. */
			fail_tmp[0] ^= 0x1;
			iv.data = (void *)fail_tmp;
		}

		tag_size = vectors[i].tag_size;

		if (tag_size > gnutls_cipher_get_tag_size(cipher)) {
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		ret = gnutls_aead_cipher_init(&hd, cipher, &key);
		if (ret < 0) {
			_gnutls_debug_log("error initializing: %s\n",
					  gnutls_cipher_get_name(cipher));
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		s = sizeof(tmp);

		/* single vector */
		auth_iov_len = 1;
		auth_iov[0].iov_base = (void*)vectors[i].auth;
		auth_iov[0].iov_len = vectors[i].auth_size;

		if (vectors[i].auth_size > 0 &&  fips_request_failure(gnutls_cipher_get_name(cipher), "auth-encrypt-scatter")) {
			if (vectors[i].auth_size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, vectors[i].auth, vectors[i].auth_size);
			/* Flip one bit in the auth vector. */
			fail_tmp[0] ^= 0x1;
			auth_iov[0].iov_base = (void*)fail_tmp;
		}

		iov_len = 1;
		iov[0].iov_base = (void*)vectors[i].plaintext;
		iov[0].iov_len = vectors[i].plaintext_size;

		if (vectors[i].plaintext_size > 0 &&  fips_request_failure(gnutls_cipher_get_name(cipher), "encrypt-scatter")) {
			if (vectors[i].plaintext_size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, vectors[i].plaintext, vectors[i].plaintext_size);
			/* Flip one bit in the plaintext vector. */
			fail_tmp[0] ^= 0x1;
			iov[0].iov_base = (void*)fail_tmp;
		}

		ret =
		    gnutls_aead_cipher_encryptv(hd,
						iv.data, iv.size,
						auth_iov, auth_iov_len,
						vectors[i].tag_size,
						iov, iov_len,
						tmp, &s);
		if (ret < 0)
			return
			    gnutls_assert_val
			    (GNUTLS_E_SELF_TEST_ERROR);

		if (s != vectors[i].plaintext_size + tag_size) {
			return
			    gnutls_assert_val
			    (GNUTLS_E_SELF_TEST_ERROR);
		}

		if (vectors[i].tag_prepended)
			tag = tmp;
		else
			tag = tmp+vectors[i].plaintext_size;

		if (memcmp(tag, vectors[i].tag, tag_size) != 0) {
			_gnutls_debug_log
			    ("%s test vector %d failed (tag)!\n",
			     gnutls_cipher_get_name(cipher), i);
			FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
				"test vector %d encrypt", i);
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		} else {
			FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher",
				"test vector %d encrypt", i);
		}

		if (vectors[i].tag_prepended)
			ciphertext = tmp+vectors[i].tag_size;
		else
			ciphertext = tmp;

		if (vectors[i].plaintext_size > 0) {
			if (memcmp
			    (ciphertext, vectors[i].ciphertext,
			     vectors[i].plaintext_size) != 0) {
				_gnutls_debug_log
				    ("%s test vector %d failed!\n",
				     gnutls_cipher_get_name(cipher), i);
				FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
					"test vector %d", i);
				return
				    gnutls_assert_val
				    (GNUTLS_E_SELF_TEST_ERROR);
			} else {
				FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher",
					"test vector %d", i);
			}
		}

		/* multi-vector */
		auth_iov_len = 0;
		if (vectors[i].auth_size > IOV_PARTS) {
			unsigned split = vectors[i].auth_size / IOV_PARTS;
			assert(split>0);
			for (z=0;z<IOV_PARTS;z++) {
				auth_iov[z].iov_base = (void*)(vectors[i].auth+(z*split));
				if (z==IOV_PARTS-1)
					auth_iov[z].iov_len = vectors[i].auth_size - z*split;
				else
					auth_iov[z].iov_len = split;
				auth_iov_len++;
			}
		} else {
			auth_iov_len = 1;
			auth_iov[0].iov_base = (void*)vectors[i].auth;
			auth_iov[0].iov_len = vectors[i].auth_size;
		}

		if (auth_iov[0].iov_len > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "auth-encrypt-multi-scatter")) {
			if (auth_iov[0].iov_len > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, auth_iov[0].iov_base, auth_iov[0].iov_len);
			/* Flip one bit in the auth vector. */
			fail_tmp[0] ^= 0x1;
			auth_iov[0].iov_base = (void*)fail_tmp;
		}

		iov_len = 0;
		if (vectors[i].plaintext_size > IOV_PARTS) {
			unsigned split = vectors[i].plaintext_size / IOV_PARTS;
			assert(split>0);

			for (z=0;z<IOV_PARTS;z++) {
				iov[z].iov_base = (void*)(vectors[i].plaintext+(z*split));
				if (z==IOV_PARTS-1)
					iov[z].iov_len = vectors[i].plaintext_size - z*split;
				else
					iov[z].iov_len = split;
				iov_len++;
			}
		} else {
			iov_len = 1;
			iov[0].iov_base = (void*)vectors[i].plaintext;
			iov[0].iov_len = vectors[i].plaintext_size;
		}

		if (iov[0].iov_len > 0 &&  fips_request_failure(gnutls_cipher_get_name(cipher), "encrypt-multi-scatter")) {
			if (iov[0].iov_len > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, iov[0].iov_base, iov[0].iov_len);
			/* Flip one bit in the plaintext vector. */
			fail_tmp[0] ^= 0x1;
			iov[0].iov_base = (void*)fail_tmp;
		}

		s = sizeof(tmp);

		ret =
		    gnutls_aead_cipher_encryptv(hd,
						iv.data, iv.size,
						auth_iov, auth_iov_len,
						vectors[i].tag_size,
						iov, iov_len,
						tmp, &s);
		if (ret < 0)
			return
			    gnutls_assert_val
			    (GNUTLS_E_SELF_TEST_ERROR);

		if (s != vectors[i].plaintext_size + tag_size) {
			return
			    gnutls_assert_val
			    (GNUTLS_E_SELF_TEST_ERROR);
		}

		if (vectors[i].tag_prepended)
			tag = tmp;
		else
			tag = tmp+vectors[i].plaintext_size;

		if (memcmp(tag, vectors[i].tag, tag_size) != 0) {
			_gnutls_debug_log
			    ("%s test vector %d failed (tag)!\n",
			     gnutls_cipher_get_name(cipher), i);
			FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
				"test vector %d (tag)", i);
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		} else {
			FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher",
				"test vector %d (tag)", i);
		}

		if (vectors[i].tag_prepended)
			ciphertext = tmp+vectors[i].tag_size;
		else
			ciphertext = tmp;

		if (vectors[i].plaintext_size > 0) {
			if (memcmp
			    (ciphertext, vectors[i].ciphertext,
			     vectors[i].plaintext_size) != 0) {
				_gnutls_debug_log
				    ("%s test vector %d failed!\n",
				     gnutls_cipher_get_name(cipher), i);

				FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
					"test vector %d", i);
				return
				    gnutls_assert_val
				    (GNUTLS_E_SELF_TEST_ERROR);
			} else {
				FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher",
					"test vector %d", i);
			}
		}



		gnutls_aead_cipher_deinit(hd);
	}

	_gnutls_debug_log
	    ("%s scatter self check succeeded\n",
	     gnutls_cipher_get_name(cipher));

	if (flags & GNUTLS_SELF_TEST_FLAG_NO_COMPAT)
		return 0;
	else
		return test_cipher_aead_compat(cipher, vectors, vectors_size);
}

/* AEAD modes */
static int test_cipher_aead(gnutls_cipher_algorithm_t cipher,
			    const struct cipher_aead_vectors_st *vectors,
			    size_t vectors_size, unsigned flags)
{
	gnutls_aead_cipher_hd_t hd;
	int ret;
	unsigned int i;
	uint8_t tmp[384];
	uint8_t tmp2[384];
	uint8_t fail_tmp[384];
	gnutls_datum_t key, iv;
	size_t s, s2;
	const uint8_t *tag;
	unsigned tag_size;
	uint8_t *ciphertext;

	_gnutls_debug_log("running tests for: %s\n",
				  gnutls_cipher_get_name(cipher));

	for (i = 0; i < vectors_size; i++) {
		memset(tmp, 0, sizeof(tmp));
		key.data = (void *) vectors[i].key;
		key.size = vectors[i].key_size;

		iv.data = (void *) vectors[i].iv;
		iv.size = vectors[i].iv_size;
		if (iv.size > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "IV-encrypt-aead")) {
			if (iv.size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, iv.data, iv.size);
			/* Flip one IV bit. */
			fail_tmp[0] ^= 0x1;
			iv.data = (void *)fail_tmp;
		}

		tag_size = vectors[i].tag_size;

		if (tag_size > gnutls_cipher_get_tag_size(cipher)) {
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}
#if 0
		if (iv.size != vectors[i].iv_size)
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
#endif
		ret = gnutls_aead_cipher_init(&hd, cipher, &key);
		if (ret < 0) {
			_gnutls_debug_log("error initializing: %s\n",
					  gnutls_cipher_get_name(cipher));
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		s = sizeof(tmp);

		if (vectors[i].auth_size > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "auth-encrypt-aead")) {
			if (vectors[i].auth_size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, vectors[i].auth, vectors[i].auth_size);
			/* Flip one auth bit. */
			fail_tmp[0] ^= 0x1;
			ret =
			    gnutls_aead_cipher_encrypt(hd,
					   iv.data, iv.size,
					   fail_tmp, vectors[i].auth_size,
					   vectors[i].tag_size,
					   vectors[i].plaintext,
					   vectors[i].plaintext_size,
					   tmp, &s);
		} else if (vectors[i].plaintext_size > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "encrypt-aead")) {
			if (vectors[i].plaintext_size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, vectors[i].plaintext, vectors[i].plaintext_size);
			/* Flip one plaintext bit. */
			fail_tmp[0] ^= 0x1;
			ret =
			    gnutls_aead_cipher_encrypt(hd,
					   iv.data, iv.size,
					   vectors[i].auth, vectors[i].auth_size,
					   vectors[i].tag_size,
					   fail_tmp,
					   vectors[i].plaintext_size,
					   tmp, &s);
		} else {
			ret =
			    gnutls_aead_cipher_encrypt(hd,
					   iv.data, iv.size,
					   vectors[i].auth, vectors[i].auth_size,
					   vectors[i].tag_size,
					   vectors[i].plaintext,
					   vectors[i].plaintext_size,
					   tmp, &s);
		}
		if (ret < 0)
			return
			    gnutls_assert_val
			    (GNUTLS_E_SELF_TEST_ERROR);

		if (s != vectors[i].plaintext_size + tag_size) {
			return
			    gnutls_assert_val
			    (GNUTLS_E_SELF_TEST_ERROR);
		}

		if (vectors[i].tag_prepended)
			tag = tmp;
		else
			tag = tmp+vectors[i].plaintext_size;

		if (memcmp(tag, vectors[i].tag, tag_size) != 0) {
			_gnutls_debug_log
			    ("%s test vector %d failed (tag)!\n",
			     gnutls_cipher_get_name(cipher), i);
			FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
				"test vector %d (tag)", i);
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		} else {
			FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher",
				"test vector %d (tag)", i);
		}

		if (vectors[i].tag_prepended)
			ciphertext = tmp+vectors[i].tag_size;
		else
			ciphertext = tmp;

		if (vectors[i].plaintext_size > 0) {
			if (memcmp
			    (ciphertext, vectors[i].ciphertext,
			     vectors[i].plaintext_size) != 0) {
				_gnutls_debug_log
				    ("%s test vector %d failed!\n",
				     gnutls_cipher_get_name(cipher), i);

				FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
					"test vector %d", i);

				return
				    gnutls_assert_val
				    (GNUTLS_E_SELF_TEST_ERROR);
			} else {
				FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher",
					"test vector %d", i);
			}
		}

		/* check decryption */
		{
			s2 = sizeof(tmp2);

			if (iv.size > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "IV-decrypt-aead")) {
				if (iv.size > sizeof(fail_tmp)) {
					return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
				}
				memcpy(fail_tmp, iv.data, iv.size);
				/* Flip one IV bit. */
				fail_tmp[0] ^= 0x1;
				iv.data = (void *)fail_tmp;
			}

			if (vectors[i].auth_size > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "auth-decrypt-aead")) {
				if (vectors[i].auth_size > sizeof(fail_tmp)) {
					return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
				}
				memcpy(fail_tmp, vectors[i].auth, vectors[i].auth_size);
				/* Flip one auth bit. */
				fail_tmp[0] ^= 0x1;
				ret =
				    gnutls_aead_cipher_decrypt(hd,
						   iv.data, iv.size,
						   fail_tmp, vectors[i].auth_size,
						   vectors[i].tag_size,
						   tmp, s,
						   tmp2, &s2);
			} else if (vectors[i].plaintext_size > 0 && fips_request_failure(gnutls_cipher_get_name(cipher), "decrypt-aead")) {
				/* Flip one ciphertext bit. */
				tmp[0] ^= 0x1;
				ret =
				    gnutls_aead_cipher_decrypt(hd,
						   iv.data, iv.size,
						   vectors[i].auth, vectors[i].auth_size,
						   vectors[i].tag_size,
						   tmp, s,
						   tmp2, &s2);
			} else {
				ret =
				    gnutls_aead_cipher_decrypt(hd,
						   iv.data, iv.size,
						   vectors[i].auth, vectors[i].auth_size,
						   vectors[i].tag_size,
						   tmp, s,
						   tmp2, &s2);
			}
			if (ret < 0) {
				/*
				 * Changing the IV, auth or ciphertext causes
				 * gnutls_aead_cipher_decrypt() to return GNUTLS_E_DECRYPTION_FAILED
				 * as it breaks the tag validation. So we need to log
				 * the failure here, not in the memcmp below.
				 */
				FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
					"test vector %d (decryption)", i);
				return
				    gnutls_assert_val
				    (GNUTLS_E_SELF_TEST_ERROR);
			}

			if (s2 != vectors[i].plaintext_size ||
			    (vectors[i].plaintext_size > 0 &&
			     memcmp(tmp2, vectors[i].plaintext, vectors[i].plaintext_size) != 0)) {
				_gnutls_debug_log("%s test vector %d failed (decryption)!\n",
					gnutls_cipher_get_name(cipher), i);
				FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
					"test vector %d (decryption)", i);
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			} else {
				FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher",
					"test vector %d (decryption)", i);
			}

			/* test tag verification */
			if (s > 0) {
				(*ciphertext)++;

				s2 = sizeof(tmp2);
				ret =
				    gnutls_aead_cipher_decrypt(hd,
							   iv.data, iv.size,
							   vectors[i].auth, vectors[i].auth_size,
							   vectors[i].tag_size,
							   tmp, s,
							   tmp2, &s2);

				if (ret >= 0) {
					_gnutls_debug_log("%s: tag check failed\n", gnutls_cipher_get_name(cipher));
					FIPSLOG_FAILED(gnutls_cipher_get_name(cipher), "cipher",
						"test vector %d (tag verification)", i);
					return
					    gnutls_assert_val
					    (GNUTLS_E_SELF_TEST_ERROR);
				} else {
					FIPSLOG_SUCCESS(gnutls_cipher_get_name(cipher), "cipher",
						"test vector %d (tag verification)", i);
				}
			}
		}

		gnutls_aead_cipher_deinit(hd);
	}

	_gnutls_debug_log
	    ("%s self check succeeded\n",
	     gnutls_cipher_get_name(cipher));

	return test_cipher_aead_scatter(cipher, vectors, vectors_size, flags);
}



struct hash_vectors_st {
	const uint8_t *plaintext;
	unsigned int plaintext_size;
	const uint8_t *output;
	unsigned int output_size;
};

const struct hash_vectors_st md5_vectors[] = {
	{
	 STR(plaintext, plaintext_size, "abcdefghijklmnopqrstuvwxyz"),
	 STR(output, output_size,
	     "\xc3\xfc\xd3\xd7\x61\x92\xe4\x00\x7d\xfb\x49\x6c\xca\x67\xe1\x3b"),
	 },
};

const struct hash_vectors_st sha1_vectors[] = {
	{
	 STR(plaintext, plaintext_size, "what do ya want for nothing?"),
	 STR(output, output_size,
	     "\x8f\x82\x03\x94\xf9\x53\x35\x18\x20\x45\xda\x24\xf3\x4d\xe5\x2b\xf8\xbc\x34\x32"),
	 },
	{
	 STR(plaintext, plaintext_size,
	     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
	 STR(output, output_size,
	     "\xbe\xae\xd1\x6d\x65\x8e\xc7\x92\x9e\xdf\xd6\x2b\xfa\xfe\xac\x29\x9f\x0d\x74\x4d"),
	 },
};

const struct hash_vectors_st sha224_vectors[] = {
	{
	 STR(plaintext, plaintext_size,
	     "The quick brown fox jumps over the lazy dog"),
	 STR(output, output_size,
	     "\x73\x0e\x10\x9b\xd7\xa8\xa3\x2b\x1c\xb9\xd9\xa0\x9a\xa2\x32\x5d\x24\x30\x58\x7d\xdb\xc0\xc3\x8b\xad\x91\x15\x25"),
	 },
};

const struct hash_vectors_st sha256_vectors[] = {
	{
	 STR(plaintext, plaintext_size,
	     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
	 STR(output, output_size,
	     "\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1"),
	 },
	{
	 STR(plaintext, plaintext_size,
	     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
	 STR(output, output_size,
	     "\x50\xea\x82\x5d\x96\x84\xf4\x22\x9c\xa2\x9f\x1f\xec\x51\x15\x93\xe2\x81\xe4\x6a\x14\x0d\x81\xe0\x00\x5f\x8f\x68\x86\x69\xa0\x6c"),
	 },
};

const struct hash_vectors_st sha384_vectors[] = {
	{
	 STR(plaintext, plaintext_size,
	     "The quick brown fox jumps over the lazy dog"),
	 STR(output, output_size,
	     "\xca\x73\x7f\x10\x14\xa4\x8f\x4c\x0b\x6d\xd4\x3c\xb1\x77\xb0\xaf\xd9\xe5\x16\x93\x67\x54\x4c\x49\x40\x11\xe3\x31\x7d\xbf\x9a\x50\x9c\xb1\xe5\xdc\x1e\x85\xa9\x41\xbb\xee\x3d\x7f\x2a\xfb\xc9\xb1"),
	 },
};

const struct hash_vectors_st sha512_vectors[] = {
	{
	 STR(plaintext, plaintext_size,
	     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
	 STR(output, output_size,
	     "\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc\x14\x3f\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae\xad\xb6\x88\x90\x18\x50\x1d\x28\x9e\x49\x00\xf7\xe4\x33\x1b\x99\xde\xc4\xb5\x43\x3a\xc7\xd3\x29\xee\xb6\xdd\x26\x54\x5e\x96\xe5\x5b\x87\x4b\xe9\x09"),
	 },
};

const struct hash_vectors_st sha3_224_vectors[] = {
	{
	 STR(plaintext, plaintext_size,
	     "\xC1\xEC\xFD\xFC"),
	 STR(output, output_size,
	     "\xA3\x3C\x58\xDF\x8A\x80\x26\xF0\xF9\x59\x19\x66\xBD\x6D\x00\xEE\xD3\xB1\xE8\x29\x58\x0A\xB9\xBE\x26\x8C\xAF\x39"),
	 },
};

const struct hash_vectors_st sha3_256_vectors[] = {
	{
	 STR(plaintext, plaintext_size,
	     "\xC1\xEC\xFD\xFC"),
	 STR(output, output_size,
	     "\xC5\x85\x9B\xE8\x25\x60\xCC\x87\x89\x13\x3F\x7C\x83\x4A\x6E\xE6\x28\xE3\x51\xE5\x04\xE6\x01\xE8\x05\x9A\x06\x67\xFF\x62\xC1\x24"),
	 }
};

const struct hash_vectors_st sha3_384_vectors[] = {
	{
	 STR(plaintext, plaintext_size,
	     "\x4A\x4F\x20\x24\x84\x51\x25\x26"),
	 STR(output, output_size,
	     "\x89\xDB\xF4\xC3\x9B\x8F\xB4\x6F\xDF\x0A\x69\x26\xCE\xC0\x35\x5A\x4B\xDB\xF9\xC6\xA4\x46\xE1\x40\xB7\xC8\xBD\x08\xFF\x6F\x48\x9F\x20\x5D\xAF\x8E\xFF\xE1\x60\xF4\x37\xF6\x74\x91\xEF\x89\x7C\x23"),
	 },
};

const struct hash_vectors_st sha3_512_vectors[] = {
	{
	 STR(plaintext, plaintext_size,
	     "\x82\xE1\x92\xE4\x04\x3D\xDC\xD1\x2E\xCF\x52\x96\x9D\x0F\x80\x7E\xED"),
	 STR(output, output_size,
	     "\x96\x44\xE3\xC9\x0B\x67\xE2\x21\x24\xE9\x6D\xFE\xDC\xE5\x3D\x33\xC4\x60\xF1\x32\x86\x8F\x09\x75\xD1\x8B\x22\xCF\xD5\x9F\x63\x7D\xD8\x5A\xA4\x05\xE3\x98\x08\xA4\x55\x70\xA4\x98\xC0\xB8\xF2\xCB\xA5\x9F\x8E\x14\x37\xEA\xEF\x89\xF2\x0B\x88\x29\x8A\xDF\xA2\xDE"),
	 },
};

const struct hash_vectors_st gostr_94_vectors[] = {
	{
	 STR(plaintext, plaintext_size,
	     "The quick brown fox jumps over the lazy dog"),
	 STR(output, output_size,
	     "\x90\x04\x29\x4a\x36\x1a\x50\x8c\x58\x6f\xe5\x3d\x1f\x1b\x02\x74\x67\x65\xe7\x1b\x76\x54\x72\x78\x6e\x47\x70\xd5\x65\x83\x0a\x76"),
	},
};

/* GOST R 34.11-2012 */
const struct hash_vectors_st streebog_512_vectors[] = {
	{
            STR(plaintext, plaintext_size,
		"\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee"
		"\xe6\xe8\x20\xe2\xed\xf3\xf6\xe8\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20"
		"\xf1\x20\xec\xee\xf0\xff\x20\xf1\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20"
		"\xed\xe0\x20\xf5\xf0\xe0\xe1\xf0\xfb\xff\x20\xef\xeb\xfa\xea\xfb"
		"\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb"),
            STR(output, output_size,
		"\x1e\x88\xe6\x22\x26\xbf\xca\x6f\x99\x94\xf1\xf2\xd5\x15\x69\xe0"
		"\xda\xf8\x47\x5a\x3b\x0f\xe6\x1a\x53\x00\xee\xe4\x6d\x96\x13\x76"
		"\x03\x5f\xe8\x35\x49\xad\xa2\xb8\x62\x0f\xcd\x7c\x49\x6c\xe5\xb3"
		"\x3f\x0c\xb9\xdd\xdc\x2b\x64\x60\x14\x3b\x03\xda\xba\xc9\xfb\x28"),
	},
	{
            STR(plaintext, plaintext_size,
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"),
            STR(output, output_size,
		"\x90\xa1\x61\xd1\x2a\xd3\x09\x49\x8d\x3f\xe5\xd4\x82\x02\xd8\xa4"
		"\xe9\xc4\x06\xd6\xa2\x64\xae\xab\x25\x8a\xc5\xec\xc3\x7a\x79\x62"
		"\xaa\xf9\x58\x7a\x5a\xbb\x09\xb6\xbb\x81\xec\x4b\x37\x52\xa3\xff"
		"\x5a\x83\x8e\xf1\x75\xbe\x57\x72\x05\x6b\xc5\xfe\x54\xfc\xfc\x7e"),
	},
};

/* GOST R 34.11-2012 */
const struct hash_vectors_st streebog_256_vectors[] = {
	{
            STR(plaintext, plaintext_size,
		"\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee"
		"\xe6\xe8\x20\xe2\xed\xf3\xf6\xe8\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20"
		"\xf1\x20\xec\xee\xf0\xff\x20\xf1\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20"
		"\xed\xe0\x20\xf5\xf0\xe0\xe1\xf0\xfb\xff\x20\xef\xeb\xfa\xea\xfb"
		"\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb"),
            STR(output, output_size,
		"\x9d\xd2\xfe\x4e\x90\x40\x9e\x5d\xa8\x7f\x53\x97\x6d\x74\x05\xb0"
		"\xc0\xca\xc6\x28\xfc\x66\x9a\x74\x1d\x50\x06\x3c\x55\x7e\x8f\x50"),
	},
};

#define HASH_DATA_SIZE 64

/* SHA1 and other hashes */
static int test_digest(gnutls_digest_algorithm_t dig,
		       const struct hash_vectors_st *vectors,
		       size_t vectors_size, unsigned flags)
{
	uint8_t data[HASH_DATA_SIZE];
	unsigned int i;
	int ret;
	size_t data_size;
	gnutls_hash_hd_t hd;
	gnutls_hash_hd_t copy;
	uint8_t fail_tmp[512];

	if (_gnutls_digest_exists(dig) == 0)
		return 0;

	for (i = 0; i < vectors_size; i++) {
		ret = gnutls_hash_init(&hd, dig);
		if (ret < 0) {
			_gnutls_debug_log("error initializing: %s\n",
					  gnutls_digest_get_name(dig));
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		ret = gnutls_hash(hd, vectors[i].plaintext, 1);
		if (ret < 0)
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

		copy = gnutls_hash_copy(hd);
		/* Returning NULL is not an error here for the time being, but
		 * it might become one later */
		if (!copy && secure_getenv("GNUTLS_TEST_SUITE_RUN"))
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

		if (fips_request_failure(gnutls_digest_get_name(dig), "digest")) {
			if (vectors[i].plaintext_size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, vectors[i].plaintext, vectors[i].plaintext_size);
			/* Flip a bit being passed to the hash fn. */
			fail_tmp[1] ^= 0x1;
			ret = gnutls_hash(hd,
				  &fail_tmp[1],
				  vectors[i].plaintext_size - 1);
		} else {
			ret = gnutls_hash(hd,
				  &vectors[i].plaintext[1],
				  vectors[i].plaintext_size - 1);
		}
		if (ret < 0)
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

		gnutls_hash_deinit(hd, data);

		data_size = gnutls_hash_get_len(dig);
		if (data_size <= 0)
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

		if (data_size != vectors[i].output_size ||
		    memcmp(data, vectors[i].output,
			   vectors[i].output_size) != 0) {
			_gnutls_debug_log("%s test vector %d failed!\n",
					  gnutls_digest_get_name(dig), i);
			FIPSLOG_FAILED(gnutls_digest_get_name(dig), "digest",
					"comparison failed for test vector %d", i);
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		} else {
			FIPSLOG_SUCCESS(gnutls_digest_get_name(dig), "digest",
					"test vector %d", i);
		}

		if (copy != NULL) {
			if (fips_request_failure(gnutls_digest_get_name(dig), "digest-copy")) {
				if (vectors[i].plaintext_size > sizeof(fail_tmp)) {
					return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
				}
				memcpy(fail_tmp, vectors[i].plaintext, vectors[i].plaintext_size);
				/* Flip a bit being passed to the hash fn. */
				fail_tmp[1] ^= 0x1;
				ret = gnutls_hash(copy,
					  &fail_tmp[1],
					  vectors[i].plaintext_size - 1);
			} else {
				ret = gnutls_hash(copy,
					  &vectors[i].plaintext[1],
					  vectors[i].plaintext_size - 1);
			}
			if (ret < 0)
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

			memset(data, 0xaa, data_size);
			gnutls_hash_deinit(copy, data);

			if (memcmp(data, vectors[i].output,
			    vectors[i].output_size) != 0) {
				_gnutls_debug_log("%s copy test vector %d failed!\n",
						  gnutls_digest_get_name(dig), i);
				FIPSLOG_FAILED(gnutls_digest_get_name(dig), "digest",
					"comparison failed for copy test vector %d", i);
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			} else {
				FIPSLOG_SUCCESS(gnutls_digest_get_name(dig), "digest",
					"copy test vector %d", i);
			}
		}
	}

	_gnutls_debug_log("%s self check succeeded\n",
			  gnutls_digest_get_name(dig));

	return 0;
}


struct mac_vectors_st {
	const uint8_t *key;
	unsigned int key_size;
	const uint8_t *nonce;
	unsigned int nonce_size;
	const uint8_t *plaintext;
	unsigned int plaintext_size;
	const uint8_t *output;
	unsigned int output_size;
};

const struct mac_vectors_st hmac_md5_vectors[] = {
	{
	 STR(key, key_size, "Jefe"),
	 STR(plaintext, plaintext_size, "what do ya want for nothing?"),
	 STR(output, output_size,
	     "\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38"),
	 },
};

const struct mac_vectors_st hmac_sha1_vectors[] = {
	{
	 STR(key, key_size,
	     "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
	 STR(plaintext, plaintext_size, "Hi There"),
	 STR(output, output_size,
	     "\x67\x5b\x0b\x3a\x1b\x4d\xdf\x4e\x12\x48\x72\xda\x6c\x2f\x63\x2b\xfe\xd9\x57\xe9"),
	 },
};

	    /* from rfc4231 */
const struct mac_vectors_st hmac_sha224_vectors[] = {
	{
	 STR(key, key_size,
	     "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
	 STR(plaintext, plaintext_size, "Hi There"),
	 STR(output, output_size,
	     "\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f\x47\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22"),
	 },
};

const struct mac_vectors_st hmac_sha256_vectors[] = {
	{
	 STR(key, key_size,
	     "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
	 STR(plaintext, plaintext_size, "Hi There"),
	 STR(output, output_size,
	     "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7"),
	 },
};

const struct mac_vectors_st hmac_sha384_vectors[] = {
	{
	 STR(key, key_size,
	     "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
	 STR(plaintext, plaintext_size, "Hi There"),
	 STR(output, output_size,
	     "\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6"),
	 },
};

const struct mac_vectors_st hmac_sha512_vectors[] = {
	{
	 STR(key, key_size,
	     "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
	 STR(plaintext, plaintext_size, "Hi There"),
	 STR(output, output_size,
	     "\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54"),
	 },
};

/* Calculated */
const struct mac_vectors_st hmac_gostr_94_vectors[] = {
	{
	 STR(key, key_size,
	     "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	     "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"),
	 STR(plaintext, plaintext_size,
	     "\x01\x26\xbd\xb8\x78\x00\xaf\x21\x43\x41\x45\x65\x63\x78\x01\x00"),
	 STR(output, output_size,
	     "\xba\xd7\x0b\x61\xc4\x10\x95\xbc\x47\xe1\x14\x1c\xfa\xed\x42\x72"
	     "\x6a\x5c\xee\xbd\x62\xce\x75\xdb\xbb\x9a\xd7\x6c\xda\x9f\x72\xf7"),
	},
};

/* RFC 7836 */
const struct mac_vectors_st hmac_streebog_512_vectors[] = {
	{
	 STR(key, key_size,
	     "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	     "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"),
	 STR(plaintext, plaintext_size,
	     "\x01\x26\xbd\xb8\x78\x00\xaf\x21\x43\x41\x45\x65\x63\x78\x01\x00"),
	 STR(output, output_size,
	     "\xa5\x9b\xab\x22\xec\xae\x19\xc6\x5f\xbd\xe6\xe5\xf4\xe9\xf5\xd8"
	     "\x54\x9d\x31\xf0\x37\xf9\xdf\x9b\x90\x55\x00\xe1\x71\x92\x3a\x77"
	     "\x3d\x5f\x15\x30\xf2\xed\x7e\x96\x4c\xb2\xee\xdc\x29\xe9\xad\x2f"
	     "\x3a\xfe\x93\xb2\x81\x4f\x79\xf5\x00\x0f\xfc\x03\x66\xc2\x51\xe6"),
	},
};

/* RFC 7836 */
const struct mac_vectors_st hmac_streebog_256_vectors[] = {
	{
	 STR(key, key_size,
	     "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	     "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"),
	 STR(plaintext, plaintext_size,
	     "\x01\x26\xbd\xb8\x78\x00\xaf\x21\x43\x41\x45\x65\x63\x78\x01\x00"),
	 STR(output, output_size,
	     "\xa1\xaa\x5f\x7d\xe4\x02\xd7\xb3\xd3\x23\xf2\x99\x1c\x8d\x45\x34"
	     "\x01\x31\x37\x01\x0a\x83\x75\x4f\xd0\xaf\x6d\x7c\xd4\x92\x2e\xd9"),
	},
};

const struct mac_vectors_st aes_cmac_128_vectors[] = { /* NIST SP800-38A */
	{
	 STR(key, key_size,
	     "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"),
	 STR(plaintext, plaintext_size,
             "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"),
	 STR(output, output_size,
	     "\x07\x0a\x16\xb4\x6b\x4d\x41\x44\xf7\x9b\xdd\x9d\xd0\x4a\x28\x7c"),
	 },
};

const struct mac_vectors_st aes_cmac_256_vectors[] = { /* NIST SP800-38A */
	{
	 STR(key, key_size,
	     "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
             "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4"),
	 STR(plaintext, plaintext_size,
             "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"),
	 STR(output, output_size,
	     "\x28\xa7\x02\x3f\x45\x2e\x8f\x82\xbd\x4b\xf2\x8d\x8c\x37\xc3\x5c"),
	 },
};

const struct mac_vectors_st aes_gmac_128_vectors[] = { /* NIST test vectors */
	{
	 STR(key, key_size,
	     "\x23\x70\xe3\x20\xd4\x34\x42\x08\xe0\xff\x56\x83\xf2\x43\xb2\x13"),
	 STR(nonce, nonce_size,
	     "\x04\xdb\xb8\x2f\x04\x4d\x30\x83\x1c\x44\x12\x28"),
	 STR(plaintext, plaintext_size,
	     "\xd4\x3a\x8e\x50\x89\xee\xa0\xd0\x26\xc0\x3a\x85\x17\x8b\x27\xda"),
	 STR(output, output_size,
	     "\x2a\x04\x9c\x04\x9d\x25\xaa\x95\x96\x9b\x45\x1d\x93\xc3\x1c\x6e"),
	},
};

const struct mac_vectors_st aes_gmac_192_vectors[] = { /* NIST test vectors */
	{
	 STR(key, key_size,
	     "\xaa\x92\x1c\xb5\xa2\x43\xab\x08\x91\x1f\x32\x89\x26\x6b\x39\xda"
	     "\xb1\x33\xf5\xc4\x20\xa6\xc5\xcd"),
	 STR(nonce, nonce_size,
	     "\x8f\x73\xdb\x68\xda\xee\xed\x2d\x15\x5f\xb1\xa0"),
	 STR(plaintext, plaintext_size,
	     "\x48\x74\x43\xc7\xc1\x4c\xe4\x74\xcb\x3d\x29\x1f\x25\x70\x70\xa2"),
	 STR(output, output_size,
	     "\xb1\x26\x74\xfb\xea\xc6\x88\x9a\x24\x94\x8f\x27\x92\xe3\x0a\x50"),
	},
};

const struct mac_vectors_st aes_gmac_256_vectors[] = { /* NIST test vectors */
	{
	 STR(key, key_size,
	     "\x6d\xfd\xaf\xd6\x70\x3c\x28\x5c\x01\xf1\x4f\xd1\x0a\x60\x12\x86"
	     "\x2b\x2a\xf9\x50\xd4\x73\x3a\xbb\x40\x3b\x2e\x74\x5b\x26\x94\x5d"),
	 STR(nonce, nonce_size,
	     "\x37\x49\xd0\xb3\xd5\xba\xcb\x71\xbe\x06\xad\xe6"),
	 STR(plaintext, plaintext_size,
	     "\xc0\xd2\x49\x87\x19\x92\xe7\x03\x02\xae\x00\x81\x93\xd1\xe8\x9f"),
	 STR(output, output_size,
	     "\x4a\xa4\xcc\x69\xf8\x4e\xe6\xac\x16\xd9\xbf\xb4\xe0\x5d\xe5\x00"),
	},
};

const struct mac_vectors_st gost28147_tc26z_imit_vectors[] = {
	{
		STR(key, key_size,
		    "\x9d\x05\xb7\x9e\x90\xca\xd0\x0a\x2c\xda\xd2\x2e\xf4\xe8\x6f\x5c"
		    "\xf5\xdc\x37\x68\x19\x85\xb3\xbf\xaa\x18\xc1\xc3\x05\x0a\x91\xa2"),
		STR(plaintext, plaintext_size,
		    "\xb5\xa1\xf0\xe3\xce\x2f\x02\x1d\x67\x61\x94\x34\x5c\x41\xe3\x6e"),
		STR(output, output_size,
		    "\x03\xe5\x67\x66"),
	},
};

static int test_mac(gnutls_mac_algorithm_t mac,
		    const struct mac_vectors_st *vectors,
		    size_t vectors_size, unsigned flags)
{
	uint8_t data[HASH_DATA_SIZE];
	unsigned int i;
	int ret;
	size_t data_size;
	gnutls_hmac_hd_t hd;
	gnutls_hmac_hd_t copy;
	uint8_t fail_tmp[512];

	for (i = 0; i < vectors_size; i++) {
		ret = gnutls_hmac_init(&hd,
				       mac, vectors[i].key,
				       vectors[i].key_size);

		if (ret < 0) {
			_gnutls_debug_log("error initializing: MAC-%s\n",
					  gnutls_mac_get_name(mac));
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		if (vectors[i].nonce_size > 0 && fips_request_failure(gnutls_mac_get_name(mac), "hmac-nonce")) {
			if (vectors[i].nonce_size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, vectors[i].nonce, vectors[i].nonce_size);
			/* Flip a bit in the nonce. */
			fail_tmp[0] ^= 0x1;
			gnutls_hmac_set_nonce(hd,
					      fail_tmp,
					      vectors[i].nonce_size);
		} else if (vectors[i].nonce_size) {
			gnutls_hmac_set_nonce(hd,
					      vectors[i].nonce,
					      vectors[i].nonce_size);
		}

		ret = gnutls_hmac(hd, vectors[i].plaintext, 1);
		if (ret < 0)
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

		copy = gnutls_hmac_copy(hd);
		/* Returning NULL is not an error here for the time being, but
		 * it might become one later */
		if (!copy && secure_getenv("GNUTLS_TEST_SUITE_RUN"))
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

		if (fips_request_failure(gnutls_mac_get_name(mac), "hmac")) {
			if (vectors[i].plaintext_size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, vectors[i].plaintext, vectors[i].plaintext_size);
			/* Flip a bit being passed to the hmac fn. */
			fail_tmp[1] ^= 0x1;
			ret = gnutls_hmac(hd,
				  &fail_tmp[1],
				  vectors[i].plaintext_size - 1);
		} else {
			ret = gnutls_hmac(hd,
				  &vectors[i].plaintext[1],
				  vectors[i].plaintext_size - 1);
		}
		if (ret < 0)
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

		gnutls_hmac_deinit(hd, data);

		data_size = gnutls_hmac_get_len(mac);
		if (data_size <= 0)
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

		if (data_size != vectors[i].output_size ||
		    memcmp(data, vectors[i].output,
			   vectors[i].output_size) != 0) {

			_gnutls_debug_log
			    ("MAC-%s test vector %d failed!\n",
			     gnutls_mac_get_name(mac), i);

			FIPSLOG_FAILED(gnutls_mac_get_name(mac), "mac",
				"comparison failed for MAC test vector %d", i);

			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		} else {
			FIPSLOG_SUCCESS(gnutls_mac_get_name(mac), "mac",
				"MAC test vector %d", i);
		}

		if (copy != NULL) {
			if (fips_request_failure(gnutls_mac_get_name(mac), "hmac-copy")) {
				if (vectors[i].plaintext_size > sizeof(fail_tmp)) {
					return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
				}
				memcpy(fail_tmp, vectors[i].plaintext, vectors[i].plaintext_size);
				/* Flip a bit being passed to the hmac fn. */
				fail_tmp[1] ^= 0x1;
				ret = gnutls_hmac(copy,
					  &fail_tmp[1],
					  vectors[i].plaintext_size - 1);
			} else {
				ret = gnutls_hmac(copy,
					  &vectors[i].plaintext[1],
					  vectors[i].plaintext_size - 1);
			}
			if (ret < 0)
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

			memset(data, 0xaa, data_size);
			gnutls_hmac_deinit(copy, data);

			if (memcmp(data, vectors[i].output,
			    vectors[i].output_size) != 0) {
				_gnutls_debug_log
					("MAC-%s copy test vector %d failed!\n",
					 gnutls_mac_get_name(mac), i);
				FIPSLOG_FAILED(gnutls_mac_get_name(mac), "mac",
					"comparison failed for MAC copy test vector %d", i);
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			} else {
				FIPSLOG_SUCCESS(gnutls_mac_get_name(mac), "mac",
					"MAC copy test vector %d", i);
			}
		}
	}

	_gnutls_debug_log
	    ("MAC-%s self check succeeded\n",
	     gnutls_mac_get_name(mac));

	return 0;
}

#define CASE(x, func, vectors) case x: \
		do { \
			FIPSLOG_SUCCESS(_specific_op_name, "POST", _op_name, "test started"); \
			ret = func(x, V(vectors), flags); \
			if (!(flags & GNUTLS_SELF_TEST_FLAG_ALL) || ret < 0) { \
				if (ret < 0) { \
					FIPSLOG_FAILED(_specific_op_name, "POST", _op_name, "test ended"); \
				} else { \
					FIPSLOG_SUCCESS(_specific_op_name, "POST", _op_name, "test ended"); \
				} \
				return ret; \
			} \
		} while(0)

#define CASE2(x, func, func2, vectors) case x:	  \
		do { \
			FIPSLOG_SUCCESS(_specific_op_name, "POST", _op_name, "test started"); \
			ret = func(x, V(vectors), flags); \
			if (ret < 0) { \
				FIPSLOG_FAILED(_specific_op_name, "POST", _op_name, "test ended"); \
				return ret; \
			} \
			ret = func2(x, V(vectors), flags); \
			if (!(flags & GNUTLS_SELF_TEST_FLAG_ALL) || ret < 0) { \
				if (ret < 0) { \
					FIPSLOG_FAILED(_specific_op_name, "POST", _op_name, "test ended"); \
				} else { \
					FIPSLOG_SUCCESS(_specific_op_name, "POST", _op_name, "test ended"); \
				} \
				return ret; \
			} \
		} while(0)

#define NON_FIPS_CASE(x, func, vectors) case x: \
			if (_gnutls_fips_mode_enabled() == 0) { \
				ret = func(x, V(vectors), flags); \
				if (!(flags & GNUTLS_SELF_TEST_FLAG_ALL) || ret < 0) \
					return ret; \
			}

/*-
 * gnutls_cipher_self_test:
 * @flags: GNUTLS_SELF_TEST_FLAG flags
 * @cipher: the encryption algorithm to use
 *
 * This function will run self tests on the provided cipher or all
 * available ciphers if @flags is %GNUTLS_SELF_TEST_FLAG_ALL.
 *
 * Returns: Zero or a negative error code on error.
 *
 * Since: 3.3.0-FIPS140
 -*/
int gnutls_cipher_self_test(unsigned flags, gnutls_cipher_algorithm_t cipher)
{
	int ret;
	const char *_specific_op_name = NULL;

	if (flags & GNUTLS_SELF_TEST_FLAG_ALL)
		cipher = GNUTLS_CIPHER_UNKNOWN;

	_specific_op_name = gnutls_cipher_get_name(cipher);
#undef _op_name
#define _op_name "cipher %s"

	switch (cipher) {
	case GNUTLS_CIPHER_UNKNOWN:
		CASE(GNUTLS_CIPHER_AES_128_CCM, test_cipher_aead,
		     aes128_ccm_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_CIPHER_AES_256_CCM, test_cipher_aead,
		     aes256_ccm_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_CIPHER_AES_128_CBC, test_cipher,
		     aes128_cbc_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_CIPHER_AES_192_CBC, test_cipher,
		     aes192_cbc_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_CIPHER_AES_256_CBC, test_cipher,
		     aes256_cbc_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_CIPHER_3DES_CBC, test_cipher,
		     tdes_cbc_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_CIPHER_ARCFOUR_128, test_cipher,
		     arcfour_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_CIPHER_AES_128_GCM, test_cipher_aead,
		     aes128_gcm_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_CIPHER_AES_192_GCM, test_cipher_aead,
		     aes192_gcm_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_CIPHER_AES_256_GCM, test_cipher_aead,
		     aes256_gcm_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_CIPHER_CHACHA20_POLY1305, test_cipher_aead,
		     chacha_poly1305_vectors);
		FALLTHROUGH;
		CASE2(GNUTLS_CIPHER_AES_128_CFB8, test_cipher,
		      test_cipher_all_block_sizes,
		      aes128_cfb8_vectors);
		FALLTHROUGH;
		CASE2(GNUTLS_CIPHER_AES_192_CFB8, test_cipher,
		      test_cipher_all_block_sizes,
		      aes192_cfb8_vectors);
		FALLTHROUGH;
		CASE2(GNUTLS_CIPHER_AES_256_CFB8, test_cipher,
		      test_cipher_all_block_sizes,
		      aes256_cfb8_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_CIPHER_AES_128_XTS, test_cipher,
		     aes128_xts_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_CIPHER_AES_256_XTS, test_cipher,
		     aes256_xts_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_CIPHER_AES_128_SIV, test_cipher_aead,
		     aes128_siv_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_CIPHER_AES_256_SIV, test_cipher_aead,
		     aes256_siv_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_CIPHER_CHACHA20_32, test_cipher,
		     chacha20_32_vectors);
		FALLTHROUGH;
		/* The same test vector for _32 variant should work */
		NON_FIPS_CASE(GNUTLS_CIPHER_CHACHA20_64, test_cipher,
		     chacha20_32_vectors);
#if ENABLE_GOST
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_CIPHER_GOST28147_CPA_CFB, test_cipher,
			      gost28147_cpa_cfb_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_CIPHER_GOST28147_CPB_CFB, test_cipher,
			      gost28147_cpb_cfb_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_CIPHER_GOST28147_CPC_CFB, test_cipher,
			      gost28147_cpc_cfb_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_CIPHER_GOST28147_CPD_CFB, test_cipher,
			      gost28147_cpd_cfb_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_CIPHER_GOST28147_TC26Z_CFB, test_cipher,
			      gost28147_tc26z_cfb_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_CIPHER_GOST28147_TC26Z_CNT, test_cipher,
			      gost28147_tc26z_cnt_vectors);
#endif
		break;
	default:
		return gnutls_assert_val(GNUTLS_E_NO_SELF_TEST);
	}

	return 0;
}

/*-
 * gnutls_mac_self_test:
 * @flags: GNUTLS_SELF_TEST_FLAG flags
 * @mac: the message authentication algorithm to use
 *
 * This function will run self tests on the provided mac.
 *
 * Returns: Zero or a negative error code on error.
 *
 * Since: 3.3.0-FIPS140
 -*/
int gnutls_mac_self_test(unsigned flags, gnutls_mac_algorithm_t mac)
{
	int ret;
	const char *_specific_op_name = NULL;

	if (flags & GNUTLS_SELF_TEST_FLAG_ALL)
		mac = GNUTLS_MAC_UNKNOWN;

	_specific_op_name = gnutls_mac_get_name(mac);
#undef _op_name
#define _op_name "mac %s"

	switch (mac) {
	case GNUTLS_MAC_UNKNOWN:
		NON_FIPS_CASE(GNUTLS_MAC_MD5, test_mac, hmac_md5_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_MAC_SHA1, test_mac, hmac_sha1_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_MAC_SHA224, test_mac, hmac_sha224_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_MAC_SHA256, test_mac, hmac_sha256_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_MAC_SHA384, test_mac, hmac_sha384_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_MAC_SHA512, test_mac, hmac_sha512_vectors);
#if ENABLE_GOST
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_MAC_GOSTR_94, test_mac, hmac_gostr_94_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_MAC_STREEBOG_512, test_mac, hmac_streebog_512_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_MAC_STREEBOG_256, test_mac, hmac_streebog_256_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_MAC_GOST28147_TC26Z_IMIT, test_mac, gost28147_tc26z_imit_vectors);
#endif
		FALLTHROUGH;
		CASE(GNUTLS_MAC_AES_CMAC_128, test_mac, aes_cmac_128_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_MAC_AES_CMAC_256, test_mac, aes_cmac_256_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_MAC_AES_GMAC_128, test_mac, aes_gmac_128_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_MAC_AES_GMAC_192, test_mac, aes_gmac_192_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_MAC_AES_GMAC_256, test_mac, aes_gmac_256_vectors);

		break;
	default:
		return gnutls_assert_val(GNUTLS_E_NO_SELF_TEST);
	}

	return 0;
}

/*-
 * gnutls_digest_self_test:
 * @flags: GNUTLS_SELF_TEST_FLAG flags
 * @digest: the digest algorithm to use
 *
 * This function will run self tests on the provided digest.
 *
 * Returns: Zero or a negative error code on error.
 *
 * Since: 3.3.0-FIPS140
 -*/
int gnutls_digest_self_test(unsigned flags, gnutls_digest_algorithm_t digest)
{
	int ret;
	const char *_specific_op_name = NULL;

	if (flags & GNUTLS_SELF_TEST_FLAG_ALL)
		digest = GNUTLS_DIG_UNKNOWN;

	_specific_op_name = gnutls_digest_get_name(digest);
#undef _op_name
#define _op_name "digest %s"

	switch (digest) {
	case GNUTLS_DIG_UNKNOWN:
		NON_FIPS_CASE(GNUTLS_DIG_MD5, test_digest, md5_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_DIG_SHA1, test_digest, sha1_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_DIG_SHA224, test_digest, sha224_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_DIG_SHA256, test_digest, sha256_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_DIG_SHA384, test_digest, sha384_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_DIG_SHA512, test_digest, sha512_vectors);
#ifdef NETTLE_SHA3_FIPS202
		FALLTHROUGH;
		CASE(GNUTLS_DIG_SHA3_224, test_digest, sha3_224_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_DIG_SHA3_256, test_digest, sha3_256_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_DIG_SHA3_384, test_digest, sha3_384_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_DIG_SHA3_512, test_digest, sha3_512_vectors);
#endif
#if ENABLE_GOST
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_DIG_GOSTR_94, test_digest, gostr_94_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_DIG_STREEBOG_512, test_digest, streebog_512_vectors);
		FALLTHROUGH;
		NON_FIPS_CASE(GNUTLS_DIG_STREEBOG_256, test_digest, streebog_256_vectors);
#endif
		break;
	default:
		return gnutls_assert_val(GNUTLS_E_NO_SELF_TEST);
	}

	return 0;
}

struct hkdf_vectors_st {
	const uint8_t *ikm;
	unsigned int ikm_size;
	const uint8_t *salt;
	unsigned int salt_size;
	const uint8_t *prk;
	unsigned int prk_size;
	const uint8_t *info;
	unsigned int info_size;
	const uint8_t *okm;
	unsigned int okm_size;
};

const struct hkdf_vectors_st hkdf_sha256_vectors[] = {
	/* RFC 5869: A.1. Test Case 1: Basic test case with SHA-256 */
	{
		STR(ikm, ikm_size,
		    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
		    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
		STR(salt, salt_size,
		    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"),
		STR(prk, prk_size,
		    "\x07\x77\x09\x36\x2c\x2e\x32\xdf\x0d\xdc\x3f\x0d\xc4\x7b"
		    "\xba\x63\x90\xb6\xc7\x3b\xb5\x0f\x9c\x31\x22\xec\x84\x4a"
		    "\xd7\xc2\xb3\xe5"),
		STR(info, info_size,
		    "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9"),
		STR(okm, okm_size,
		    "\x3c\xb2\x5f\x25\xfa\xac\xd5\x7a\x90\x43\x4f\x64\xd0\x36"
		    "\x2f\x2a\x2d\x2d\x0a\x90\xcf\x1a\x5a\x4c\x5d\xb0\x2d\x56"
		    "\xec\xc4\xc5\xbf\x34\x00\x72\x08\xd5\xb8\x87\x18\x58\x65"),
	},
	/* RFC 5869: A.2. Test Case 2: Test with SHA-256 and longer inputs/outputs */
	{
		STR(ikm, ikm_size,
		    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
		    "\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b"
		    "\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29"
		    "\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
		    "\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45"
		    "\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"),
		STR(salt, salt_size,
		    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d"
		    "\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b"
		    "\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89"
		    "\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97"
		    "\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5"
		    "\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"),
		STR(prk, prk_size,
		    "\x06\xa6\xb8\x8c\x58\x53\x36\x1a\x06\x10\x4c\x9c\xeb\x35"
		    "\xb4\x5c\xef\x76\x00\x14\x90\x46\x71\x01\x4a\x19\x3f\x40"
		    "\xc1\x5f\xc2\x44"),
		STR(info, info_size,
		    "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd"
		    "\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb"
		    "\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9"
		    "\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7"
		    "\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5"
		    "\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"),
		STR(okm, okm_size,
		    "\xb1\x1e\x39\x8d\xc8\x03\x27\xa1\xc8\xe7\xf7\x8c\x59\x6a"
		    "\x49\x34\x4f\x01\x2e\xda\x2d\x4e\xfa\xd8\xa0\x50\xcc\x4c"
		    "\x19\xaf\xa9\x7c\x59\x04\x5a\x99\xca\xc7\x82\x72\x71\xcb"
		    "\x41\xc6\x5e\x59\x0e\x09\xda\x32\x75\x60\x0c\x2f\x09\xb8"
		    "\x36\x77\x93\xa9\xac\xa3\xdb\x71\xcc\x30\xc5\x81\x79\xec"
		    "\x3e\x87\xc1\x4c\x01\xd5\xc1\xf3\x43\x4f\x1d\x87"),
	},
};

static int test_hkdf(gnutls_mac_algorithm_t mac,
		     const struct hkdf_vectors_st *vectors,
		     size_t vectors_size, unsigned flags)
{
	unsigned int i;
	uint8_t fail_tmp[512];

	for (i = 0; i < vectors_size; i++) {
		gnutls_datum_t ikm, prk, salt, info;
		uint8_t output[4096];
		int ret;

		ikm.data = (void *) vectors[i].ikm;
		ikm.size = vectors[i].ikm_size;
		salt.data = (void *) vectors[i].salt;
		salt.size = vectors[i].salt_size;

		if (fips_request_failure(gnutls_mac_get_name(mac), "hkdf-extract")) {
			if (ikm.size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, ikm.data, ikm.size);
			/* Flip a bit in the ikm. */
			fail_tmp[0] ^= 0x1;
			ikm.data = (void *)fail_tmp;
		}

		ret = gnutls_hkdf_extract(mac, &ikm, &salt, output);
		if (ret < 0) {
			_gnutls_debug_log("error extracting HKDF: MAC-%s\n",
					  gnutls_mac_get_name(mac));
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		if (memcmp(output, vectors[i].prk, vectors[i].prk_size) != 0) {
			_gnutls_debug_log
			    ("HKDF extract: MAC-%s test vector failed!\n",
			     gnutls_mac_get_name(mac));

			FIPSLOG_FAILED(gnutls_mac_get_name(mac), "hkdf",
				"HKDF extract - MAC test vector %d", i);

			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		} else {
			FIPSLOG_SUCCESS(gnutls_mac_get_name(mac), "hkdf",
				"HKDF extract - MAC test vector %d", i);
		}

		prk.data = (void *) vectors[i].prk;
		prk.size = vectors[i].prk_size;
		info.data = (void *) vectors[i].info;
		info.size = vectors[i].info_size;

		if (fips_request_failure(gnutls_mac_get_name(mac), "hkdf-expand")) {
			if (prk.size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, prk.data, prk.size);
			/* Flip a bit in the prk. */
			fail_tmp[0] ^= 0x1;
			prk.data = (void *)fail_tmp;
		}

		ret = gnutls_hkdf_expand(mac, &prk, &info,
					 output, vectors[i].okm_size);
		if (ret < 0) {
			_gnutls_debug_log("error extracting HKDF: MAC-%s\n",
					  gnutls_mac_get_name(mac));
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		if (memcmp(output, vectors[i].okm, vectors[i].okm_size) != 0) {
			_gnutls_debug_log
			    ("HKDF expand: MAC-%s test vector failed!\n",
			     gnutls_mac_get_name(mac));

			FIPSLOG_FAILED(gnutls_mac_get_name(mac), "hkdf",
				"HKDF expand - MAC test vector %d", i);

			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		} else {
			FIPSLOG_SUCCESS(gnutls_mac_get_name(mac), "hkdf",
				"HKDF expand - MAC test vector %d", i);
		}
	}

	_gnutls_debug_log
	    ("HKDF: MAC-%s self check succeeded\n",
	     gnutls_mac_get_name(mac));

	return 0;
}

/*-
 * gnutls_hkdf_self_test:
 * @flags: GNUTLS_SELF_TEST_FLAG flags
 * @mac: the message authentication algorithm to use
 *
 * This function will run self tests on HKDF with the provided mac.
 *
 * Returns: Zero or a negative error code on error.
 *
 * Since: 3.3.0-FIPS140
 -*/
int gnutls_hkdf_self_test(unsigned flags, gnutls_mac_algorithm_t mac)
{
	int ret;
	const char *_specific_op_name = NULL;

	if (flags & GNUTLS_SELF_TEST_FLAG_ALL)
		mac = GNUTLS_MAC_UNKNOWN;

	_specific_op_name = gnutls_mac_get_name(mac);
#undef _op_name
#define _op_name "hkdf %s"

	switch (mac) {
	case GNUTLS_MAC_UNKNOWN:
		CASE(GNUTLS_MAC_SHA256, test_hkdf, hkdf_sha256_vectors);

		break;
	default:
		return gnutls_assert_val(GNUTLS_E_NO_SELF_TEST);
	}

	return 0;
}

struct pbkdf2_vectors_st {
	const uint8_t *key;
	size_t key_size;
	const uint8_t *salt;
	size_t salt_size;
	unsigned iter_count;
	const uint8_t *output;
	size_t output_size;
};

const struct pbkdf2_vectors_st pbkdf2_sha256_vectors[] = {
	/* RFC 7914: 11. Test Vectors for PBKDF2 with HMAC-SHA-256 */
	{
		STR(key, key_size, "passwd"),
		STR(salt, salt_size, "salt"),
		.iter_count = 1,
		STR(output, output_size,
		    "\x55\xac\x04\x6e\x56\xe3\x08\x9f\xec\x16\x91\xc2\x25\x44"
		    "\xb6\x05\xf9\x41\x85\x21\x6d\xde\x04\x65\xe6\x8b\x9d\x57"
		    "\xc2\x0d\xac\xbc\x49\xca\x9c\xcc\xf1\x79\xb6\x45\x99\x16"
		    "\x64\xb3\x9d\x77\xef\x31\x7c\x71\xb8\x45\xb1\xe3\x0b\xd5"
		    "\x09\x11\x20\x41\xd3\xa1\x97\x83"),
	},
	/* RFC 7914: 11. Test Vectors for PBKDF2 with HMAC-SHA-256 */
	{
		STR(key, key_size, "Password"),
		STR(salt, salt_size, "NaCl"),
		.iter_count = 80000,
		STR(output, output_size,
		    "\x4d\xdc\xd8\xf6\x0b\x98\xbe\x21\x83\x0c\xee\x5e\xf2\x27"
		    "\x01\xf9\x64\x1a\x44\x18\xd0\x4c\x04\x14\xae\xff\x08\x87"
		    "\x6b\x34\xab\x56\xa1\xd4\x25\xa1\x22\x58\x33\x54\x9a\xdb"
		    "\x84\x1b\x51\xc9\xb3\x17\x6a\x27\x2b\xde\xbb\xa1\xd0\x78"
		    "\x47\x8f\x62\xb3\x97\xf3\x3c\x8d"),
	},
	/* Test vector extracted from:
	 * https://dev.gnupg.org/source/libgcrypt/browse/master/cipher/kdf.c */
	{
		STR(key, key_size, "passwordPASSWORDpassword"),
		STR(salt, salt_size, "saltSALTsaltSALTsaltSALTsaltSALTsalt"),
		.iter_count = 4096,
		STR(output, output_size,
		    "\x34\x8c\x89\xdb\xcb\xd3\x2b\x2f\x32\xd8\x14\xb8\x11\x6e"
		    "\x84\xcf\x2b\x17\x34\x7e\xbc\x18\x00\x18\x1c\x4e\x2a\x1f"
		    "\xb8\xdd\x53\xe1\xc6\x35\x51\x8c\x7d\xac\x47\xe9"),
	},
};

static int test_pbkdf2(gnutls_mac_algorithm_t mac,
		       const struct pbkdf2_vectors_st *vectors,
		       size_t vectors_size, unsigned flags)
{
	unsigned int i;
	uint8_t fail_tmp[512];

	for (i = 0; i < vectors_size; i++) {
		gnutls_datum_t key, salt;
		uint8_t output[4096];
		int ret;

		key.data = (void *) vectors[i].key;
		key.size = vectors[i].key_size;
		salt.data = (void *) vectors[i].salt;
		salt.size = vectors[i].salt_size;

		if (fips_request_failure(gnutls_mac_get_name(mac), "pbkdf2")) {
			if (salt.size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, salt.data, salt.size);
			/* Flip a bit in the salt. */
			fail_tmp[0] ^= 0x1;
			salt.data = (void *)fail_tmp;
		}

		ret = gnutls_pbkdf2(mac, &key, &salt, vectors[i].iter_count,
				    output, vectors[i].output_size);
		if (ret < 0) {
			_gnutls_debug_log("error calculating PBKDF2: MAC-%s\n",
					  gnutls_mac_get_name(mac));
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		if (memcmp(output, vectors[i].output, vectors[i].output_size) != 0) {
			_gnutls_debug_log
			    ("PBKDF2: MAC-%s test vector failed!\n",
			     gnutls_mac_get_name(mac));

			FIPSLOG_FAILED(gnutls_mac_get_name(mac), "pbkdf2",
				"PBKDF2 - MAC test vector %d", i);

			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		} else {
			FIPSLOG_SUCCESS(gnutls_mac_get_name(mac), "pbkdf2",
				"PBKDF2 - MAC test vector %d", i);
		}
	}

	_gnutls_debug_log
	    ("PBKDF2: MAC-%s self check succeeded\n",
	     gnutls_mac_get_name(mac));

	return 0;
}

/*-
 * gnutls_pbkdf2_self_test:
 * @flags: GNUTLS_SELF_TEST_FLAG flags
 * @mac: the message authentication algorithm to use
 *
 * This function will run self tests on PBKDF2 with the provided mac.
 *
 * Returns: Zero or a negative error code on error.
 *
 * Since: 3.3.0-FIPS140
 -*/
int gnutls_pbkdf2_self_test(unsigned flags, gnutls_mac_algorithm_t mac)
{
	int ret;
	const char *_specific_op_name = NULL;

	if (flags & GNUTLS_SELF_TEST_FLAG_ALL)
		mac = GNUTLS_MAC_UNKNOWN;

	_specific_op_name = gnutls_mac_get_name(mac);
#undef _op_name
#define _op_name "pbkdf2 %s"

	switch (mac) {
	case GNUTLS_MAC_UNKNOWN:
		CASE(GNUTLS_MAC_SHA256, test_pbkdf2, pbkdf2_sha256_vectors);

		break;
	default:
		return gnutls_assert_val(GNUTLS_E_NO_SELF_TEST);
	}

	return 0;
}

struct tlsprf_vectors_st {
	const uint8_t *key;
	size_t key_size;
	const uint8_t *label;
	size_t label_size;
	const uint8_t *seed;
	size_t seed_size;
	const uint8_t *output;
	size_t output_size;
};

const struct tlsprf_vectors_st tls10prf_vectors[] = {
	/* tests/tls10-prf.c: test1 */
	{
		STR(key, key_size,
		    "\x26\x3b\xdb\xbb\x6f\x6d\x4c\x66\x4e\x05\x8d\x0a\xa9\xd3"
		    "\x21\xbe"),
		STR(label, label_size,
		    "test label"),
		STR(seed, seed_size,
		    "\xb9\x20\x57\x3b\x19\x96\x01\x02\x4f\x04\xd6\xdc\x61\x96"
		    "\x6e\x65"),
		STR(output, output_size,
		    "\x66\x17\x99\x37\x65\xfa\x6c\xa7\x03\xd1\x9e\xc7\x0d\xd5"
		    "\xdd\x16\x0f\xfc\xc0\x77\x25\xfa\xfb\x71\x4a\x9f\x81\x5a"
		    "\x2a\x30\xbf\xb7\xe3\xbb\xfb\x7e\xee\x57\x4b\x3b\x61\x3e"
		    "\xb7\xfe\x80\xee\xc9\x69\x1d\x8c\x1b\x0e\x2d\x9b\x3c\x8b"
		    "\x4b\x02\xb6\xb6\xd6\xdb\x88\xe2\x09\x46\x23\xef\x62\x40"
		    "\x60\x7e\xda\x7a\xbe\x3c\x84\x6e\x82\xa3"),
	},
};

const struct tlsprf_vectors_st tls12prf_sha256_vectors[] = {
	/* tests/tls12-prf.c: sha256_test1 */
	{
		STR(key, key_size,
		    "\x04\x50\xb0\xea\x9e\xcd\x36\x02\xee\x0d\x76\xc5\xc3\xc8"
		    "\x6f\x4a"),
		STR(label, label_size,
		    "test label"),
		STR(seed, seed_size,
		    "\x20\x7a\xcc\x02\x54\xb8\x67\xf5\xb9\x25\xb4\x5a\x33\x60"
		    "\x1d\x8b"),
		STR(output, output_size,
		    "\xae\x67\x9e\x0e\x71\x4f\x59\x75\x76\x37\x68\xb1\x66\x97"
		    "\x9e\x1d"),
	},
	/* tests/tls12-prf.c: sha256_test2 */
	{
		STR(key, key_size,
		    "\x34\x20\x4a\x9d\xf0\xbe\x6e\xb4\xe9\x25\xa8\x02\x7c\xf6"
		    "\xc6\x02"),
		STR(label, label_size,
		    "test label"),
		STR(seed, seed_size,
		    "\x98\xb2\xc4\x0b\xcd\x66\x4c\x83\xbb\x92\x0c\x18\x20\x1a"
		    "\x63\x95"),
		STR(output, output_size,
		    "\xaf\xa9\x31\x24\x53\xc2\x2f\xa8\x3d\x2b\x51\x1b\x37\x2d"
		    "\x73\xa4\x02\xa2\xa6\x28\x73\x23\x9a\x51\xfa\xde\x45\x08"
		    "\x2f\xaf\x3f\xd2\xbb\x7f\xfb\x3e\x9b\xf3\x6e\x28\xb3\x14"
		    "\x1a\xab\xa4\x84\x00\x53\x32\xa9\xf9\xe3\x88\xa4\xd3\x29"
		    "\xf1\x58\x7a\x4b\x31\x7d\xa0\x77\x08\xea\x1b\xa9\x5a\x53"
		    "\xf8\x78\x67\x24\xbd\x83\xce\x4b\x03\xaf"),
	},
	/* tests/tls12-prf.c: sha256_test3 */
	{
		STR(key, key_size,
		    "\xa3\x69\x1a\xa1\xf6\x81\x4b\x80\x59\x2b\xf1\xcf\x2a\xcf"
		    "\x16\x97"),
		STR(label, label_size,
		    "test label"),
		STR(seed, seed_size,
		    "\x55\x23\xd4\x1e\x32\x0e\x69\x4d\x0c\x1f\xf5\x73\x4d\x83"
		    "\x0b\x93\x3e\x46\x92\x70\x71\xc9\x26\x21"),
		STR(output, output_size,
		    "\x6a\xd0\x98\x4f\xa0\x6f\x78\xfe\x16\x1b\xd4\x6d\x7c\x26"
		    "\x1d\xe4\x33\x40\xd7\x28\xdd\xdc\x3d\x0f\xf0\xdd\x7e\x0d"),
	},
	/* tests/tls12-prf.c: sha256_test4 */
	{
		STR(key, key_size,
		    "\x21\x0e\xc9\x37\x06\x97\x07\xe5\x46\x5b\xc4\x6b\xf7\x79"
		    "\xe1\x04\x10\x8b\x18\xfd\xb7\x93\xbe\x7b\x21\x8d\xbf\x14"
		    "\x5c\x86\x41\xf3"),
		STR(label, label_size,
		    "test label"),
		STR(seed, seed_size,
		    "\x1e\x35\x1a\x0b\xaf\x35\xc7\x99\x45\x92\x43\x94\xb8\x81"
		    "\xcf\xe3\x1d\xae\x8f\x1c\x1e\xd5\x4d\x3b"),
		STR(output, output_size,
		    "\x76\x53\xfa\x80\x9c\xde\x3b\x55\x3c\x4a\x17\xe2\xcd\xbc"
		    "\xc9\x18\xf3\x65\x27\xf2\x22\x19\xa7\xd7\xf9\x5d\x97\x24"
		    "\x3f\xf2\xd5\xde\xe8\x26\x5e\xf0\xaf\x03"),
	},
};

const struct tlsprf_vectors_st tls12prf_sha384_vectors[] = {
	/* tests/tls12-prf.c: sha384_test1
	 * https://www.ietf.org/mail-archive/web/tls/current/msg03416.html
	 */
	{
		STR(key, key_size,
		    "\xb8\x0b\x73\x3d\x6c\xee\xfc\xdc\x71\x56\x6e\xa4\x8e\x55"
		    "\x67\xdf"),
		STR(label, label_size,
		    "test label"),
		STR(seed, seed_size,
		    "\xcd\x66\x5c\xf6\xa8\x44\x7d\xd6\xff\x8b\x27\x55\x5e\xdb"
		    "\x74\x65"),
		STR(output, output_size,
		    "\x7b\x0c\x18\xe9\xce\xd4\x10\xed\x18\x04\xf2\xcf\xa3\x4a"
		    "\x33\x6a\x1c\x14\xdf\xfb\x49\x00\xbb\x5f\xd7\x94\x21\x07"
		    "\xe8\x1c\x83\xcd\xe9\xca\x0f\xaa\x60\xbe\x9f\xe3\x4f\x82"
		    "\xb1\x23\x3c\x91\x46\xa0\xe5\x34\xcb\x40\x0f\xed\x27\x00"
		    "\x88\x4f\x9d\xc2\x36\xf8\x0e\xdd\x8b\xfa\x96\x11\x44\xc9"
		    "\xe8\xd7\x92\xec\xa7\x22\xa7\xb3\x2f\xc3\xd4\x16\xd4\x73"
		    "\xeb\xc2\xc5\xfd\x4a\xbf\xda\xd0\x5d\x91\x84\x25\x9b\x5b"
		    "\xf8\xcd\x4d\x90\xfa\x0d\x31\xe2\xde\xc4\x79\xe4\xf1\xa2"
		    "\x60\x66\xf2\xee\xa9\xa6\x92\x36\xa3\xe5\x26\x55\xc9\xe9"
		    "\xae\xe6\x91\xc8\xf3\xa2\x68\x54\x30\x8d\x5e\xaa\x3b\xe8"
		    "\x5e\x09\x90\x70\x3d\x73\xe5\x6f"),
	},
};

static int test_tlsprf(gnutls_mac_algorithm_t mac,
		       const struct tlsprf_vectors_st *vectors,
		       size_t vectors_size, unsigned flags)
{
	unsigned int i;
	uint8_t fail_tmp[512];

	for (i = 0; i < vectors_size; i++) {
		char output[4096];
		int ret;

		if (fips_request_failure("TLS1_2", "TLS1_2-PRF")) {
			if (vectors[i].seed_size > sizeof(fail_tmp)) {
				return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
			}
			memcpy(fail_tmp, vectors[i].seed, vectors[i].seed_size);
			/* Flip a bit in the seed. */
			fail_tmp[0] ^= 0x1;
			ret = _gnutls_prf_raw(mac,
				      vectors[i].key_size, vectors[i].key,
				      vectors[i].label_size, (const char *)vectors[i].label,
				      vectors[i].seed_size, fail_tmp,
				      vectors[i].output_size, output);
		} else {
			ret = _gnutls_prf_raw(mac,
				      vectors[i].key_size, vectors[i].key,
				      vectors[i].label_size, (const char *)vectors[i].label,
				      vectors[i].seed_size, vectors[i].seed,
				      vectors[i].output_size, output);
		}
		if (ret < 0) {
			_gnutls_debug_log("error calculating TLS-PRF: MAC-%s\n",
					  gnutls_mac_get_name(mac));
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		if (memcmp(output, vectors[i].output, vectors[i].output_size) != 0) {
			_gnutls_debug_log
			    ("TLS1_2-PRF: MAC-%s test vector failed!\n",
			     gnutls_mac_get_name(mac));

			FIPSLOG_FAILED("TLS1_2", "TLS1_2-PRF",
				"MAC %s test vector %d",
				gnutls_mac_get_name(mac), i);

			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		} else {
			FIPSLOG_SUCCESS("TLS1_2", "TLS1_2-PRF",
				"MAC %s test vector %d",
				gnutls_mac_get_name(mac), i);
		}
	}

	_gnutls_debug_log
	    ("TLS-PRF: MAC-%s self check succeeded\n",
	     gnutls_mac_get_name(mac));

	return 0;
}

/*
 * Rewritten from FIPS_selftest_tls13() in OpenSSL.
 */

int gnutls_tlsprf13_self_test(void)
{
	int ret;
	uint8_t hmac[SHA256_DIGEST_SIZE];
	uint8_t tls13_kdf_psk[] = {
		0xF8, 0xAF, 0x6A, 0xEA, 0x2D, 0x39, 0x7B, 0xAF,
		0x29, 0x48, 0xA2, 0x5B, 0x28, 0x34, 0x20, 0x06,
		0x92, 0xCF, 0xF1, 0x7E, 0xEE, 0x91, 0x65, 0xE4,
		0xE2, 0x7B, 0xAB, 0xEE, 0x9E, 0xDE, 0xFD, 0x05
	};
	const uint8_t tls13_kdf_early_secret[] = {
		0x15, 0x3B, 0x63, 0x94, 0xA9, 0xC0, 0x3C, 0xF3,
		0xF5, 0xAC, 0xCC, 0x6E, 0x45, 0x5A, 0x76, 0x93,
		0x28, 0x11, 0x38, 0xA1, 0xBC, 0xFA, 0x38, 0x03,
		0xC2, 0x67, 0x35, 0xDD, 0x11, 0x94, 0xD2, 0x16
	};

	FIPSLOG_SUCCESS("TLS1_3", "POST", "%s", "TLS1_3-PRF test started");

	if (fips_request_failure("TLS1_3", "TLS1_3-PRF")) {
		/* Flip a bit in the data. */
		tls13_kdf_psk[0] ^= 0x1;
	}

	ret = gnutls_hmac_fast(GNUTLS_MAC_SHA256,
				"",		/* key */
				0,		/* keylen */
				tls13_kdf_psk,	/* data to hash */
				sizeof(tls13_kdf_psk),/* length of data to hash */
				hmac);		/* output */
	if (ret < 0) {
		return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
	}

	if (memcmp(hmac, tls13_kdf_early_secret, sizeof(hmac)) != 0) {
		_gnutls_debug_log
		    ("TLS1_3-PRF: MAC-%s test vector failed!\n",
		     gnutls_mac_get_name(GNUTLS_MAC_SHA256));

		FIPSLOG_FAILED("TLS1_3", "TLS1_3-PRF",
			"MAC %s test vector",
			gnutls_mac_get_name(GNUTLS_MAC_SHA256));

		FIPSLOG_FAILED("TLS1_3", "POST", "%s", "TLS1_3-PRF test ended");
		return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
	} else {
		FIPSLOG_SUCCESS("TLS1_3", "TLS1_3-PRF",
				"MAC %s test vector",
				gnutls_mac_get_name(GNUTLS_MAC_SHA256));
	}
	FIPSLOG_SUCCESS("TLS1_3", "POST", "%s", "TLS1_3-PRF test ended");
	return 0;
}

/*-
 * gnutls_tlsprf_self_test:
 * @flags: GNUTLS_SELF_TEST_FLAG flags
 * @mac: the message authentication algorithm to use
 *
 * This function will run self tests on TLS-PRF with the provided mac.
 *
 * Returns: Zero or a negative error code on error.
 *
 * Since: 3.3.0-FIPS140
 -*/
int gnutls_tlsprf_self_test(unsigned flags, gnutls_mac_algorithm_t mac)
{
	int ret;
	const char *_specific_op_name = "TLS1_2";

	if (flags & GNUTLS_SELF_TEST_FLAG_ALL)
		mac = GNUTLS_MAC_UNKNOWN;

#undef _op_name
#define _op_name "TLS1_2-PRF %s"

	switch (mac) {
	case GNUTLS_MAC_UNKNOWN:
		NON_FIPS_CASE(GNUTLS_MAC_MD5_SHA1, test_tlsprf, tls10prf_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_MAC_SHA256, test_tlsprf, tls12prf_sha256_vectors);
		FALLTHROUGH;
		CASE(GNUTLS_MAC_SHA384, test_tlsprf, tls12prf_sha384_vectors);

		break;
	default:
		return gnutls_assert_val(GNUTLS_E_NO_SELF_TEST);
	}

	return 0;
}
