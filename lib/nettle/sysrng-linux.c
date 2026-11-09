/*
 * Copyright (C) 2010-2016 Free Software Foundation, Inc.
 * Copyright (C) 2015-2016 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
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

/* The Linux style system random generator: That is,
 * getrandom() -> /dev/urandom, where "->" indicates fallback.
 */

#ifndef RND_NO_INCLUDES
#include "gnutls_int.h"
#include "errors.h"
#include "num.h"
#include <errno.h>
#include "rnd-common.h"
#include "fips.h"
#include "glthread/tls.h"
#include "locks.h"
#include "gl_linkedhash_list.h"
#include "gl_list.h"
#else
#define _gnutls_fips_mode_enabled() 0
#define _gnutls_switch_fips_state(x) do {} while (0)
#define _gnutls_switch_lib_state(x) do {} while (0)
#define LIB_STATE_ERROR 0
#define GNUTLS_FIPS140_OP_ERROR 0
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

/* gnulib wants to claim strerror even if it cannot provide it. WTF */
#undef strerror

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>

get_entropy_func _rnd_get_system_entropy = NULL;


# if defined(ENABLE_FIPS140)
#  define HAVE_JENT
#  include <jitterentropy.h>
/*
 * The jitterentropy collector is thread-local and lazily allocated per thread.
 * It is held indirectly, through a per-thread "slot", so that the collector
 * can be freed both when a thread exits and when the library is deinitialized:
 *
 *   - Each thread's slot is registered in a process-wide list (jent_slot_list)
 *     and referenced by a TLS key (jent_slot_key) whose destructor runs on
 *     thread exit.  On thread exit the slot is removed from the list, which
 *     disposes (frees) it; at library deinit the list is freed, disposing any
 *     slots whose threads are still alive.  This mirrors the per-thread DRBG
 *     context cleanup done for ctx_key/list in lib/random.c, and prevents the
 *     collector -- and the mlock()ed memory it holds -- from leaking.
 *
 *   - The list stores the (stable) slot pointer, not the collector pointer, so
 *     that jent_read_entropy_safe() re-allocating the collector only rewrites
 *     slot->ec and never has to mutate the shared list on the hot read path.
 */
struct jent_slot {
	struct rand_data *ec;
};

static _Thread_local struct jent_slot *jent_slot = NULL;
static _Thread_local int jent_initialized = 0;

/* Free the collector a slot holds, then the slot itself.  Used as the list's
 * dispose callback and, in the RND_NO_INCLUDES build, directly.  Uses only
 * libc + jitterentropy, so it is available in both build configurations. */
static void jent_slot_dispose(const void *elt)
{
	struct jent_slot *s = (struct jent_slot *)elt;

	if (s == NULL)
		return;
	if (s->ec != NULL)
		jent_entropy_collector_free(s->ec);
	free(s);
}

#ifndef RND_NO_INCLUDES
GNUTLS_STATIC_MUTEX(jent_slot_mutex);
/* All live slots, so every thread's collector can be freed at library deinit.
 * NULL exactly when the registry is not initialized; used (under the mutex) as
 * the liveness flag guarding access to the list and the TLS key. */
static gl_list_t jent_slot_list = NULL;
static gl_tls_key_t jent_slot_key;

/* Thread-exit destructor: drop this thread's slot from the list (which
 * disposes it).  Guarded against a registry that has already been torn down. */
static void jent_slot_tls_destructor(void *ptr)
{
	struct jent_slot *s = ptr;

	if (s == NULL)
		return;
	(void)gnutls_static_mutex_lock(&jent_slot_mutex);
	if (jent_slot_list != NULL)
		gl_list_remove(jent_slot_list, s);
	gnutls_static_mutex_unlock(&jent_slot_mutex);
	jent_slot = NULL;
	jent_initialized = 0;
}

/* Create the process-wide registry.  Called once from the single-threaded
 * initialization path, before any slot is allocated. */
static int jent_registry_init(void)
{
	int ret;

	ret = gnutls_static_mutex_lock(&jent_slot_mutex);
	if (ret < 0)
		return gnutls_assert_val(ret);
	if (jent_slot_list == NULL) {
		if (glthread_tls_key_init(&jent_slot_key,
					  jent_slot_tls_destructor)) {
			ret = gnutls_assert_val(GNUTLS_E_RANDOM_DEVICE_ERROR);
		} else {
			jent_slot_list = gl_list_nx_create_empty(
				GL_LINKEDHASH_LIST, NULL, NULL,
				jent_slot_dispose, false);
			if (jent_slot_list == NULL) {
				glthread_tls_key_destroy(&jent_slot_key);
				ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
			}
		}
	}
	gnutls_static_mutex_unlock(&jent_slot_mutex);
	return ret;
}

/* Register a freshly-allocated slot for this thread: publish it through the
 * TLS key and append it to the list (last, so the caller can still free it
 * directly on failure).  Fails if the registry is gone, so a collector is
 * never created that nothing will ever free. */
static int jent_slot_register(struct jent_slot *s)
{
	int ret;

	ret = gnutls_static_mutex_lock(&jent_slot_mutex);
	if (ret < 0)
		return gnutls_assert_val(ret);
	ret = GNUTLS_E_RANDOM_DEVICE_ERROR;
	if (jent_slot_list != NULL &&
	    glthread_tls_set(&jent_slot_key, s) == 0) {
		if (gl_list_nx_add_last(jent_slot_list, s) != NULL)
			ret = 0;
		else
			(void)glthread_tls_set(&jent_slot_key, NULL);
	}
	gnutls_static_mutex_unlock(&jent_slot_mutex);
	return ret;
}

/* Release this thread's slot (remove from the list, which disposes it).  If
 * the registry is already gone the slot was freed by jent_registry_deinit()'s
 * gl_list_free(), so only the thread-locals are cleared. */
static void jent_release_current(void)
{
	struct jent_slot *s = jent_slot;

	jent_slot = NULL;
	jent_initialized = 0;
	if (s == NULL)
		return;
	(void)gnutls_static_mutex_lock(&jent_slot_mutex);
	if (jent_slot_list != NULL) {
		(void)glthread_tls_set(&jent_slot_key, NULL);
		gl_list_remove(jent_slot_list, s);
	}
	gnutls_static_mutex_unlock(&jent_slot_mutex);
}

/* Tear down the whole registry at library deinit: destroy the key first (so no
 * thread-exit destructor can race the list free), then free the list, which
 * disposes every remaining slot -- including those of threads still alive. */
static void jent_registry_deinit(void)
{
	(void)gnutls_static_mutex_lock(&jent_slot_mutex);
	if (jent_slot_list != NULL) {
		glthread_tls_key_destroy(&jent_slot_key);
		gl_list_free(jent_slot_list);
		jent_slot_list = NULL;
	}
	gnutls_static_mutex_unlock(&jent_slot_mutex);
	jent_slot = NULL;
	jent_initialized = 0;
}
#else /* RND_NO_INCLUDES: no gnulib list/lock/TLS primitives available */
#define jent_registry_init() (0)
#define jent_slot_register(s) (0)
static void jent_release_current(void)
{
	if (jent_slot != NULL) {
		jent_slot_dispose(jent_slot);
		jent_slot = NULL;
		jent_initialized = 0;
	}
}
static void jent_registry_deinit(void)
{
	jent_release_current();
}
#endif /* !RND_NO_INCLUDES */

/* Declare function to fix a missing-prototypes compilation warning */
void gnutls_jent_entropy_deinit(void);
# endif

#if defined(__linux__)
#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#else
#include <sys/syscall.h>
#undef getrandom
#if defined(SYS_getrandom)
#define getrandom(dst, s, flags) \
	syscall(SYS_getrandom, (void *)dst, (size_t)s, (unsigned int)flags)
#else
static ssize_t _getrandom0(void *buf, size_t buflen, unsigned int flags)
{
	errno = ENOSYS;
	return -1;
}

#define getrandom(dst, s, flags) _getrandom0(dst, s, flags)
#endif
#endif

# if defined(ENABLE_FIPS140)
#  if defined(HAVE_JENT)
/* check whether the CPU Jitter entropy collector is available. */
/* osr: Oversampling rate */
/* flags:
 * JENT_FORCE_FIPS
 * JENT_DISABLE_MEMORY_ACCESS
 * JENT_DISABLE_INTERNAL_TIMER
 * JENT_FORCE_INTERNAL_TIMER
 * JENT_MAX_MEMSIZE_{32,64,128,256,512}kB
 * JENT_MAX_MEMSIZE_{1,2,4,8,16,32,64,128,256,512}MB
 */
static unsigned gnutls_jent_entropy_init(void)
{
	unsigned int rv = 1;
	unsigned int osr = 0;
	unsigned int flags = 0;

	if (_gnutls_fips_mode_enabled()) {
		/* Set the FIPS flag. */
		flags |= JENT_FORCE_FIPS;
		/* Oversampling of 3 is required for FIPS mode. */
		osr = 3;
	}

	/* Do not re-initialize jent. */
	if (jent_initialized == 0) {
		if (jent_entropy_init_ex(osr, flags))
			return 0;
		jent_initialized = 1;
	}

	/* Allocate this thread's slot and its entropy collector.  The slot is
	 * added to the registry last, so any earlier failure frees what it
	 * allocated directly; once registered, the slot is owned by the list
	 * and freed only by its dispose callback. */
	if (jent_slot == NULL) {
		struct jent_slot *s = calloc(1, sizeof(*s));

		if (s == NULL) {
			rv = 0;
		} else {
			s->ec = jent_entropy_collector_alloc(osr, flags);
			if (s->ec == NULL) {
				free(s);
				rv = 0;
			} else if (jent_slot_register(s) != 0) {
				jent_entropy_collector_free(s->ec);
				free(s);
				rv = 0;
			} else {
				jent_slot = s;
			}
		}
	}

	return rv;
}

void gnutls_jent_entropy_deinit(void)
{
	/* Release this thread's collector (and slot). */
	jent_release_current();

	return;
}

/* returns exactly the amount of bytes requested */
static int force_jent(void *buf, size_t buflen)
{
	int jent_bytes = -1;

	if (buf == NULL || buflen == 0) {
		return -1;
	}

	/* Ensure the entropy source has been fully initiated. */
	if (jent_initialized == 0 || jent_slot == NULL ||
	    jent_slot->ec == NULL) {
		if (!gnutls_jent_entropy_init()) {
			return -1;
		}
	}

	/* Get entropy bytes.  jent_read_entropy_safe() may re-allocate the
	 * collector in place (updating slot->ec); because the registry tracks
	 * the stable slot pointer, no list update is needed here. */
	jent_bytes = jent_read_entropy_safe(&jent_slot->ec, (char *)buf,
					    buflen);

	return jent_bytes;
}

static int _rnd_get_system_entropy_jent(void* _rnd, size_t size)
{
	int ret;

	ret = force_jent(_rnd, size);
	if (ret < 0) {
		int e = errno;
		gnutls_assert();
		_gnutls_debug_log("Failed to use jent: %s\n", strerror(e));
		gnutls_jent_entropy_deinit();
		if (_gnutls_fips_mode_enabled()) {
			_gnutls_switch_fips_state(GNUTLS_FIPS140_OP_ERROR);
			_gnutls_switch_lib_state(LIB_STATE_ERROR);
		}
		return GNUTLS_E_RANDOM_DEVICE_ERROR;
	}

	return 0;
}
#  endif
# endif

static unsigned have_getrandom(void)
{
	char c;
	int ret;
	ret = getrandom(&c, 1, 1 /*GRND_NONBLOCK */);
	if (ret == 1 || (ret == -1 && errno == EAGAIN))
		return 1;
	return 0;
}

/* returns exactly the amount of bytes requested */
static int force_getrandom(void *buf, size_t buflen, unsigned int flags)
{
	int left = buflen;
	int ret;
	uint8_t *p = buf;

	while (left > 0) {
		ret = getrandom(p, left, flags);
		if (ret == -1) {
			if (errno != EINTR)
				return ret;
		}

		if (ret > 0) {
			left -= ret;
			p += ret;
		}
	}

	return buflen;
}

static int _rnd_get_system_entropy_getrandom(void *_rnd, size_t size)
{
	int ret;
	unsigned int flags = 0;

	if (_gnutls_fips_mode_enabled()) {
		flags |= 2/*GRND_RANDOM*/;
	}
	ret = force_getrandom(_rnd, size, flags);
	if (ret == -1) {
		int e = errno;
		gnutls_assert();
		_gnutls_debug_log("Failed to use getrandom: %s\n", strerror(e));
		return GNUTLS_E_RANDOM_DEVICE_ERROR;
	}

	return 0;
}
#else /* not linux */
#define have_getrandom() 0
#endif

static int _rnd_get_system_entropy_urandom(void *_rnd, size_t size)
{
	uint8_t *rnd = _rnd;
	uint32_t done;
	int urandom_fd;

	urandom_fd = open("/dev/urandom", O_RDONLY);
	if (urandom_fd < 0) {
		_gnutls_debug_log("Cannot open /dev/urandom!\n");
		return GNUTLS_E_RANDOM_DEVICE_ERROR;
	}

	for (done = 0; done < size;) {
		int res;
		do {
			res = read(urandom_fd, rnd + done, size - done);
		} while (res < 0 && errno == EINTR);

		if (res <= 0) {
			int e = errno;
			if (res < 0) {
				_gnutls_debug_log(
					"Failed to read /dev/urandom: %s\n",
					strerror(e));
			} else {
				_gnutls_debug_log(
					"Failed to read /dev/urandom: end of file\n");
			}

			close(urandom_fd);
			return GNUTLS_E_RANDOM_DEVICE_ERROR;
		}

		done += res;
	}

	close(urandom_fd);
	return 0;
}

int _rnd_system_entropy_init(void)
{
	int urandom_fd;

#if defined(__linux__)

# if defined(ENABLE_FIPS140)
#  if defined(HAVE_JENT)
	/* Enable jitterentropy usage only in FIPS mode */
	if (_gnutls_fips_mode_enabled()) {
		int ret;

		/* Create the registry used to free each thread's jitterentropy
		 * collector (on thread exit, and at library deinit).  This must
		 * happen before any collector is allocated, including the one
		 * allocated by the gnutls_jent_entropy_init() call just below. */
		ret = jent_registry_init();
		if (ret < 0) {
			_gnutls_debug_log(
				"could not initialize jitterentropy registry\n");
			_gnutls_switch_fips_state(GNUTLS_FIPS140_OP_ERROR);
			_gnutls_switch_lib_state(LIB_STATE_ERROR);
			return gnutls_assert_val(ret);
		}
		if (gnutls_jent_entropy_init()) {
			_rnd_get_system_entropy = _rnd_get_system_entropy_jent;
			_gnutls_debug_log("jitterentropy random generator was selected\n");
			return 0;
		} else {
			_gnutls_debug_log("jitterentropy is not available\n");
			jent_registry_deinit();
			_gnutls_switch_fips_state(GNUTLS_FIPS140_OP_ERROR);
			_gnutls_switch_lib_state(LIB_STATE_ERROR);
			return gnutls_assert_val(GNUTLS_E_RANDOM_DEVICE_ERROR);
		}
	}
#  endif
# endif

	/* Enable getrandom() usage if available */
	if (have_getrandom()) {
		_rnd_get_system_entropy = _rnd_get_system_entropy_getrandom;
		_gnutls_debug_log("getrandom random generator was selected\n");
		return 0;
	} else {
		_gnutls_debug_log("getrandom is not available\n");
	}
#endif

	/* Fallback: /dev/urandom */

	/* Check that we can open it */
	urandom_fd = open("/dev/urandom", O_RDONLY);
	if (urandom_fd < 0) {
		_gnutls_debug_log(
			"Cannot open /dev/urandom during initialization!\n");
		return gnutls_assert_val(GNUTLS_E_RANDOM_DEVICE_ERROR);
	}
	close(urandom_fd);

	_rnd_get_system_entropy = _rnd_get_system_entropy_urandom;
	_gnutls_debug_log("/dev/urandom random generator was selected\n");

	return 0;
}

void _rnd_system_entropy_deinit(void)
{
#if defined(__linux__)
# if defined(ENABLE_FIPS140)
#  if defined(HAVE_JENT)
	/* Tear down the jitterentropy registry, freeing every thread's
	 * collector -- including collectors held by threads that are still
	 * alive (their thread-local slot pointer is left dangling, so callers
	 * must not draw entropy concurrently with, or after, deinitialization;
	 * the per-thread DRBG context in lib/random.c has the same contract).
	 * Done regardless of the current FIPS mode flag, which could in
	 * principle differ from the value seen at initialization time. */
	jent_registry_deinit();
#  endif
# endif
#endif
	/* A no-op now when we open and close /dev/urandom every time */
	return;
}
