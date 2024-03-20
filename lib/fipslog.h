/*
 * Copyright (C) 2023 CIQ Inc.
 *
 * Author: Jeremy Allison.
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

#ifndef GNUTLS_LIB_FIPSLOG_H
#define GNUTLS_LIB_FIPSLOG_H

enum fips_logging_type {
	FIPS_NO_LOGGING = 0,
	FIPS_LOG_SYSLOG = 1,
	FIPS_LOG_STDERR = 2
};

#define GNUTLS_SUCCESS_AUDIT_WITH_SYSLOG 1
#if defined(GNUTLS_SUCCESS_AUDIT_WITH_SYSLOG)
#include <syslog.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>

enum fips_logging_type fips_logging_enabled(const char *name, const char *subname);

#define GNUTLS_FAILURE_PROBES 1
#if defined(GNUTLS_FAILURE_PROBES)
bool fips_request_failure(const char *name, const char *subname);
#endif /* GNUTLS_FAILURE_PROBES */

#define FIPSLOG_SUCCESS(name, subname, fmt, ...) \
	do { \
		enum fips_logging_type flt = fips_logging_enabled((name), (subname)); \
		if (flt != FIPS_NO_LOGGING) { \
			if ((subname) != NULL) { \
				if (flt == FIPS_LOG_SYSLOG) { \
					syslog(LOG_INFO, "GNUTLS: %s:%s:%d:%s.%s:" fmt ":SUCCESS", \
					__FILE__, __func__, __LINE__, (name), ((subname) != NULL) ? (const char *)(subname) : "", __VA_ARGS__); \
				} else { \
					fprintf(stderr, "GNUTLS: %s:%s:%d:%s.%s:" fmt ":SUCCESS\n", \
					__FILE__, __func__, __LINE__, (name), ((subname) != NULL) ? (const char *)(subname) : "", __VA_ARGS__); \
					fflush(stderr); \
				} \
			} else { \
				if (flt == FIPS_LOG_SYSLOG) { \
					syslog(LOG_INFO, "GNUTLS: %s:%s:%d:%s:" fmt ":SUCCESS", __FILE__, __func__, __LINE__, (name), __VA_ARGS__); \
				} else { \
					fprintf(stderr, "GNUTLS: %s:%s:%d:%s:" fmt ":SUCCESS\n", __FILE__, __func__, __LINE__, (name), __VA_ARGS__); \
					fflush(stderr); \
				} \
			} \
		} \
	} while(0)
#define FIPSLOG_FAILED(name, subname, fmt, ...) \
	do { \
		enum fips_logging_type flt = fips_logging_enabled((name), (subname)); \
		if (flt != FIPS_NO_LOGGING) { \
			if ((subname) != NULL) { \
				if (flt == FIPS_LOG_SYSLOG) { \
					syslog(LOG_INFO, "GNUTLS: %s:%s:%d:%s.%s:" fmt ":FAILED", \
					__FILE__, __func__, __LINE__, (name), ((subname) != NULL) ? (const char *)(subname) : "", __VA_ARGS__); \
				} else { \
					fprintf(stderr, "GNUTLS: %s:%s:%d:%s.%s:" fmt ":FAILED\n", \
					__FILE__, __func__, __LINE__, (name), ((subname) != NULL) ? (const char *)(subname) : "", __VA_ARGS__); \
					fflush(stderr); \
				} \
			} else { \
				if (flt == FIPS_LOG_SYSLOG) { \
					syslog(LOG_INFO, "GNUTLS: %s:%s:%d:%s:" fmt ":FAILED", __FILE__, __func__, __LINE__, (name), __VA_ARGS__); \
				} else { \
					fprintf(stderr, "GNUTLS: %s:%s:%d:%s:" fmt ":FAILED\n", __FILE__, __func__, __LINE__, (name), __VA_ARGS__); \
					fflush(stderr); \
				} \
			} \
		} \
	} while(0)

#else /* GNUTLS_SUCCESS_AUDIT_WITH_SYSLOG */

#define FIPSLOG_SUCCESS(name, subname, fmt, ...) ((void)0)
#define FIPSLOG_FAILED(name, subname, fmt, ...) ((void)0)

#include <stdbool.h>

inline enum fips_logging_type fips_logging_enabled(const char *name, const char *subname);
{
	return FIPS_NO_LOGGING;
}
inline bool fips_request_failure(const char *name, const char *subname)
{
	return false;
}
#endif /* GNUTLS_SUCCESS_AUDIT_WITH_SYSLOG */

#endif /* GNUTLS_LIB_FIPSLOG_H */
