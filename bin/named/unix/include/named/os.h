/*
 * Copyright (C) 1999-2002, 2004, 2005, 2007-2009, 2014, 2016-2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef NAMED_OS_H
#define NAMED_OS_H 1

/*! \file */

#include <pwd.h>

#include <isc/types.h>

void
named_os_init(const char *progname);

void
named_os_daemonize(void);

void
named_os_opendevnull(void);

void
named_os_closedevnull(void);

void
named_os_chroot(const char *root);

void
named_os_inituserinfo(const char *username);

void
named_os_changeuser(void);

uid_t
ns_os_uid(void);

void
named_os_adjustnofile(void);

void
named_os_minprivs(void);

FILE *
named_os_openfile(const char *filename, mode_t mode, isc_boolean_t switch_user);

void
named_os_writepidfile(const char *filename, isc_boolean_t first_time);

isc_boolean_t
named_os_issingleton(const char *filename);

void
named_os_shutdown(void);

isc_result_t
named_os_gethostname(char *buf, size_t len);

void
named_os_shutdownmsg(char *command, isc_buffer_t *text);

void
named_os_tzset(void);

void
named_os_started(void);

char *
named_os_uname(void);

#endif /* NAMED_OS_H */
