/*
 * Copyright (C) 2000, 2001, 2004, 2005, 2007, 2015, 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: util.c,v 1.7 2007/06/19 23:46:59 tbox Exp $ */

/*! \file */

#include <config.h>

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include <isc/boolean.h>
#include <isc/print.h>

#include "util.h"

extern isc_boolean_t verbose;
extern const char *progname;

void
notify(const char *fmt, ...) {
	va_list ap;

	if (verbose) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fputs("\n", stderr);
	}
}

void
fatal(const char *format, ...) {
	va_list args;

	fprintf(stderr, "%s: ", progname);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	exit(1);
}
