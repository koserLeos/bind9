/*
 * Copyright (C) 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: check.c,v 1.4 2001/03/03 23:05:23 bwelling Exp $ */

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include <isc/log.h>
#include <isc/result.h>

#include <isccfg/cfg.h>
#include <isccfg/check.h>

#define MASTERZONE	1
#define SLAVEZONE	2
#define STUBZONE	4
#define HINTZONE	8
#define FORWARDZONE	16

typedef struct {
	const char *name;
	int allowed;
} optionstable;

static isc_result_t
check_zoneconf(cfg_obj_t *zconfig, isc_log_t *logctx) {
	const char *zname;
	const char *typestr;
	unsigned int ztype;
	cfg_obj_t *zoptions;
	cfg_obj_t *obj = NULL;
	isc_result_t result;
	unsigned int i;

	static optionstable options[] = {
	{ "allow-query", MASTERZONE | SLAVEZONE | STUBZONE },
	{ "allow-transfer", MASTERZONE | SLAVEZONE | STUBZONE },
	{ "notify", MASTERZONE | SLAVEZONE },
	{ "also-notify", MASTERZONE | SLAVEZONE },
	{ "dialup", MASTERZONE | SLAVEZONE | STUBZONE },
	{ "forward", MASTERZONE | SLAVEZONE | STUBZONE | FORWARDZONE},
	{ "forwarders", MASTERZONE | SLAVEZONE | STUBZONE | FORWARDZONE},
	{ "maintain-ixfr-base", MASTERZONE | SLAVEZONE },
	{ "max-ixfr-log-size", MASTERZONE | SLAVEZONE },
	{ "transfer-source", MASTERZONE | SLAVEZONE | STUBZONE },
	{ "transfer-source-v6", MASTERZONE | SLAVEZONE | STUBZONE },
	{ "max-transfer-time-in", SLAVEZONE | STUBZONE },
	{ "max-transfer-time-out", MASTERZONE | SLAVEZONE },
	{ "max-transfer-idle-in", SLAVEZONE | STUBZONE },
	{ "max-transfer-idle-out", MASTERZONE | SLAVEZONE },
	{ "max-retry-time", SLAVEZONE | STUBZONE },
	{ "min-retry-time", SLAVEZONE | STUBZONE },
	{ "max-refresh-time", SLAVEZONE | STUBZONE },
	{ "min-refresh-time", SLAVEZONE | STUBZONE },
	{ "sig-validity-interval", MASTERZONE },
	{ "zone-statistics", MASTERZONE | SLAVEZONE | STUBZONE },
	{ "allow-update", MASTERZONE },
	{ "allow-update-forwarding", SLAVEZONE | STUBZONE },
	{ "file", MASTERZONE | SLAVEZONE | STUBZONE | HINTZONE},
	{ "ixfr-base", MASTERZONE | SLAVEZONE },
	{ "ixfr-tmp-file", MASTERZONE | SLAVEZONE },
	{ "masters", SLAVEZONE | STUBZONE },
	{ "pubkey", MASTERZONE | SLAVEZONE | STUBZONE },
	{ "update-policy", MASTERZONE },
	{ "database", MASTERZONE | SLAVEZONE | STUBZONE },
	};

	static optionstable dialups[] = {
	{ "notify", MASTERZONE | SLAVEZONE },
	{ "notify-passive", SLAVEZONE },
	{ "refresh", SLAVEZONE | STUBZONE },
	{ "passive", SLAVEZONE | STUBZONE },
	};

	zname = cfg_obj_asstring(cfg_tuple_get(zconfig, "name"));

	zoptions = cfg_tuple_get(zconfig, "options");

	obj = NULL;
	(void)cfg_map_get(zoptions, "type", &obj);
	if (obj == NULL) {
		cfg_obj_log(zconfig, logctx, ISC_LOG_ERROR,
			    "zone '%s': type not present", zname);
		return (ISC_R_FAILURE);
	}

	typestr = cfg_obj_asstring(obj);
	if (strcasecmp(typestr, "master") == 0)
		ztype = MASTERZONE;
	else if (strcasecmp(typestr, "slave") == 0)
		ztype = SLAVEZONE;
	else if (strcasecmp(typestr, "stub") == 0)
		ztype = STUBZONE;
	else if (strcasecmp(typestr, "forward") == 0)
		ztype = FORWARDZONE;
	else if (strcasecmp(typestr, "hint") == 0)
		ztype = HINTZONE;
	else {
		cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
			    "zone '%s': invalid type %s",
			    zname, typestr);
		return (ISC_R_FAILURE);
	}

	for (i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
		obj = NULL;
		if ((options[i].allowed & ztype) == 0 &&
		    cfg_map_get(zoptions, options[i].name, &obj) ==
		    ISC_R_SUCCESS)
		{
			cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
				    "option '%s' is not allowed in '%s' "
				    "zone '%s'",
				    options[i].name, typestr, zname);
			result = ISC_R_FAILURE;
		}
	}

	if (ztype == SLAVEZONE || ztype == STUBZONE) {
		obj = NULL;
		if (cfg_map_get(zoptions, "masters", &obj) != ISC_R_SUCCESS) {
			cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
				    "zone '%s': missing 'masters' entry",
				    zname);
			result = ISC_R_FAILURE;
		}
	}

	if (ztype == MASTERZONE) {
		isc_result_t res1, res2;
		obj = NULL;
		res1 = cfg_map_get(zoptions, "allow-update", &obj);
		obj = NULL;
		res2 = cfg_map_get(zoptions, "update-policy", &obj);
		if (res1 == ISC_R_SUCCESS && res2 == ISC_R_SUCCESS) {
			cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
				    "zone '%s': 'allow-update' is ignored "
				    "when 'update-policy' is present",
				    zname);
			result = ISC_R_FAILURE;
		}
	}

	if (ztype == MASTERZONE || ztype == SLAVEZONE || ztype == STUBZONE) {
		cfg_obj_t *dialup = NULL;
		cfg_map_get(zoptions, "dialup", &dialup);
		if (dialup != NULL && cfg_obj_isstring(dialup)) {
			char *str = cfg_obj_asstring(dialup);
			for (i = 0;
			     i < sizeof(dialups) / sizeof(dialups[0]);
			     i++)
			{
				if (strcasecmp(dialups[i].name, str) != 0)
					continue;
				if ((dialups[i].allowed & ztype) == 0) {
					cfg_obj_log(obj, logctx,
						    ISC_LOG_ERROR,
						    "dialup type '%s' is not "
						    "allowed in '%s' "
						    "zone '%s'",
						    str, typestr, zname);
					result = ISC_R_FAILURE;
				}
				break;
			}
			if (i == sizeof(dialups) / sizeof(dialups[0])) {
				cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
					    "invalid dialup type '%s' in zone "
					    "'%s'", str, zname);
				result = ISC_R_FAILURE;
			}
		}
	}

	return (result);
}

isc_result_t
cfg_check_namedconf(cfg_obj_t *config, isc_log_t *logctx) {
	cfg_obj_t *options = NULL;
	cfg_obj_t *views = NULL;
	cfg_obj_t *obj;
	cfg_listelt_t *velement;
	isc_result_t result = ISC_R_SUCCESS;

	(void)cfg_map_get(config, "options", &options);

	(void)cfg_map_get(config, "view", &views);

	if (views == NULL) {
		cfg_obj_t *zones = NULL;
		cfg_listelt_t *zelement;

		(void)cfg_map_get(config, "zone", &zones);
		for (zelement = cfg_list_first(zones);
		     zelement != NULL;
		     zelement = cfg_list_next(zelement))
		{
			cfg_obj_t *zone = cfg_listelt_value(zelement);

			if (check_zoneconf(zone, logctx) != ISC_R_SUCCESS)
				result = ISC_R_FAILURE;
		}
	} else {
		cfg_obj_t *zones = NULL;
		cfg_obj_t *peers = NULL;

		(void)cfg_map_get(config, "zone", &zones);
		if (zones != NULL) {
			cfg_obj_log(zones, logctx, ISC_LOG_ERROR,
				    "when using 'view' statements, "
				    "all zones must be in views");
			result = ISC_R_FAILURE;
		}

		(void)cfg_map_get(config, "server", &peers);
		if (peers != NULL) {
			cfg_obj_log(zones, logctx, ISC_LOG_ERROR,
				    "when using 'view' statements, "
				    "all server statements must be in views");
			result = ISC_R_FAILURE;
		}
	}

	for (velement = cfg_list_first(views);
	     velement != NULL;
	     velement = cfg_list_next(velement))
	{
		cfg_obj_t *view = cfg_listelt_value(velement);
		cfg_obj_t *voptions = cfg_tuple_get(view, "options");
		cfg_obj_t *zones = NULL;
		cfg_listelt_t *zelement;

		(void)cfg_map_get(voptions, "zone", &zones);
		for (zelement = cfg_list_first(zones);
		     zelement != NULL;
		     zelement = cfg_list_next(zelement))
		{
			cfg_obj_t *zone = cfg_listelt_value(zelement);

			if (check_zoneconf(zone, logctx) != ISC_R_SUCCESS)
				result = ISC_R_FAILURE;
		}
	}

	if (views != NULL && options != NULL) {
		obj = NULL;
		result = cfg_map_get(options, "cache-file", &obj);
		if (result == ISC_R_SUCCESS) {
			cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
				    "'cache-file' cannot be a global "
				    "option if views are present");
			result = ISC_R_FAILURE;
		}
		result = ISC_R_SUCCESS;
	}

	if (options != NULL) {
		obj = NULL;
		result = cfg_map_get(options, "max-cache-size", &obj);
		if (result == ISC_R_SUCCESS &&
		    cfg_obj_isstring(obj))
		{
			cfg_obj_log(obj, logctx, ISC_LOG_ERROR,
				    "'max-cache-size' cannot have the "
				    "value 'default'");
			result = ISC_R_FAILURE;
		}
	}

	return (result);
}
