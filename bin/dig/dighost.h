/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#ifndef DIG_H
#define DIG_H

/*! \file */

#include <inttypes.h>
#include <stdbool.h>

#include <isc/attributes.h>
#include <isc/buffer.h>
#include <isc/bufferlist.h>
#include <isc/formatcheck.h>
#include <isc/lang.h>
#include <isc/list.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/sockaddr.h>
#include <isc/socket.h>

#include <dns/rdatalist.h>

#include <dst/dst.h>

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif /* ifdef __APPLE__ */

#define MXSERV 20
#define MXNAME (DNS_NAME_MAXTEXT + 1)
#define MXRD   32
/*% Buffer Size */
#define BUFSIZE	 512
#define COMMSIZE 0xffff
#ifndef RESOLV_CONF
/*% location of resolve.conf */
#define RESOLV_CONF "/etc/resolv.conf"
#endif /* ifndef RESOLV_CONF */
/*% output buffer */
#define OUTPUTBUF 32767
/*% Max RR Limit */
#define MAXRRLIMIT 0xffffffff
#define MAXTIMEOUT 0xffff
/*% Max number of tries */
#define MAXTRIES 0xffffffff
/*% Max number of dots */
#define MAXNDOTS 0xffff
/*% Max number of ports */
#define MAXPORT 0xffff
/*% Max serial number */
#define MAXSERIAL 0xffffffff
/*% Max query ID */
#define MAXQID 0xffff

/*% Default TCP Timeout */
#define TCP_TIMEOUT 10
/*% Default UDP Timeout */
#define UDP_TIMEOUT 5

#define SERVER_TIMEOUT 1

#define LOOKUP_LIMIT 64

#define DEFAULT_EDNS_VERSION 0
#define DEFAULT_EDNS_BUFSIZE 4096

/*%
 * Lookup_limit is just a limiter, keeping too many lookups from being
 * created.  It's job is mainly to prevent the program from running away
 * in a tight loop of constant lookups.  It's value is arbitrary.
 */

ISC_LANG_BEGINDECLS

typedef struct dig_lookup dig_lookup_t;
typedef struct dig_query dig_query_t;
typedef struct dig_server dig_server_t;
typedef ISC_LIST(dig_server_t) dig_serverlist_t;
typedef struct dig_searchlist dig_searchlist_t;

#define DIG_QUERY_MAGIC ISC_MAGIC('D', 'i', 'g', 'q')

#define DIG_VALID_QUERY(x) ISC_MAGIC_VALID((x), DIG_QUERY_MAGIC)

/*% The dig_lookup structure */
struct dig_lookup {
	bool pending, /*%< Pending a successful answer */
		waiting_connect, doing_xfr, ns_search_only, /*%< dig
							     * +nssearch,
							     * host -C */
		identify, /*%< Append an "on server <foo>" message */
		identify_previous_line, /*% Prepend a "Nameserver <foo>:"
					 * message, with newline and tab */
		ignore, recurse, aaonly, adflag, cdflag, raflag, tcflag, zflag,
		trace,	    /*% dig +trace */
		trace_root, /*% initial query for either +trace or +nssearch
			     * */
		tcp_mode, tcp_mode_set, comments, stats, section_question,
		section_answer, section_authority, section_additional,
		servfail_stops, new_search, need_search, done_as_is, besteffort,
		dnssec, expire, sendcookie, seenbadcookie, badcookie,
		nsid, /*% Name Server ID (RFC 5001) */
		tcp_keepalive, header_only, ednsneg, mapped,
		print_unknown_format, multiline, nottl, noclass, onesoa,
		use_usec, nocrypto, ttlunits, idnin, idnout, expandaaaa, qr,
		accept_reply_unexpected_src, /*%  print replies from
					      * unexpected
					      *   sources. */
		setqid;			     /*% use a speciied query ID */
	char textname[MXNAME];		     /*% Name we're going to be
					      * looking up */
	char cmdline[MXNAME];
	dns_rdatatype_t rdtype;
	dns_rdatatype_t qrdtype;
	dns_rdataclass_t rdclass;
	bool rdtypeset;
	bool rdclassset;
	char name_space[BUFSIZE];
	char oname_space[BUFSIZE];
	isc_buffer_t namebuf;
	isc_buffer_t onamebuf;
	isc_buffer_t renderbuf;
	char *sendspace;
	dns_name_t *name;
	isc_interval_t interval;
	dns_message_t *sendmsg;
	dns_name_t *oname;
	ISC_LINK(dig_lookup_t) link;
	ISC_LIST(dig_query_t) q;
	ISC_LIST(dig_query_t) connecting;
	dig_query_t *current_query;
	dig_serverlist_t my_server_list;
	dig_searchlist_t *origin;
	dig_query_t *xfr_q;
	uint32_t retries;
	int nsfound;
	int16_t udpsize;
	int16_t edns;
	int16_t padding;
	uint32_t ixfr_serial;
	isc_buffer_t rdatabuf;
	char rdatastore[MXNAME];
	dst_context_t *tsigctx;
	isc_buffer_t *querysig;
	uint32_t msgcounter;
	dns_fixedname_t fdomain;
	isc_sockaddr_t *ecs_addr;
	char *cookie;
	dns_ednsopt_t *ednsopts;
	unsigned int ednsoptscnt;
	isc_dscp_t dscp;
	unsigned int ednsflags;
	dns_opcode_t opcode;
	int rrcomments;
	unsigned int eoferr;
	uint16_t qid;
};

/*% The dig_query structure */
struct dig_query {
	unsigned int magic;
	dig_lookup_t *lookup;
	bool waiting_connect, pending_free, waiting_senddone, first_pass,
		first_soa_rcvd, second_rr_rcvd, first_repeat_rcvd,
		warn_id, timedout;
	uint32_t first_rr_serial;
	uint32_t second_rr_serial;
	uint32_t msg_count;
	uint32_t rr_count;
	bool ixfr_axfr;
	char *servname;
	char *userarg;
	isc_buffer_t sendbuf;
	char *recvspace, *tmpsendspace, lengthspace[4];
	isc_nmhandle_t *handle;
	isc_nmhandle_t *readhandle;
	isc_nmhandle_t *sendhandle;
	ISC_LINK(dig_query_t) link;
	ISC_LINK(dig_query_t) clink;
	isc_sockaddr_t sockaddr;
	isc_time_t time_sent;
	isc_time_t time_recv;
	uint64_t byte_count;
	isc_timer_t *timer;
};

struct dig_server {
	char servername[MXNAME];
	char userarg[MXNAME];
	ISC_LINK(dig_server_t) link;
};

struct dig_searchlist {
	char origin[MXNAME];
	ISC_LINK(dig_searchlist_t) link;
};

typedef ISC_LIST(dig_searchlist_t) dig_searchlistlist_t;
typedef ISC_LIST(dig_lookup_t) dig_lookuplist_t;

/*
 * Externals from dighost.c
 */

extern dig_lookuplist_t lookup_list;
extern dig_serverlist_t server_list;
extern dig_searchlistlist_t search_list;
extern unsigned int extrabytes;

extern bool check_ra, have_ipv4, have_ipv6, specified_source, usesearch,
	showsearch, yaml;
extern in_port_t port;
extern unsigned int timeout;
extern isc_mem_t *mctx;
extern int sendcount;
extern int ndots;
extern int lookup_counter;
extern int exitcode;
extern isc_sockaddr_t localaddr;
extern char keynametext[MXNAME];
extern char keyfile[MXNAME];
extern char keysecret[MXNAME];
extern const dns_name_t *hmacname;
extern unsigned int digestbits;
extern dns_tsigkey_t *tsigkey;
extern bool validated;
extern isc_taskmgr_t *taskmgr;
extern isc_task_t *global_task;
extern bool free_now;
extern bool debugging, debugtiming, memdebugging;
extern bool keep_open;

extern char *progname;
extern int tries;
extern int fatalexit;
extern bool verbose;

/*
 * Routines in dighost.c.
 */
isc_result_t
get_address(char *host, in_port_t myport, isc_sockaddr_t *sockaddr);

int
getaddresses(dig_lookup_t *lookup, const char *host, isc_result_t *resultp);

isc_result_t
get_reverse(char *reverse, size_t len, char *value, bool strict);

ISC_NORETURN void
fatal(const char *format, ...) ISC_FORMAT_PRINTF(1, 2);

void
warn(const char *format, ...) ISC_FORMAT_PRINTF(1, 2);

ISC_NORETURN void
digexit(void);

void
debug(const char *format, ...) ISC_FORMAT_PRINTF(1, 2);

void
check_result(isc_result_t result, const char *msg);

bool
setup_lookup(dig_lookup_t *lookup);

void
destroy_lookup(dig_lookup_t *lookup);

void
do_lookup(dig_lookup_t *lookup);

void
start_lookup(void);

void
onrun_callback(isc_task_t *task, isc_event_t *event);

int
dhmain(int argc, char **argv);

void
setup_libs(void);

void
setup_system(bool ipv4only, bool ipv6only);

isc_result_t
parse_uint(uint32_t *uip, const char *value, uint32_t max, const char *desc);

isc_result_t
parse_xint(uint32_t *uip, const char *value, uint32_t max, const char *desc);

isc_result_t
parse_netprefix(isc_sockaddr_t **sap, const char *value);

void
parse_hmac(const char *hmacstr);

dig_lookup_t *
requeue_lookup(dig_lookup_t *lookold, bool servers);

dig_lookup_t *
make_empty_lookup(void);

dig_lookup_t *
clone_lookup(dig_lookup_t *lookold, bool servers);

dig_server_t *
make_server(const char *servname, const char *userarg);

void
flush_server_list(void);

void
set_nameserver(char *opt);

void
clone_server_list(dig_serverlist_t src, dig_serverlist_t *dest);

void
cancel_all(void);

void
destroy_libs(void);

void
set_search_domain(char *domain);

/*
 * Routines to be defined in dig.c, host.c, and nslookup.c. and
 * then assigned to the appropriate function pointer
 */
extern isc_result_t (*dighost_printmessage)(dig_query_t *query,
					    const isc_buffer_t *msgbuf,
					    dns_message_t *msg, bool headers);

/*
 * Print an error message in the appropriate format.
 */
extern void (*dighost_error)(const char *format, ...);

/*
 * Print a warning message in the appropriate format.
 */
extern void (*dighost_warning)(const char *format, ...);

/*
 * Print a comment in the appropriate format.
 */
extern void (*dighost_comments)(dig_lookup_t *lookup, const char *format, ...);

/*%<
 * Print the final result of the lookup.
 */

extern void (*dighost_received)(unsigned int bytes, isc_sockaddr_t *from,
				dig_query_t *query);
/*%<
 * Print a message about where and when the response
 * was received from, like the final comment in the
 * output of "dig".
 */

extern void (*dighost_trying)(char *frm, dig_lookup_t *lookup);

extern void (*dighost_shutdown)(void);

extern void (*dighost_pre_exit_hook)(void);

void
save_opt(dig_lookup_t *lookup, char *code, char *value);

void
setup_file_key(void);
void
setup_text_key(void);

/*
 * Routines exported from dig.c for use by dig for iOS
 */

/*%<
 * Call once only to set up libraries, parse global
 * parameters and initial command line query parameters
 */
void
dig_setup(int argc, char **argv);

/*%<
 * Call to supply new parameters for the next lookup
 */
void
dig_query_setup(bool, bool, int argc, char **argv);

/*%<
 * set the main application event cycle running
 */
void
dig_startup(void);

/*%<
 * Initiates the next lookup cycle
 */
void
dig_query_start(void);

/*%<
 * Cleans up the application
 */
void
dig_shutdown(void);

ISC_LANG_ENDDECLS

#endif /* ifndef DIG_H */
