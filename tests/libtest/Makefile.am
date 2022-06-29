include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBNS_CFLAGS)		\
	$(LIBUV_CFLAGS)		\
	-I$(top_srcdir)/lib/isc

LDADD +=			\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)		\
	$(LIBNS_LIBS)

check_LTLIBRARIES = libtest.la

libtest_la_SOURCES =			\
	../include/tests/dns.h		\
	../include/tests/isc.h		\
	../include/tests/ns.h		\
	dns.c				\
	isc.c				\
	ns.c

isc.lo: $(LIBISC_LIBS)
dns.lo: $(LIBDNS_LIBS)
ns.lo: $(LIBNS_LIBS)

libtest_la:: $(LIBISC_LIBS) $(LIBDNS_LIBS) $(LIBNS_LIBS)

include $(top_srcdir)/Makefile.tests
