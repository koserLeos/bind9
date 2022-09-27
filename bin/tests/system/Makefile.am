include $(top_srcdir)/Makefile.top

EXTRA_DIST = .

# Source tarballs must not contain configure/build artifacts.
dist-hook:
	git clean -n -x -d | \
	        grep -v "Makefile.in$$" | \
	        sed -n "s|^Would remove \(.*\)|$(distdir)/\1|p" | \
	        xargs -I{} rm -rf "{}"

SUBDIRS = dyndb/driver dlzexternal/driver hooks/driver

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)

LDADD +=			\
	$(LIBISC_LIBS)

check_PROGRAMS =		\
	feature-test		\
	makejournal		\
	pipelined/pipequeries	\
	rndc/gencheck		\
	rpz/dnsrps		\
	tkey/keycreate		\
	tkey/keydelete

feature_test_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(LIBDNS_CFLAGS)

makejournal_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(LIBDNS_CFLAGS)

makejournal_LDADD =		\
	$(LDADD)		\
	$(LIBDNS_LIBS)

pipelined_pipequeries_CPPFLAGS =	\
	$(AM_CPPFLAGS)			\
	$(LIBDNS_CFLAGS)

pipelined_pipequeries_LDADD =	\
	$(LDADD)		\
	$(LIBDNS_LIBS)

tkey_keycreate_CPPFLAGS =	\
	$(AM_CPPFLAGS)		\
	$(LIBDNS_CFLAGS)

tkey_keycreate_LDADD =		\
	$(LDADD)		\
	$(LIBDNS_LIBS)

tkey_keydelete_CPPFLAGS =	\
	$(AM_CPPFLAGS)		\
	$(LIBDNS_CFLAGS)

tkey_keydelete_LDADD =		\
	$(LDADD)		\
	$(LIBDNS_LIBS)

TESTS = doth

LOG_DRIVER_V = $(LOG_DRIVER_V_@AM_V@)
LOG_DRIVER_V_ = $(LOG_DRIVER_V_@AM_DEFAULT_V@)
LOG_DRIVER_V_0 = --verbose no
LOG_DRIVER_V_1 = --verbose yes

LOG_DRIVER = $(srcdir)/custom-test-driver
AM_LOG_DRIVER_FLAGS = $(LOG_DRIVER_V)

LOG_COMPILER = $(builddir)/run.sh
AM_LOG_FLAGS = -r

$(TESTS): run.sh

test-local: check
