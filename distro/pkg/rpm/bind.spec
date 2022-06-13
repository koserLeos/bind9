%global PACKAGE_VERSION {{ version | replace("-", ".") }}

%bcond_without scl

%if %{with scl}
%global scl isc-bind
%endif

# Work around an SCL build issue on Fedora 33+
# (https://bugzilla.redhat.com/show_bug.cgi?id=1898587)
%if 0%{?fedora} >= 33
%global __python %{__python3}
%endif

%{?scl:%scl_package bind}
%{!?scl:%global pkg_name %{name}}

##### Macro and variable definitions

%define replace_tokens						\
	sed							\\\
		-e "s|@LOCALSTATEDIR@|%{_localstatedir}|g;"	\\\
		-e "s|@SCL_ROOT@|%{?_scl_root}|g;"		\\\
		-e "s|@SYSCONFDIR@|%{_sysconfdir}|g;"

# On some systems, %%scl_prefix is a macro rather than a %%global variable;
# thus, a helper variable is used to prevent "Too many levels of recursion in
# macro expansion" errors on such systems, caused by passing an argument
# containing %%{?scl_prefix} to a macro using the %%{?*} construct
%global service_name %{?scl_prefix}named

##### Conditionally enabled features

%bcond_without	dnstap
%bcond_with	tuninglarge

##### Package metadata

# 'bind' package

Name:		%{?scl:%scl_pkg_name}%{?!scl:isc-bind}
Version:	%{PACKAGE_VERSION}
# TODO: custom release version, see https://gitlab.nic.cz/packaging/apkg/-/issues/76
Release:	0%{?dist}
Summary:	The Berkeley Internet Name Domain (BIND) DNS (Domain Name System) server
License:	MPL 2.0
URL:		https://www.isc.org/downloads/BIND/
BuildRequires:	json-c-devel
BuildRequires:	krb5-devel
BuildRequires:	libxml2-devel
BuildRequires:	libxslt
BuildRequires:	openssl-devel
BuildRequires:	perl
BuildRequires:	systemd
%{?systemd_requires}

BuildRequires:	jemalloc-devel
BuildRequires:	libnghttp2-devel
Requires:	%{name}-libs = %{PACKAGE_VERSION}
%{?!scl:Conflicts: bind}

BuildRequires:	python3
BuildRequires:	libcap-devel
BuildRequires:	%{?scl_prefix}libuv-devel
Requires:	%{?scl_prefix}libuv

%if %{with dnstap}
BuildRequires:	%{?scl_prefix}fstrm-devel
BuildRequires:	%{?scl_prefix}protobuf-c-compiler
BuildRequires:	%{?scl_prefix}protobuf-c-devel
BuildRequires:	%{?scl_prefix}protobuf-compiler
BuildRequires:	%{?scl_prefix}protobuf-devel
Requires:	%{?scl_prefix}fstrm
Requires:	%{?scl_prefix}protobuf-c
%endif

%{?scl:BuildRequires: %{scl}-build}
%{?scl:BuildRequires: %scl_runtime}
%{?scl:Requires: %scl_runtime}

Source0:	{{ name }}-{{ version }}.tar.xz
Source1:	named.service.in
Source2:	named.sysconfig
Source3:	named.conf.in

%description
BIND (Berkeley Internet Name Domain) is an implementation of the DNS
(Domain Name System) protocol. BIND includes a DNS server (named),
which resolves host names to IP addresses; a resolver library
(routines for applications to use when interfacing with DNS); and
tools for verifying that the DNS server is operating properly.

# 'bind-devel' package

%package devel
Summary:	Header files and libraries needed for BIND DNS development
Requires:	%{name}-libs = %{PACKAGE_VERSION}
%{?!scl:Conflicts: bind-devel}

%description devel
The isc-bind-devel package contains full version of the header files and libraries
required for development with ISC BIND 9.

# 'bind-libs' package

%package libs
Summary:	Libraries used by the BIND DNS packages
%{?!scl:Conflicts: bind-libs}

%description libs
Contains heavyweight version of BIND suite libraries used by both named DNS
server and utilities in isc-bind-utils package.

# 'bind-utils' package

%package utils
Summary:	Utilities for querying DNS name servers
Requires:	%{name}-libs = %{PACKAGE_VERSION}
%{?!scl:Conflicts: bind-utils}

%description utils
isc-bind-utils contains a collection of utilities for querying DNS (Domain
Name System) name servers to find out information about Internet
hosts. These tools will provide you with the IP addresses for given
host names, as well as other information about registered domains and
network addresses.

You should install isc-bind-utils if you need to get information from DNS name
servers.

##### Build instructions

# 'bind' package

%prep
%setup -q -n bind-{{ version }}

%build
%{?scl:scl enable %scl -- <<\EOF}
%set_build_flags
set -e -v
export CPPFLAGS="${CPPFLAGS}%{?extra_cppflags: %{extra_cppflags}}"
export CFLAGS="${CFLAGS}%{?extra_cflags: %{extra_cflags}}"
export LDFLAGS="${LDFLAGS} -L%{_libdir}%{?extra_ldflags: %{extra_ldflags}}"
# Some systems (e.g. Fedora 32+) set LT_SYS_LIBRARY_PATH to the value of the
# SCL's %%{_libdir}, which prevents RPATH for BIND binaries from being set to
# that path.  However, we need RPATH to be set for BIND binaries in SCL-based
# packages so that the isc-bind-named service can be started in the proper
# SELinux context (as using "scl enable" messes with SELinux contexts on
# systemd-based systems).  Hardcode LT_SYS_LIBRARY_PATH to an arbitrary path in
# order to prevent libtool from stripping BIND binaries from the SCL RPATH.
export LT_SYS_LIBRARY_PATH=/usr/lib64
export SPHINX_BUILD=%{_builddir}/bind-{{ version }}/sphinx/bin/sphinx-build
export CPPFLAGS="${CPPFLAGS} -I%{_includedir}"
export STD_CINCLUDES="-I%{_includedir}"
%endif
%configure \
	--disable-static \
%if %{with dnstap}
	--enable-dnstap \
%else
	--disable-dnstap \
%endif
	--with-pic \
	--with-gssapi \
	--with-json-c \
	--with-libxml2 \
	--without-lmdb \
	--without-python \
%if %{with tuninglarge}
	--with-tuning=large \
%endif
;

python3 -m venv sphinx
source sphinx/bin/activate
pip install sphinx_rtd_theme
make %{?_smp_mflags}
make doc

%{?scl:EOF}

%install
make install DESTDIR=${RPM_BUILD_ROOT}

# Remove redundant files installed by "make install"
rm -f ${RPM_BUILD_ROOT}%{_sysconfdir}/bind.keys
rm -f ${RPM_BUILD_ROOT}%{_libdir}/*.la
rm -f ${RPM_BUILD_ROOT}%{_libdir}/*/*.la
rm -rf ${RPM_BUILD_ROOT}%{_builddir}/

# systemd unit file
install -d ${RPM_BUILD_ROOT}%{_unitdir}
%replace_tokens %{SOURCE1} > ${RPM_BUILD_ROOT}%{_unitdir}/%{service_name}.service

# /etc files
install -d ${RPM_BUILD_ROOT}%{_sysconfdir}/sysconfig
install %{SOURCE2} ${RPM_BUILD_ROOT}%{_sysconfdir}/sysconfig/named
%replace_tokens %{SOURCE3} > ${RPM_BUILD_ROOT}%{_sysconfdir}/named.conf
touch ${RPM_BUILD_ROOT}%{_sysconfdir}/rndc.key

# /var directories
install -d ${RPM_BUILD_ROOT}%{_localstatedir}/named/data
install -d ${RPM_BUILD_ROOT}%{_localstatedir}/run/named

# tmpfiles.d entry required to recreate /run/named on reboot (/tmp is a tmpfs)
install -d ${RPM_BUILD_ROOT}%{_tmpfilesdir}
echo "d %{_localstatedir}/run/named 0770 named named -" > ${RPM_BUILD_ROOT}%{_tmpfilesdir}/%{service_name}.conf

%files
%defattr(-,root,root,-)

%doc CHANGES*
%doc README*

%doc doc/arm/_build/html/*

%{_libdir}/*/*.so

%{_bindir}/dnssec-*
%{_bindir}/named-checkconf
%{_bindir}/named-checkzone
%{_bindir}/named-compilezone
%{_bindir}/named-journalprint
%{_bindir}/nsec3hash
%{_mandir}/man1/dnssec-*.1.*
%{_mandir}/man1/named-checkconf.1.*
%{_mandir}/man1/named-checkzone.1.*
%{_mandir}/man1/named-compilezone.1.*
%{_mandir}/man1/named-journalprint.1.*
%{_mandir}/man1/nsec3hash.1.*

%{_mandir}/man5
%{_mandir}/man8
%{_sbindir}/*

%attr(0644,root,root) %{_unitdir}/%{service_name}.service

%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/sysconfig/named

%defattr(0640, root, named, 0750)
%config(noreplace) %{_sysconfdir}/named.conf
%ghost %config(noreplace) %{_sysconfdir}/rndc.key
%dir %{_localstatedir}/named
%defattr(0660, named, named, 0770)
%dir %{_localstatedir}/named/data

%defattr(-,root,root,-)
%{_tmpfilesdir}/%{service_name}.conf

# 'bind-devel' package

%files devel
%defattr(-,root,root,-)
%{_includedir}/*

# 'bind-libs' package

%files libs
%defattr(-,root,root,-)
%{_libdir}/*.so*

# 'bind-utils' package

%files utils
%defattr(-,root,root,-)
%{_bindir}/arpaname
%{_bindir}/delv
%{_bindir}/dig
%{_bindir}/host
%{_bindir}/mdig
%{_bindir}/named-rrchecker
%{_bindir}/nslookup
%{_bindir}/nsupdate
%{_mandir}/man1/arpaname.1.*
%{_mandir}/man1/delv.1.*
%{_mandir}/man1/dig.1.*
%{_mandir}/man1/host.1.*
%{_mandir}/man1/mdig.1.*
%{_mandir}/man1/named-rrchecker.1.*
%{_mandir}/man1/nslookup.1.*
%{_mandir}/man1/nsupdate.1.*

%if %{with dnstap}
%{_bindir}/dnstap-read
%{_mandir}/man1/dnstap-read.1.*
%endif

##### Installation/upgrade/removal scriptlets

# 'bind' package

%pre
if [ "$1" -eq 1 ]; then
	# Initial installation, not upgrade
	getent group named >/dev/null 2>&1 || groupadd -f -r named
	getent passwd named >/dev/null 2>&1 || useradd -c named -d %{_localstatedir}/named -g named -r -s /sbin/nologin named
fi

%post
%systemd_post %{service_name}.service
if [ "$1" -eq 1 ]; then
	# Initial installation, not upgrade
	%tmpfiles_create %{service_name}.conf
fi

%global RNDC_CONFGEN_CMD	%{_sbindir}/rndc-confgen -a

if [ "$1" -eq 1 ]; then
	# Initial installation, not upgrade
	if [ ! -s %{_sysconfdir}/rndc.key ] && [ ! -s %{_sysconfdir}/rndc.conf ]; then
		if %{RNDC_CONFGEN_CMD} > /dev/null 2>&1; then
			chown root:named %{_sysconfdir}/rndc.key
			chmod 640 %{_sysconfdir}/rndc.key
			[ -x /sbin/restorecon ] && /sbin/restorecon %{_sysconfdir}/rndc.key
		fi
	fi
fi

%preun
%systemd_preun %{service_name}.service

%postun
%if 0%{?rhel} >= 8 || 0%{?fedora} >= 24
systemctl daemon-reload >/dev/null 2>&1 || :
%endif
%systemd_postun_with_restart %{service_name}.service

# 'bind-libs' package

%post libs
if [ "$1" -eq 1 ]; then
	# Initial installation, not upgrade
	ldconfig
fi
# ldconfig is intentionally not run in %%post during an upgrade; if the newer
# version of the 'bind-libs' package contains a library with the same interface
# number, but an older revision number than the library present in the
# currently installed version of this package, running ldconfig will reset the
# relevant symlink in /usr/lib64 so that it points to the library with highest
# revision number (i.e. the one installed by the version of the package which
# is about to be removed); this in turn will likely break restarting named upon
# upgrade (in %%postun for the 'bind' package), because it will attempt to
# dynamically load an incorrect version of the library

%postun libs
ldconfig
