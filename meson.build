project(
    'BIND',
    ['c'],
    version: '9.20.0-dev',
    meson_version: '>=1.1.0',
    license: 'MPL-2.0',
    default_options: [
        'b_asneeded=true',
        'b_pch=false',
        'b_pie=true',
        'c_std=gnu11',
        'default_library=shared',
        'warning_level=2',
        'werror=false',
        'wrap_mode=nofallback',
    ],
)

fs = import('fs')

git = find_program('git', required: false)
perl = find_program(['perl', 'perl5'])
sed = find_program('sed')

cc = meson.get_compiler('c')

prefix = get_option('prefix')

localstatedir = prefix / get_option('localstatedir')
sysconfdir = prefix / get_option('sysconfdir')
datadir = prefix / get_option('datadir')

if git.found() and fs.is_dir('.git')
    src_id = run_command(git, 'rev-parse', '--short', 'HEAD', check: true).stdout().substring(0, 7)
elif fs.is_file('.source-id')
    src_id = fs.read('.source-id', encoding: 'utf-8').strip()
else
    src_id = ''
endif

config = configuration_data()

config.set_quoted('PACKAGE_NAME', 'BIND')
config.set_quoted('PACKAGE_DESCRIPTION', 'Development Release')
config.set_quoted('PACKAGE_VERSION', meson.project_version())
config.set_quoted('PACKAGE_STRING', 'BIND' + meson.project_version())
config.set_quoted('PACKAGE_BUILDER', 'meson')
config.set_quoted('PACKAGE_SRCID', src_id)

if meson.build_options() == ''
    config.set_quoted('PACKAGE_CONFIGARGS', 'defaults')
else
    config.set_quoted('PACKAGE_CONFIGARGS', meson.build_options())
endif

if get_option('auto-validation').allowed()
    config.set_quoted('VALIDATION_DEFAULT', 'yes')
else
    config.set_quoted('VALIDATION_DEFAULT', 'no')
endif

config.set_quoted('SESSION_KEYFILE', localstatedir / 'run' / 'named' / 'session.key')

config.set_quoted('RNDC_CONFFILE', sysconfdir / 'rndc_srconf')
config.set_quoted('RNDC_KEYFILE', sysconfdir / 'rndc.key')

config.set_quoted('NAMED_PLUGINDIR', datadir / 'bind')
config.set_quoted('NAMED_LOCALSTATEDIR', localstatedir)
config.set_quoted('NAMED_SYSCONFDIR', sysconfdir)
config.set_quoted('NAMED_CONFFILE', sysconfdir / 'named_srconf')

# TODO: allow for config
config.set_quoted('CACHEDB_DEFAULT', 'qpcache')
config.set_quoted('ZONEDB_DEFAULT', 'qpzone')

sys_defines = [
    '-D_DARWIN_C_SOURCE',
    '-D_DEFAULT_SOURCE',
    '-D_FILE_OFFSET_BITS=64',
    '-D_GNU_SOURCE',
    '-D_LARGE_FILES',
    '-D_POSIX_C_SOURCE=200809L',
    '-D__APPLE_USE_RFC_3542=1',
]

add_project_arguments(sys_defines, language: 'c')

developer_mode = get_option('developer').enabled()
if developer_mode
    config.set('ISC_MEM_DEFAULTFILL', 1)
    config.set('ISC_MEM_TRACKLINES', 1)
    config.set('ISC_LIST_CHECKINIT', 1)
    config.set('ISC_STATS_CHECKUNDERFLOW', 1)
    config.set('DNS_RBTDB_STRONG_RWLOCK_CHECK', 1)
    config.set('ISC_MUTEX_ERROR_CHECK', 1)
endif

if get_option('optimization') != '0'
    add_project_arguments(
        [
            '-U_FORTIFY_SOURCE',
            '-D_FORTIFY_SOURCE=3',
        ],
        language: 'c',
    )
endif

### Compiler
add_project_arguments(
    cc.get_supported_arguments(
        [
            '-Wflex-array-member-not-at-end',
            '-Wformat',
            '-Wno-missing-field-initializers',
            '-Wpointer-arith',
            '-Wshadow',
            '-Wwrite-strings',

            '-Werror=alloca',
            '-Werror=format-security',
            '-Werror=implicit',
            '-Werror=implicit-function-declaration',
            '-Werror=missing-prototypes',
            '-Werror=parentheses',
            '-Werror=strict-prototypes',
            '-Werror=vla',

            '-fdiagnostics-show-option',
            '-fno-delete-null-pointer-checks',
            '-fno-strict-aliasing',
        ],
    ),
    language: 'c',
)

add_project_link_arguments(
    cc.get_supported_link_arguments(
        '-Wl,--export-dynamic',
        '-Wl,-z,noexecstack',
        '-Wl,-z,now',
        '-Wl,-z,relro',
        '-Wl,-z,separate-code',
    ),
    language: 'c',
)

if host_machine.system() == 'darwin'
    add_project_arguments(
        cc.get_supported_arguments(
            [
                # For GSS.Framework
                '-Wno-deprecated-declarations',

                # For _Noreturn in urcu
                '-Wno-unknown-attributes',
            ],
        ),
        language: 'c',
    )

    add_project_link_arguments(
        # for krb5
        cc.get_supported_link_arguments('-Wl,-no_warn_duplicate_libraries'),
        language: 'c',
    )
endif

foreach fn : [
    '__builtin_add_overflow',
    '__builtin_clz',
    '__builtin_mul_overflow',
    '__builtin_sub_overflow',
    '__builtin_unreachable',
]
    if cc.has_function(fn)
        config.set('HAVE_' + fn.substring(2).to_upper(), 1)
    endif
endforeach

foreach attr : [
    'constructor',
    'destructor',
    'malloc',
    'noreturn',
    'returns_nonnull',
]
    if cc.has_function_attribute(attr)
        config.set('HAVE_FUNC_ATTRIBUTE_' + attr.to_upper(), 1)
    endif
endforeach

malloc_ext_test = '''
#include <stddef.h>
#include <stdlib.h>

__attribute__ ((malloc, malloc(free, 1))
void * xmalloc(size_t sz) {
    return malloc(sz);
}

void main(void) {
    return xmalloc(8) != NULL;
}
'''

if cc.compiles(malloc_ext_test)
    config.set('HAVE_MALLOC_EXT_ATTR', 1)
endif

### Architecture
instruction_test = '''
int main(void) {
    __asm__ __volatile__ ("@0@");
    return 0;
}
'''

cpu_family = host_machine.cpu_family()

if cpu_family == 'arm' or cpu_family == 'aarch64'
    if cc.compiles(instruction_test.format('yield'))
        config.set('HAVE_ARM_YIELD', 1)
    endif
endif

if cpu_family == 'sparc' or cpu_family == 'sparc64'
    if cc.compiles(instruction_test.format('pause'))
        config.set('HAVE_SPARC_PAUSE', 1)
    endif
endif

if host_machine.endian() == 'big'
    config.set('WORDS_BIGENDIAN', 1)
endif

### Standard library and extensions
cc.has_header('stdatomic.h', required: true)
cc.has_header('stdnoreturn.h', required: true)

config.set('HAVE_STDNORETURN_H', 1)

atomic_test = '''
#include <stdatomic.h>
int main(void) {
    atomic_int_fast64_t val = 0;
    atomic_fetch_add_explicit(&val, 1, memory_order_relaxed);

    return 0;
}
'''

if not cc.compiles(atomic_test)
    atomic_dep = declare_dependency(link_args: '-latomic')
    if not cc.compiles(atomic_test, dependencies: atomic_dep)
        error(
            'libatomic needed, but linking with -latomic failed, please fix your toolchain',
        )
    endif

    add_project_link_arguments(atomic_dep, language: 'c')
endif

### OS
if get_option('locktype') == 'system'
    config.set('USE_PTHREAD_RWLOCK', 1)
endif

if host_machine.system() == 'sunos' and cc.get_id() == 'gcc'
    add_project_link_arguments('-zrelax=transtls', language: 'c')
    warn(
        'When using GNU C Compiler on Solaris, -zrelax=transtls linker flag is used to fix bug in Thread Local Storage',
    )
endif

# IPv6
foreach s : [
    'struct in6_addr',
    'struct in6_pktinfo',
    'struct sockaddr_in6',
    'struct sockaddr_storage',
]
    if not cc.has_type(s, args: sys_defines, prefix: '#include <netinet/in.h>')
        error('IPv6 support is mandatory')
    endif
endforeach

if not cc.has_member(
    'struct sockaddr_in6',
    'sin6_scope_id',
    args: sys_defines,
    prefix: '#include <netinet/in.h>',
)
    error('IPv6 support is mandatory')
endif

foreach sym : ['in6addr_any', 'in6addr_loopback']
    if not cc.has_header_symbol('netinet/in.h', sym, args: sys_defines)
        error('IPv6 support is mandatory')
    endif
endforeach

# TCP Fast Open
if get_option('tcp-fastopen').enabled()
    config.set('ENABLE_TCP_FASTOPEN', 1)
endif

foreach fn, header : {
    # Better strings
    'strlcpy': '#include <string.h>',
    'strlcat': '#include <string.h>',
    'strnstr': '#include <string.h>',

    # Backtrace
    'backtrace_symbols': '#include <execinfo.h>',

    # Timezone
    'tzset': '#include <time.h>',

    # Check for if_nametoindex() for IPv6 scoped addresses support
    'if_nametoindex': '#include <net/if.h>',

    # FILE locking
    'flockfile': '#include <stdio.h>',
    'getc_unlocked': '#include <stdio.h>',

    # UID/GID manipulation
    'setresuid': '#include <unistd.h>',
    'setreuid': '#include <unistd.h>',
    'getresuid': '#include <unistd.h>',
    'setresgid': '#include <unistd.h>',
    'setregid': '#include <unistd.h>',
    'getresgid': '#include <unistd.h>',

    # Thread Control
    'pthread_attr_getstacksize': '#include <pthread.h>',
    'pthread_attr_setstacksize': '#include <pthread.h>',
    'pthread_barrier_init': '#include <pthread.h>',
    'pthread_set_name_np': '#include <pthread.h>',
    'pthread_setname_np': '#include <pthread.h>',
    'pthread_spin_init': '#include <pthread.h>',
    'pthread_yield': '#include <pthread.h>',
    'pthread_yield_np': '#include <pthread.h>',

    # Misc.
    'sched_yield': '#include <sched.h>',
    'sysconf': '#include <unistd.h>',
    'clock_gettime': '#include <time.h>',
}
    if cc.has_function(fn, prefix: header, args: sys_defines)
        config.set('HAVE_' + fn.to_upper(), 1)
    endif
endforeach

# Check for nanoseconds in file stats
if cc.has_member('struct stat', 'st_mtim.tv_nsec', prefix: '#include <sys/stat.h>')
    config.set('HAVE_STAT_NSEC', 1)
endif

foreach h : [
    'fcntl.h',
    'linux/netlink.h',
    'linux/rtnetlink.h',
    'net/if6.h',
    'net/route.h',
    'regex.h',
    'sched.h',
    'sys/mman.h',
    'sys/param.h',
    'sys/select.h',
    'sys/socket.h',
    'sys/sockio.h',
    'sys/sysctl.h',
    'sys/time.h',
    'unistd.h',
]
    if cc.has_header(h)
        config.set('HAVE_' + h.underscorify().to_upper(), 1)
    endif
endforeach

### Dependencies
null_dep = dependency('', required: false)

thread_dep = dependency('threads')
m_dep = cc.find_library('m', required: false)

## OpenSSL
crypto_dep = dependency('libssl')
ssl_dep = dependency('libcrypto')

openssl_version_test = '''
#include <openssl/opensslv.h>

#if defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER < 0x02070000fL)
#error LibreSSL >= 2.7.0 required
#elif OPENSSL_VERSION_NUMBER < 0x1000000fL
#error OpenSSL >= 1.0.0 required
#endif

int main() {}
'''

if not cc.compiles(openssl_version_test, dependencies: [crypto_dep, ssl_dep])
    error('OpenSSL >= 1.0.0 or LibreSSL >= 2.7.0 required')
endif

foreach fn, header : {
    'EVP_default_properties_enable_fips': '#include <openssl/evp.h>',
    'FIPS_mode': '#include <openssl/crypto.h>',
}
    if cc.has_function(fn, prefix: header, dependencies: [crypto_dep, ssl_dep])
        config.set('HAVE_' + fn.to_upper(), 1)
    endif
endforeach

if get_option('fips').enabled() and not (
    config.has('HAVE_EVP_DEFAULT_PROPERTIES_ENABLE_FIPS')
    or config.has('FIPS_MODE')
)
    error('OpenSSL FIPS mode requested but not available')
endif

## Hash and curve probe
pkey_id_test = '''
#include <openssl/evp.h>

int main(void)
{
    if (EVP_PKEY_CTX_new_id(@0@, NULL) == NULL) {
        return 1;
    }

    return 0;
}
'''

foreach curve, id : {
    'P-256': 'NID_X9_62_prime256v1',
    'P-384': 'NID_secp384r1',
}
    if not cc.compiles(pkey_id_test.format(id), dependencies: ssl_dep)
        error(f'ECDSA over @curve@ support in OpenSSL is mandatory')
    endif
endforeach

if cc.compiles(pkey_id_test.format('NID_ED25519'), dependencies: ssl_dep)
    config.set('HAVE_OPENSSL_ED25519', 1)
endif

if cc.compiles(pkey_id_test.format('NID_ED448'), dependencies: ssl_dep)
    config.set('HAVE_OPENSSL_ED448', 1)
endif

if not cc.has_function('EVP_sha1', dependencies: [crypto_dep, ssl_dep])
    error('SHA-1 support in OpenSSL is mandatory')
endif

foreach evp : ['EVP_sha224', 'EVP_sha256', 'EVP_sha384', 'EVP_sha512']
    if not cc.has_function(evp, dependencies: [crypto_dep, ssl_dep])
        error('SHA-2 support in OpenSSL is mandatory')
    endif
endforeach

## Shimmable functions
foreach fn : [
    'BIO_read_ex',
    'BIO_write_ex',
    'BN_GENCB_new',
    'CRYPTO_zalloc',
    'ECDSA_SIG_get0',
    'ERR_get_error_all',
    'EVP_CIPHER_CTX_free',
    'EVP_CIPHER_CTX_new',
    'EVP_MD_CTX_free',
    'EVP_MD_CTX_get0_md',
    'EVP_MD_CTX_new',
    'EVP_MD_CTX_reset',
    'EVP_PKEY_eq',
    'EVP_PKEY_get0_EC_KEY',
    'EVP_PKEY_get0_RSA',
    'EVP_PKEY_new_raw_private_key',
    'OPENSSL_cleanup',
    'OPENSSL_init_crypto',
    'OPENSSL_init_ssl',
    'RSA_set0_key',
    'SSL_CTX_set1_cert_store',
    'SSL_CTX_up_ref',
    'SSL_peek_ex',
    'SSL_read_ex',
    'SSL_write_ex',
    'TLS_client_method',
    'TLS_server_method',
    'X509_STORE_up_ref',
]
    config.set10(
        'HAVE_' + fn.to_upper(),
        cc.has_function(fn, dependencies: [crypto_dep, ssl_dep]),
    )
endforeach

## libuv
uv_dep = dependency('libuv', version: '>=1.34.0')
if uv_dep.version().version_compare('<1.40.0')
    warn('libuv version 1.40.0 or greater is highly recommended')
endif

foreach sym : [
    'UV_UDP_LINUX_RECVERR',
    'UV_UDP_MMSG_CHUNK',
    'UV_UDP_MMSG_FREE',
]
    if cc.has_header_symbol('uv.h', sym, dependencies: uv_dep)
        config.set(f'HAVE_DECL_@sym@', 1)
    endif
endforeach

if cc.has_members('struct msghdr', '__pad1', '__pad2', prefix: '#include <sys/socket.h>')
    message('likely non-glibc on linux, disabling recvmmsg')
    config.set('HAVE_DECL_UV_UDP_RECVMMSG', 0)
else
    if cc.has_header_symbol('uv.h', 'UV_UDP_RECVMMSG')
        config.set('HAVE_DECL_UV_UDP_RECVMMSG', 1)
    endif
endif

## userspace-rcu
urcu_dep = [dependency('liburcu-cds', version: '>=0.10.0')]
rcu_flavor = get_option('rcu-flavor')
if rcu_flavor == 'membarrier'
    config.set('RCU_MEMBARRIER', true)
    urcu_dep += dependency('liburcu', version: '>=0.10.0')
elif not developer_mode
    error('Changing Userspace-RCU flavor is allowed only in development mode')
elif rcu_flavor == 'bp'
    config.set('RCU_BP', true)
    urcu_dep += dependency('liburcu-bp', version: '>=0.10.0')
elif rcu_flavor == 'mb'
    config.set('RCU_MB', true)
    urcu_dep += dependency('liburcu-mb', version: '>=0.10.0')
elif rcu_flavor == 'qsbr'
    config.set('RCU_QSBR', true)
    urcu_dep += dependency('liburcu-qsbr', version: '>=0.10.0')
endif

# liburcu << v0.13.0 didn't add -lurcu-common and some toolchains would
# not add it automatically - we need to add it explicitly in such case.

if urcu_dep[1].version().version_compare('<0.13.0')
    urcu_dep += cc.find_library('liburcu-common')
endif

urcu_inline_test = '''
#define URCU_INLINE_SMALL_FUNCTIONS 1
#include <urcu.h>
int main(void) {
    void *a = malloc(1);
    void *b = rcu_dereference(a);

    return b != NULL;
}
'''

config.set_quoted('RCU_FLAVOR', rcu_flavor)
config.set_quoted('RCU_VERSION', urcu_dep[0].version())

if cc.compiles(urcu_inline_test, dependencies: urcu_dep)
    config.set('URCU_INLINE_SMALL_FUNCTIONS', 1)
endif

## jemalloc
jemalloc_dep = null_dep
if cc.has_header('malloc_np.h')
    config.set('HAVE_MALLOC_NP_H', 1)
elif get_option('jemalloc').allowed()
    jemalloc_dep = dependency('jemalloc', required: get_option('jemalloc').enabled())
    if jemalloc_dep.found()
        config.set('HAVE_JEMALLOC', 1)
    endif
endif

## dnstap
fstrm_dep = null_dep
proto_dep = null_dep
if get_option('dnstap').allowed()
    protoc = find_program('protoc', required: get_option('dnstap').enabled())

    fstrm_dep = dependency('libfstrm', required: get_option('dnstap').enabled())
    proto_dep = dependency('libprotobuf-c', required: get_option('dnstap').enabled())

    if protoc.found() and fstrm_dep.found() and proto_dep.found()
        config.set('HAVE_DNSTAP', 1)
    endif
endif

## json
json_c_dep = null_dep
if get_option('stats-json').allowed()
    json_c_dep = dependency(
        'json-c',
        version: '>=0.11',
        required: get_option('stats-json').enabled(),
    )

    if json_c_dep.found()
        config.set('HAVE_JSON_C', 1)
    endif
endif

## xml
xml2_dep = null_dep
stats_xml_opt = get_option('stats-xml')
if stats_xml_opt.allowed()
    xml2_dep = dependency('libxml-2.0', version: '>=2.6.0', required: stats_xml_opt.enabled())
    if xml2_dep.found()
        config.set('HAVE_LIBXML2', 1)
    endif
endif

nghttp2_dep = null_dep
if get_option('doh').allowed()
    nghttp2_dep = dependency(
        'libnghttp2',
        version: '>=1.6.0',
        required: get_option('doh').enabled(),
    )
    if nghttp2_dep.found()
        config.set('HAVE_LIBNGHTTP2', 1)
    endif
endif

maxminddb_dep = null_dep
if get_option('geoip').allowed()
    maxminddb_dep = dependency('libmaxminddb', required: get_option('geoip').enabled())
    if maxminddb_dep.found()
        config.set('HAVE_GEOIP2', 1)
        config.set_quoted('MAXMINDDB_PREFIX', maxminddb_dep.get_variable('prefix'))
    endif
endif

# GSSAPI

krb5_dep = null_dep
gssapi_dep = null_dep
if get_option('gssapi').allowed()
    krb5_config = find_program(get_option('krb5-config'), required: get_option('gssapi').enabled())
    if krb5_config.found()
        gssapi_dep = declare_dependency(
            compile_args: run_command(krb5_config, '--cflags', 'gssapi', check: true).stdout().split(),
            link_args: run_command(krb5_config, '--libs', 'gssapi', check: true).stdout().split(),
        )

        gss_header = '#error "neither gssapi/gssapi.h nor gssapi.h found"'

        if cc.has_header('gssapi/gssapi.h', dependencies: gssapi_dep)
            gss_header = '#include <gssapi/gssapi.h>'
            config.set('HAVE_GSSAPI_GSSAPI_H', 1)
        elif cc.has_header('gssapi.h', dependencies: gssapi_dep)
            gss_header = '#include <gssapi.h>'
            config.set('HAVE_GSSAPI_H', 1)
        else
            error('neither gssapi/gssapi.h nor gssapi.h found')
        endif

        if not cc.has_function('gss_acquire_cred', dependencies: gssapi_dep)
            error('GSSAPI does not work')
        endif

        if cc.has_header('gssapi/gssapi_krb5.h', dependencies: gssapi_dep)
            config.set('HAVE_GSSAPI_GSSAPI_KRB5_H', 1)
        elif cc.has_header('gssapi_krb5.h', dependencies: gssapi_dep)
            config.set('HAVE_GSSAPI_KRB5_H', 1)
        else
            error('neither gssapi/gssapi_krb5.h nor gssapi_krb5.h found')
        endif

        krb5_dep = declare_dependency(
            compile_args: run_command(krb5_config, '--cflags', 'krb5', check: true).stdout().split(),
            link_args: run_command(krb5_config, '--libs', 'krb5', check: true).stdout().split(),
        )

        if cc.has_header('krb5/krb5.h', dependencies: krb5_dep)
            config.set('HAVE_KRB5_KRB5_H', 1)
        elif cc.has_header('krb5.h', dependencies: krb5_dep)
            config.set('HAVE_KRB5_H', 1)
        else
            error('neither krb5/krb5.h nor krb5 found')
        endif

        if not cc.has_function('krb5_init_context', dependencies: krb5_dep)
            error('KRB5 does not work')
        endif

        config.set('HAVE_GSSAPI', 1)
    endif
endif

idn2_dep = null_dep
if get_option('idn').allowed()
    idn2_dep = dependency('libidn2', required: get_option('idn').enabled())
    if idn2_dep.found()
        config.set('HAVE_LIBIDN2', 1)
    endif
endif

lmdb_dep = null_dep
if get_option('lmdb').allowed()
    lmdb_dep = dependency('lmdb', required: get_option('lmdb').enabled())
    if lmdb_dep.found()
        config.set('HAVE_LMDB', 1)
    endif
endif

zlib_dep = null_dep
if get_option('zlib').allowed()
    zlib_dep = dependency('zlib', required: get_option('zlib').enabled())
    if zlib_dep.found()
        config.set('HAVE_ZLIB', 1)
    endif
endif

cmocka_dep = null_dep
if get_option('cmocka').enabled()
    cmocka_dep = dependency('cmocka', version: '>=1.1.3')
    config.set('HAVE_CMOCKA', 1)
endif

## Leak detection in external libraries
config.set10('ENABLE_LEAK_DETECTION', get_option('leak-detection').enabled())

### Finalize configuration
configure_file(output: 'config.h', configuration: config)

add_project_arguments(
    ['-include', meson.project_build_root() / 'config.h'],
    language: 'c',
)

### DTrace
dtrace = find_program('dtrace', meson.project_source_root() / 'util' / 'dtrace.sh')
if build_machine.system() == 'darwin'
    dtrace = find_program(meson.project_source_root() / 'util' / 'dtrace.sh')
endif

dtrace_header = generator(
    dtrace,
    output: '@BASENAME@.h',
    arguments: ['-s', '@INPUT@', '-h', '-o', '@OUTPUT@'],
)

dtrace_object = generator(
    dtrace,
    output: '@BASENAME@.o',
    arguments: ['-s', '@INPUT@', '-G', '-o', '@OUTPUT@'],
)

## Libraries/Binaries
libisc_src = []
libisc_inc = []
libisc_obj = []
libisc_inc_p = []

libisccc_src = []
libisccc_inc = []

libisccfg_src = []
libisccfg_inc = []

libdns_src = []
libdns_obj = []
libdns_inc = []
libdns_inc_p = []
libdns_gen_headers = []

libns_src = []
libns_obj = []
libns_inc = []

arpaname_src = []
delv_src = []
dig_src = []
dnssec_cds_src = []
dnssec_dsfromkey_src = []
dnssec_importkey_src = []
dnssec_keyfromlabel_src = []
dnssec_keygen_src = []
dnssec_ksr_src = []
dnssec_revoke_src = []
dnssec_settime_src = []
dnssec_signzone_src = []
dnssec_verify_src = []
dnstap_read_src = []
mdig_src = []
named_checkconf_src = []
named_checkzone_src = []
named_journalprint_src = []
named_nzd2nzf_src = []
nsec3hash_src = []
nslookup_src = []
nsupdate_src = []
rndc_src = []

confgen_inc = []
tsig_keygen_src = []
rndc_confgen_src = []

named_src = []
named_inc = []

libtest_src = []
libtest_inc = []

subdir('bin')
subdir('lib')

bind_keys = custom_target(
    'bind-keys',
    output: 'bind.keys.h',
    depend_files: files('util' / 'bindkeys.pl', 'bind.keys'),
    capture: true,
    command: [
        perl,
        '@CURRENT_SOURCE_DIR@' / 'util' / 'bindkeys.pl',
        '@CURRENT_SOURCE_DIR@' / 'bind.keys',
    ],
)

delv_src += bind_keys
named_src += bind_keys

libisc = shared_library(
    'isc',
    libisc_src,
    objects: libisc_obj,
    include_directories: [libisc_inc, libisc_inc_p],
    install: true,
    dependencies: [
        crypto_dep,
        m_dep,
        ssl_dep,
        thread_dep,
        urcu_dep,
        uv_dep,

        jemalloc_dep,
        json_c_dep,
        nghttp2_dep,
        xml2_dep,
        zlib_dep,
    ],
)

libisc_dep = declare_dependency(
    link_with: libisc,
    include_directories: libisc_inc,
    dependencies: [
        crypto_dep,
        m_dep,
        ssl_dep,
        thread_dep,
        urcu_dep,
        uv_dep,

        jemalloc_dep,
        json_c_dep,
        nghttp2_dep,
        xml2_dep,
        zlib_dep,
    ],
)

libdns = shared_library(
    'dns',
    libdns_src + libdns_gen_headers,
    include_directories: libdns_inc,
    objects: libdns_obj,
    install: true,
    dependencies: [
        libisc_dep,

        crypto_dep,
        ssl_dep,
        thread_dep,
        urcu_dep,
        uv_dep,

        fstrm_dep,
        gssapi_dep,
        jemalloc_dep,
        json_c_dep,
        krb5_dep,
        lmdb_dep,
        maxminddb_dep,
        proto_dep,
        xml2_dep,
    ],
)

libdns_dep = declare_dependency(
    link_with: libdns,
    include_directories: libdns_inc,
)

libisccc = shared_library(
    'isccc',
    libisccc_src,
    include_directories: libisccc_inc,
    install: true,
    dependencies: [
        libisc_dep,
        libdns_dep,

        thread_dep,
        uv_dep,
    ],
)

libisccc_dep = declare_dependency(
    link_with: libisccc,
    include_directories: libisccc_inc,
)

libns = shared_library(
    'ns',
    libns_src,
    objects: libns_obj,
    include_directories: libns_inc,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,

        urcu_dep,
        uv_dep,

        jemalloc_dep,
    ],
)

libns_dep = declare_dependency(
    link_with: libns,
    include_directories: libns_inc,
)

libisccfg = shared_library(
    'isccfg',
    libisccfg_src,
    include_directories: libisccfg_inc,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libns_dep,

        fstrm_dep,
    ],
)

libisccfg_dep = declare_dependency(
    link_with: libisccfg,
    include_directories: libisccfg_inc,
)

executable(
    'dnssec-cds',
    dnssec_cds_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        urcu_dep,

        jemalloc_dep,
    ],
)

executable(
    'dnssec-dsfromkey',
    dnssec_dsfromkey_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        urcu_dep,

        jemalloc_dep,
    ],
)

executable(
    'dnssec-importkey',
    dnssec_importkey_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        jemalloc_dep,
    ],
)

executable(
    'dnssec-keyfromlabel',
    dnssec_keyfromlabel_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        jemalloc_dep,
    ],
)

executable(
    'dnssec-keygen',
    dnssec_keygen_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        ssl_dep,
        crypto_dep,

        jemalloc_dep,
    ],
)

executable(
    'dnssec-ksr',
    dnssec_ksr_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        jemalloc_dep,
    ],
)

executable(
    'dnssec-revoke',
    dnssec_revoke_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        jemalloc_dep,
    ],
)

executable(
    'dnssec-settime',
    dnssec_settime_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        jemalloc_dep,
    ],
)

executable(
    'dnssec-signzone',
    dnssec_signzone_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        ssl_dep,
        crypto_dep,

        jemalloc_dep,
    ],
)

executable(
    'dnssec-verify',
    dnssec_verify_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        jemalloc_dep,
    ],
)

executable(
    'delv',
    delv_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
        libns_dep,

        jemalloc_dep,
    ],
)

executable(
    'dig',
    dig_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        nghttp2_dep,
        idn2_dep,
    ],
)

executable(
    'named-checkconf',
    named_checkconf_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
        libns_dep,

        jemalloc_dep,
    ],
)

executable(
    'named-checkzone',
    named_checkzone_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
        libns_dep,

        jemalloc_dep,
    ],
)

executable(
    'named',
    named_src,
    install: true,
    include_directories: named_inc,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccc_dep,
        libisccfg_dep,
        libns_dep,

        uv_dep,
        crypto_dep,
        ssl_dep,
        thread_dep,

        fstrm_dep,
        jemalloc_dep,
        json_c_dep,
        lmdb_dep,
        maxminddb_dep,
        nghttp2_dep,
        proto_dep,
        xml2_dep,
        zlib_dep,
    ],
)

executable(
    'rndc',
    rndc_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccc_dep,
        libisccfg_dep,
    ],
)

executable(
    'nslookup',
    nslookup_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        idn2_dep,
    ],
)

executable(
    'nsupdate',
    nsupdate_src,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        krb5_dep,
    ],
)

executable(
    'rndc-confgen',
    rndc_confgen_src,
    install: true,
    include_directories: confgen_inc,
    dependencies: [
        libdns_dep,
        libisc_dep,

        jemalloc_dep,
    ],
)

executable(
    'tsig-keygen',
    tsig_keygen_src,
    install: true,
    include_directories: confgen_inc,
    dependencies: [
        libdns_dep,
        libisc_dep,

        jemalloc_dep,
    ],
)

### Tests
if cmocka_dep.found()
    subdir('tests')
endif

### Summary
summary(
    {
        'Compiler': cc.get_id(),
        'Linker': cc.get_linker_id(),
    },
    section: 'Toolchain',
)

summary(
    {
        'libuv': uv_dep.version(),
        'OpenSSL': ssl_dep.version(),
        'Userspace RCU': urcu_dep[0].version(),
        'RCU Flavor': rcu_flavor,
    },
    section: 'Required Dependencies',
)

summary(
    {
        'cmocka': cmocka_dep.version(),
        'fstrm': fstrm_dep.version(),
        'jemalloc': jemalloc_dep.version(),
        'json-c': json_c_dep.version(),
        'libidn2': idn2_dep.version(),
        'libxml2': xml2_dep.version(),
        'LMDB': lmdb_dep.version(),
        'MaxMindDB': maxminddb_dep.version(),
        'nghttp2': nghttp2_dep.version(),
        'protobuf-c': proto_dep.version(),
        'zlib': zlib_dep.version(),
    },
    section: 'Optional Dependencies',
)

### Warn about fragmentation
if not (config.has('HAVE_JEMALLOC') or config.has('HAVE_MALLOC_NP_H'))
    warning(
        '''
    +------------------------------------------+
    |             ==== WARNING ====            |
    |                                          |
    | This is NOT a recommended configuration. |
    | Using the system memory allocator causes |
    | reduced performance and increased memory |
    | fragmentation. Installing the jemalloc   |
    | memory allocator (version >= 4.0.0) is   |
    | strongly recommended.                    |
    +------------------------------------------+''',
    )
endif
