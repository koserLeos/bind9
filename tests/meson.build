cmocka_dep = dependency('cmocka')

libtest_src += files(
    'libtest/dns.c',
    'libtest/isc.c',
    'libtest/ns.c',
    'libtest/qp.c',
    'ns/netmgr_wrap.c',
)

libtest_inc += include_directories('include')

libtest = shared_library(
    'bindtest',
    libtest_src,
    include_directories: [libtest_inc, libdns_inc_p],
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
        libns_dep,

        urcu_dep,
        uv_dep,

        jemalloc_dep,
    ],
)

libtest_dep = declare_dependency(
    link_with: libtest,
    include_directories: libtest_inc,
)

subdir('irs')
subdir('isccfg')
subdir('dns')
subdir('ns')
subdir('isc')
