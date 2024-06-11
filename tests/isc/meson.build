isc_test = [
    'ascii',
    'async',
    'buffer',
    'counter',
    'crc64',
    'dnsstream_utils',
    'errno',
    'file',
    'hash',
    'hashmap',
    'heap',
    'histo',
    'hmac',
    'ht',
    'job',
    'lex',
    'loop',
    'md',
    'mem',
    'mutex',
    'netaddr',
    'parse',
    'proxyheader',
    'proxystream',
    'proxyudp',
    'quota',
    'radix',
    'random',
    'ratelimiter',
    'regex',
    'result',
    'rwlock',
    'safe',
    'siphash',
    'sockaddr',
    'spinlock',
    'stats',
    'symtab',
    'tcp',
    'tcpdns',
    'time',
    'timer',
    'tls',
    'tlsdns',
    'udp',
    'work',
]

if config.has('HAVE_NGHTTP2')
    isc_tests += 'doh'
endif

foreach t : isc_test
    test_bin = executable(
        f'@t@_test',
        [f'@t@_test.c', 'netmgr_common.c', 'stream_shutdown.c'],
        build_by_default: false,
        dependencies: [
            libisc_dep,
            libtest_dep,

            cmocka_dep,
            uv_dep,
            m_dep,
            ssl_dep,
            crypto_dep,
            urcu_dep,
            nghttp2_dep,
            jemalloc_dep,
        ],
    )

    test(t, test_bin, suite: 'isc', workdir: meson.current_source_dir())
endforeach
