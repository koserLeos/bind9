foreach t : ['listenlist', 'notify', 'plugin', 'query']
    test_bin = executable(
        f'@t@_test',
        [f'@t@_test.c', 'netmgr_wrap.c'],
        build_by_default: false,
        dependencies: [
            libisc_dep,
            libdns_dep,
            libns_dep,
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

    test(t, test_bin, suite: 'ns', workdir: meson.current_source_dir())
endforeach
