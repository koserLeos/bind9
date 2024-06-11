foreach t : [
    'resconf',
]
    test_bin = executable(
        f'@t@_test',
        [f'@t@_test.c'],
        c_args: ['-DTESTS_DIR="@0@"'.format(meson.current_source_dir())],
        dependencies: [
            libisc_dep,
            libdns_dep,
            libtest_dep,

            cmocka_dep,
            jemalloc_dep,
        ],
    )

    test(t, test_bin, suite: 'irs', workdir: meson.current_source_dir())
endforeach
