foreach t : [
    'duration',
    'parser',
]
    test_bin = executable(
        f'@t@_test',
        [f'@t@_test.c'],
        dependencies: [
            libisc_dep,
            libisccfg_dep,
            libtest_dep,

            cmocka_dep,
        ],
    )

    test(t, test_bin, suite: 'isccfg', workdir: meson.current_source_dir())
endforeach
