named_src += files(
    'builtin.c',
    'config.c',
    'control.c',
    'controlconf.c',
    'dlz_dlopen_driver.c',
    'fuzz.c',
    'log.c',
    'logconf.c',
    'main.c',
    'os.c',
    'server.c',
    'statschannel.c',
    'tkeyconf.c',
    'transportconf.c',
    'tsigconf.c',
    'zoneconf.c',
)

if config.has('HAVE_GEOIP2')
    named_src += files('geoip.c')
endif

named_src += custom_target(
    'xsl.c',
    input: ['bind9.xsl', 'xsl.sed'],
    output: 'xsl.c',
    capture: true,
    command: [
        find_program('sed'),
        '-f', '@INPUT1@',
        '@INPUT0@',
    ],
)

named_inc += include_directories('include')
