libisc_inc_p += include_directories('.')
libisc_src += files(
    'netmgr.c',
    'proxystream.c',
    'proxyudp.c',
    'socket.c',
    'streamdns.c',
    'tcp.c',
    'timer.c',
    'tlsstream.c',
    'udp.c',
)

if config.has('HAVE_LIBNGHTTP2')
    libisc_src += files('http.c')
endif
