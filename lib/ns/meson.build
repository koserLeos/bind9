libns_src += dtrace_header.process('probes.d')
libns_obj += dtrace_object.process('probes.d')

libns_inc += include_directories('include')
libns_src += files(
    'client.c',
    'hooks.c',
    'interfacemgr.c',
    'listenlist.c',
    'log.c',
    'notify.c',
    'query.c',
    'server.c',
    'sortlist.c',
    'stats.c',
    'update.c',
    'xfrout.c',
)
