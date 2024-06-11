libdns_src += dtrace_header.process('probes.d')
libdns_obj += dtrace_object.process('probes.d')

libdns_inc_p += include_directories('.')

libdns_inc += include_directories('include')

dns_header_gen = executable(
    'gen',
    files('gen.c'),
    native: true,
)

dns_header_depfiles = []
subdir('rdata')

libdns_src += custom_target(
    'dns-code',
    output: 'code.h',
    depend_files: dns_header_depfiles,
    capture: true,
    command: [dns_header_gen, '-s', '@CURRENT_SOURCE_DIR@'],
)

subdir('include')

if config.has('HAVE_DNSTAP')
    libdns_src += files('dnstap.c')
    libdns_src += custom_target(
        'dnstap-protobuf',
        input: ['dnstap.proto'],
        output: ['dnstap.pb-c.c', 'dnstap.pb-c.h'],
        command: [
            protoc,
            '--proto_path=@CURRENT_SOURCE_DIR@',
            '--c_out=@OUTDIR@',
            '@INPUT@',
        ],
    )
endif

if config.has('HAVE_GEOIP2')
    libdns_src += files('geoip2.c')
endif

if config.has('HAVE_GSSAPI')
    libdns_src += files('gssapi_link.c')
endif

libdns_src += files(
    'acl.c',
    'adb.c',
    'badcache.c',
    'byaddr.c',
    'cache.c',
    'callbacks.c',
    'catz.c',
    'client.c',
    'clientinfo.c',
    'compress.c',
    'db.c',
    'dbiterator.c',
    'diff.c',
    'dispatch.c',
    'dlz.c',
    'dns64.c',
    'dnsrps.c',
    'dnssec.c',
    'ds.c',
    'dst_api.c',
    'dst_parse.c',
    'dyndb.c',
    'ecs.c',
    'fixedname.c',
    'forward.c',
    'gssapictx.c',
    'hmac_link.c',
    'ipkeylist.c',
    'iptable.c',
    'journal.c',
    'kasp.c',
    'key.c',
    'keydata.c',
    'keymgr.c',
    'keystore.c',
    'keytable.c',
    'log.c',
    'master.c',
    'masterdump.c',
    'message.c',
    'name.c',
    'nametree.c',
    'ncache.c',
    'nsec.c',
    'nsec3.c',
    'nta.c',
    'openssl_link.c',
    'openssl_shim.c',
    'opensslecdsa_link.c',
    'openssleddsa_link.c',
    'opensslrsa_link.c',
    'order.c',
    'peer.c',
    'private.c',
    'qp.c',
    'qpcache.c',
    'qpzone.c',
    'rbt-cachedb.c',
    'rbt-zonedb.c',
    'rbt.c',
    'rbtdb.c',
    'rcode.c',
    'rdata.c',
    'rdatalist.c',
    'rdataset.c',
    'rdatasetiter.c',
    'rdataslab.c',
    'remote.c',
    'request.c',
    'resconf.c',
    'resolver.c',
    'result.c',
    'rootns.c',
    'rpz.c',
    'rriterator.c',
    'rrl.c',
    'sdlz.c',
    'soa.c',
    'ssu.c',
    'ssu_external.c',
    'stats.c',
    'time.c',
    'tkey.c',
    'transport.c',
    'tsig.c',
    'ttl.c',
    'update.c',
    'validator.c',
    'view.c',
    'xfrin.c',
    'zone.c',
    'zonekey.c',
    'zoneverify.c',
    'zt.c',
)
