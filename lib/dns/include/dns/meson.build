libdns_gen_headers += custom_target(
    'dns-header-enumtype',
    output: 'enumtype.h',
    depend_files: dns_header_depfiles,
    capture: true,
    command: [dns_header_gen, '-s', '@CURRENT_SOURCE_DIR@' / '..' / '..', '-t'],
)

libdns_gen_headers += custom_target(
    'dns-header-enumclass',
    output: 'enumclass.h',
    depend_files: dns_header_depfiles,
    capture: true,
    command: [dns_header_gen, '-s', '@CURRENT_SOURCE_DIR@' / '..' / '..', '-c'],
)

libdns_gen_headers += custom_target(
    'dns-header-rdatastruct',
    output: 'rdatastruct.h',
    depend_files: dns_header_depfiles,
    capture: true,
    command: [
        dns_header_gen,
        '-s', '@CURRENT_SOURCE_DIR@' / '..' / '..',
        '-i',
        '-P', '@CURRENT_SOURCE_DIR@' / '..' / '..' / 'rdata' / 'rdatastructpre.h',
        '-S', '@CURRENT_SOURCE_DIR@' / '..' / '..' / 'rdata' / 'rdatastructsuf.h',
    ],
)
