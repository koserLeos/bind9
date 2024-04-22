#!/usr/bin/python
from cffi import FFI

ffibuilder = FFI()

# cdef() expects a single string declaring the C types, functions and
# globals needed to use the shared object. It must be in valid C syntax.
ffibuilder.cdef(
    """
typedef int... isc_result_t;
typedef ... isc_mem_t;

typedef struct { ...; } dns_compress_t;
typedef int... dns_decompress_t;

typedef struct { ...; } dns_name_t;
typedef struct { ...; } dns_fixedname_t;

void
isc__mem_create(isc_mem_t **);

void
isc_mem_attach(isc_mem_t *, isc_mem_t **);

isc_result_t
dns_name_fromstring(dns_name_t *target, const char *src,
		    const dns_name_t *origin, unsigned int options,
		    isc_mem_t *mctx);

static inline void
dns_name_init(dns_name_t *name, unsigned char *offsets);

dns_name_t *
dns_fixedname_initname(dns_fixedname_t *fixed);

uint32_t
dns_name_hash(const dns_name_t *name);
"""
)

# set_source() gives the name of the python extension module to
# produce, and some C source code as a string.  This C code needs
# to make the declarated functions, types and globals available,
# so it is often just the "#include".
ffibuilder.set_source(
    "_pi_cffi",
    """
     #include "isc/mem.h"
     #include "dns/name.h"
     #include "dns/compress.h"
     #include "dns/fixedname.h"
""",
    libraries=["dns"],
    include_dirs=["lib/dns/include", "lib/isc/include"],
)  # library name, for the linker

if __name__ == "__main__":
    ffibuilder.compile(
        verbose=True,
    )
