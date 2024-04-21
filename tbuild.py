#!/usr/bin/python
from cffi import FFI

ffibuilder = FFI()

# cdef() expects a single string declaring the C types, functions and
# globals needed to use the shared object. It must be in valid C syntax.
ffibuilder.cdef(
    """
typedef ... dns_name;
typedef ... dns_name_t;

static inline void
dns_name_init(dns_name_t *name, unsigned char *offsets);

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
     #include "dns/name.h"   // the C header of the library
""",
    libraries=["dns"],
    include_dirs=["lib/dns/include", "lib/isc/include"],
)  # library name, for the linker

if __name__ == "__main__":
    ffibuilder.compile(
        verbose=True,
    )
