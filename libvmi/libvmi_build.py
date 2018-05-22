#!/usr/bin/env python3


import os

import pkgconfig
from cffi import FFI


# glib_cdef.h must be first
CDEF_HEADERS = [
    'glib_cdef.h',
    'libvmi_cdef.h',
    'events_cdef.h',
    'slat_cdef.h',
    'libvmi_extra_cdef.h',
]


def get_cflags(package):
    includes = pkgconfig.cflags(package)
    if not includes:
        raise RuntimeError('Unable to find pkgconfig cflags'
                           ' for {}'.format(package))
    includes = includes.replace('-I', '').split(' ')
    return includes


def get_libs(package):
    libs = pkgconfig.libs(package)
    if not libs:
        raise RuntimeError('Unable to find pkgconfig libs'
                           ' for {}'.format(package))
    libs = libs.replace('-l', '').split(' ')
    return libs


# glib cflags and libs
glib_includes = get_cflags('glib-2.0')
glib_libs = get_libs('glib-2.0')

# get libvmi libs
libvmi_libs = get_libs('libvmi')

includes = []
includes.extend(glib_includes)

libs = []
libs.extend(libvmi_libs)
libs.extend(glib_libs)

ffi = FFI()
# set source
ffi.set_source("_libvmi",
               """
               #include <libvmi/libvmi.h>
               #include <libvmi/events.h>
               #include <libvmi/slat.h>
               #include <libvmi/libvmi_extra.h>
               """,
               libraries=libs, include_dirs=includes)


script_dir = os.path.dirname(os.path.realpath(__file__))
# we read our C definitions from an external file
# easier to maintain + C syntax highlighting
cdef_content = ""
for cdef_path in CDEF_HEADERS:
    with open(os.path.join(script_dir, cdef_path)) as cdef_file:
        cdef_content += cdef_file.read()
        # add newline for next file
        cdef_content += '\n'
ffi.cdef(cdef_content)


if __name__ == "__main__":
    ffi.compile(verbose=True)
