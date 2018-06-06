#!/usr/bin/env python3


from setuptools import setup


setup(
    name='libvmi',
    version='3.1',
    description='Python interface to LibVMI',
    setup_requires=["cffi>=1.6.0", "pkgconfig", "pytest-runner"],
    install_requires=["cffi>=1.6.0", "future"],
    tests_require=["pytest", "pytest-pep8", "libvirt-python"],
    cffi_modules=['libvmi/libvmi_build.py:ffi'],
    packages=['libvmi'],
    package_data={
        'libvmi': ['*_cdef.h']
    }
)
