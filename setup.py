#!/usr/bin/env python3

import os
from setuptools import setup


def read_file(filename):
    with open(os.path.join(os.path.dirname(__file__), filename)) as f:
        return f.read()


setup(
    name='libvmi',
    version='3.4',
    description='Python interface to LibVMI',
    long_description=read_file('README.md'),
    long_description_content_type='text/markdown',
    author='Mathieu Tarral',
    author_email='mathieu.tarral@protonmail.com',
    url='https://github.com/libvmi/python',
    setup_requires=["cffi>=1.6.0", "pkgconfig", "pytest-runner"],
    install_requires=["cffi>=1.6.0", "future", "enum34;python_version<'3.4'"],
    tests_require=["pytest", "pytest-pep8", "libvirt-python"],
    cffi_modules=['libvmi/libvmi_build.py:ffi'],
    packages=['libvmi'],
    package_data={
        'libvmi': ['*_cdef.h']
    }
)
