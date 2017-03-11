# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function

from setuptools import setup


description = '''
    txsecrethandshake is a twisted API for building cryptographic network protocols
'''

setup(
    name='txsecrethandshake',
    version='0.0.1',
    description=description,
    long_description=open('README.rst', 'r').read(),
    keywords=['python', 'twisted', 'cryptography', 'capability', 'protocol'],
    install_requires=open('requirements.txt').readlines(),
    # "pip install -e .[dev]" will install development requirements
    extras_require=dict(
        dev=open('requirements-dev.txt').readlines(),
    ),
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Topic :: Security :: Cryptography',
        'Topic :: System :: Networking',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    license="MIT",
    packages=["txsecrethandshake"],
)
