#!/usr/bin/env python3
from setuptools import setup

setup(
    name='GemVM',
    version='0.10.1',
    description='Simple control interface for running a local VM with QEMU',
    author='Gemini Data Processing Software Group',
    author_email='sus_inquiries@gemini.edu',
    url='http://www.gemini.edu',
    maintainer='Science User Support Department',
    packages=['gemvm'],
    entry_points={
        'console_scripts' : [
            'gemvm = gemvm.gemvm:main',
            'gemvm-config = gemvm.config:main'
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console :: Curses',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Topic :: System :: Emulators',
        'Topic :: Utilities',
    ],
    license_files=('LICENSE', 'COPYING')
)
