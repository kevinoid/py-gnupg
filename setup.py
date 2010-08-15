#!/usr/bin/env python

import GnuPGInterface
import distutils.core

long_description = """
GnuPGInterface is a Python module to interface with GnuPG.
It concentrates on interacting with GnuPG via filehandles,
providing access to control GnuPG via versatile and extensible means.

This module is based on GnuPG::Interface, a Perl module by the same author.
"""

classifiers = [
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)',
    'Operating System :: Microsoft :: Windows :: Windows NT/2000',
    'Operating System :: POSIX',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 3',
    'Topic :: Security :: Cryptography',
    'Topic :: Software Development :: Libraries',
]

distutils.core.setup( name = 'GnuPGInterface',
                      version = GnuPGInterface.__version__,
                      description = 'GnuPG interactions with file handles',
		      long_description = long_description,
                      author = 'Frank J. Tobin',
                      author_email = 'ftobin@neverending.org',
		      license = 'GNU LGPL',
		      platforms = ['POSIX', 'Windows'],
		      classifiers = classifiers,
		      keywords = 'GnuPG gpg',
                      url = 'http://py-gnupg.sourceforge.net/',
                      py_modules = [ 'GnuPGInterface' ]
                      )
