import GnuPGInterface
import distutils.core

long_description = """
GnuPGInterface is a Python module to interface with GnuPG.
It concentrates on interacting with GnuPG via filehandles,
providing access to control GnuPG via versatile and extensible means.

This module is based on GnuPG::Interface, a Perl module by the same author.
"""

distutils.core.setup( name = 'GnuPGInterface',
                      version = GnuPGInterface.__version__,
                      description = 'GnuPG interactions with file handles',
		      long_description = long_description,
                      author = 'Frank J. Tobin',
                      author_email = 'ftobin@neverending.org',
		      license = 'LGPL',
		      platforms = 'POSIX',
		      keywords = 'GnuPG gpg',
                      url = 'http://py-gnupg.sourceforge.net/',
                      py_modules = [ 'GnuPGInterface' ]
                      )
