import distutils.core

distutils.core.setup( name = 'GnuPGInterface',
                      version = '0.1.0',
                      description = 'GnuPG interactions with file handles',
		      long_description = """This module allows fairly
		      low-level IPC communication with GnuPG through
		      filehandles.  This module does not use GPGME,
		      which has a higher-level API.""",
                      author = 'Frank J. Tobin',
                      author_email = 'ftobin@users.sourceforge.net',
		      licence = 'GPL',
		      platforms = 'POSIX',
		      keywords = 'GnuPG gpg',
                      url = 'http://py-gnupg.sourceforge.net/',
                      py_modules = [ 'GnuPGInterface' ]
                      )
