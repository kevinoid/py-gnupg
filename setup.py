import distutils.core

distutils.core.setup( name = 'GnuPGInterface',
                      version = '0.1.0',
                      description = 'GnuPG interactions via file handles',
                      author = 'Frank J. Tobin',
                      author_email = 'ftobin@users.sourceforge.net',
                      url = 'http://py-gnupg.sourceforge.net/',
                      py_modules = [ 'GnuPGInterface' ]
                      ),
