"""Interface to GNU Privacy Guard (GnuPG)

by Frank Tobin, ftobin@uiuc.edu
"""

# $Id$

import os
import sys
import types
import fcntl, FCNTL

__author__  = "Frank J. Tobin ftobin@uiuc.edu"
__version__ = "0.1.0"

# "standard" filehandles attached to processes
_stds = [ 'stdin', 'stdout', 'stderr' ]

# the permissions each type of fh needs to be opened with
_fd_modes = { 'stdin': 'w',
              'stdout': 'r',
              'stderr': 'r',
              'passphrase': 'w',
              'command': 'w',
              'logger': 'r',
              'status':  'r'
              }

# correlation between handle names and the arguments we'll pass
_fd_options = { 'passphrase': '--passphrase-fd',
                'logger': '--logger-fd',
                'status': '--status-fd',
                'command': '--command-fd' }

# constants
_parent = 0
_child = 1
_direct = 2

class GnuPGInterface:
    """Class representing a GnuPG interface.
    
    Example:

    >>> import os
    >>> import GnuPGInterface
    >>> 
    >>> text = "Three blind mice"
    >>> passphrase = "This is the passphrase"
    >>> 
    >>> gnupg = GnuPGInterface.GnuPGInterface()
    >>> gnupg.options.armor = 1
    >>> gnupg.options.meta_interactive = 0
    >>> gnupg.options.extra_args.append('--no-secmem-warning')
    >>> 
    >>> # Normally we might specify something in
    >>> # gnupg.options.recipients(), but since we're doing
    >>> # symmetric-only encryption, it's not needed.
    >>> # If you are doing standard, public-key encryption
    >>> # you will need to specify recipients.
    >>> 
    >>> # First we'll encrypt the text input symmetrically
    >>> p1 = gnupg.run(['--symmetric'], stdin=1, stdout=1, passphrase=1)
    >>> p1.handles['passphrase'].write(passphrase)
    >>> p1.handles['passphrase'].close()
    >>> p1.handles['stdin'].write(text)
    >>> p1.handles['stdin'].close()
    >>> out1 = p1.handles['stdout'].read()
    >>> p1.handles['stdout'].close()
    >>> # Checking to make sure GnuPG exited successfully
    >>> e = os.waitpid(p1.pid, 0)[1]
    >>> if e != 0:
    ...     raise IOError, "GnuPG exited non-zero, with status" + repr(e)
    >>> 
    >>> # Now we'll decrypt it, using the convience way to get the
    >>> # passphrase to GnuPG
    >>> gnupg.passphrase = passphrase
    >>> p2 = gnupg.run(['--decrypt'], stdin=1, stdout=1 )
    >>> p2.handles['stdin'].write(out1)
    >>> p2.handles['stdin'].close()
    >>> out2 = p2.handles['stdout'].read()
    >>> p2.handles['stdout'].close()
    >>> e = os.waitpid(p2.pid, 0)[1]
    >>> if e != 0:
    ...     raise IOError, "GnuPG exited non-zero, with status" + repr(e)
    >>> 
    >>> # Our decrypted plaintext:
    >>> out2
    'Three blind mice'
    >>>
    >>> # ...and it's the same as what we orignally encrypted
    >>> text == out2
    1
    
    Instance attributes of a GnuPGInterface object are:
    
    * call -- string to call GnuPG with.  Defaults to "gpg"

    * passphrase -- Since it is a common operation
      to pass in a passphrase to GnuPG,
      and working with the passphrase filehandle mechanism directly
      can be mundane, if set, the passphrase attribute
      works in a special manner.  If the passphrase attribute is set, 
      and no passphrase file object is sent in to run(),
      then GnuPGInterface will take care of sending the passphrase to GnuPG,
      instead of having the user sent it in manually.
      
    * options -- Object of type GnuPGInterface.Options. 
      Attribute-setting in options determines
      the command-line options used when calling GnuPG.
    """

    def __init__(self):
        self.call = 'gpg'
        self.passphrase = None
        self.options = Options()
    
    def run(self, gnupg_commands, args=None, **fh_requests):
	"""Calls GnuPG with the list of string commands gnupg_commands,
	complete with prefixing dashes.
	For example, gnupg_commands could be
	'["--sign", "--encrypt"]'
	Returns a GnuPGInterface.Process object.
	
	args is an optional list of GnuPG command arguments (not options),
	such as keyID's to export, filenames to process, etc.
	
	fh_request's are named parameters corresponding to filehandle
	names to be connected with the GnuPG process.  Valid names are:
	stdin, stdout, stderr, passphrase, command, logger, and status.
	
	The purpose of each filehandle is described in the GnuPG documentation.
	
	Valid values for each filehandle name are either
	non-FileObject booleans, or FileObjects.
	If not set, fh_request's which are a std* are defaulted
	to the running process' version of handle.
	Otherwise, that type of handle is simply not used when calling GnuPG>
	For example, if you do not care about getting data from GnuPG's
	status filehandle, simply do not specify it.
	
	If a filehandle name has a non-FileObject value which is true,
	after run() returns, the returned GnuPGInterface.Process</a>
	object will have an attribute of handles,
	which is a mapping from the handle name (such as stdin or command)
	to the respective FileObject  connected to the GnuPGInterface object.
	For instance, if the call was
	'process = gnupg.run(["--decrypt"], stdin=1)',
	after run returns 'process.handles["stdin"]'
	is a file object connected to GnuPG's standard input,
	and can be written to.
	
	If a non-FileObject boolean is sent in and is false, it is simply
	as if it was never specified in the call.
	
	If a FileObject is given, then the GnuPG process will read/write
	directly to/from that object.  This is useful if you want
	GnuPG to read/write to/from an existing file.
	For instance:

	f = open("encrypted.gpg")
	gnupg.run(["--decrypt"], stdin= f)
        """
        
	if args == None: args = []
	
        for std in _stds: fh_requests.setdefault( std, getattr(sys, std) )
        handle_passphrase = 0
        
        if self.passphrase != None and not fh_requests.has_key( 'passphrase' ):
            handle_passphrase = 1
            fh_requests['passphrase'] = 1

        process = self._attach_fork_exec(gnupg_commands, args, fh_requests)

        if handle_passphrase:
            passphrase_fh = process.handles['passphrase']
            passphrase_fh.write( self.passphrase )
            passphrase_fh.close()
            del process.handles['passphrase']
        
        return process
    
    
    def _attach_fork_exec(self, gnupg_commands, args, fh_requests):
        """This is like run(), but without the passphrase-helping
	(note that run() calls this)."""
	
	process = Process()
        
        for k, h in fh_requests.items():
            if not _fd_modes.has_key(k):
                raise KeyError, "unrecognized filehandle name '%s'; must be one of %s" % ( k, _fd_modes.keys() )
            
            if type(h) != types.FileType and h:
                # the user wants us to give them a fh
                process._pipes[k] = os.pipe() + ( 0, )
            
            elif type(h) == types.FileType:
                # the user wants us to connect the handle they gave us
                # gave us to the specified handle
                process._pipes[k] = ( h.fileno(), h.fileno(), 1 )

            # Else the user doesn't want that type of handle.
            # Note that all std fh's that aren't specified
            # are defined as the current process' handle of that name
        
        process.pid = os.fork()
        
        if process.pid == 0: self._as_child(process, gnupg_commands, args)
        return self._as_parent(process)
    
    
    def _as_parent(self, process):
        """Stuff run after forking in parent"""
        for p in process._pipes.values():
            if not p[_direct]: os.close( p[_child] )
            
        for k, p in process._pipes.items():
            if not p[_direct]: process.handles[k] = os.fdopen( p[_parent], _fd_modes[k] )

        del process._pipes

        return process


    def _as_child(self, process, gnupg_commands, args):
        """Stuff run after forking in child"""
        # child
        for std in _stds:
            p = process._pipes[std]
            if not p[_direct]:
                os.dup2( p[_child], getattr( sys, "__" + std + "__" ).fileno() )
	
        for k, p in process._pipes.items():
            if p[_direct] and k not in _stds:
                # we want the fh to stay open after execing
                fcntl.fcntl( p[_child], FCNTL.F_SETFD, 0 )
        
        fd_args = []
        
        # set command-line options for non-standard fds
        for k, p in process._pipes.items():
            if k not in _stds: fd_args.extend( [ _fd_options[k], `p[_child]` ] )
            if not p[_direct]: os.close( p[_parent] )
            
        command = [ self.call ] + fd_args + self.options.get_args() + gnupg_commands + args
        os.execvp( command[0], command )


	def _get_full_args(self, gnupg_commands, args, fd_args):
	    [ self.call ] + fd_args + self.options.get_args() \
	      + gnupg_commands + args
        

class Options:
    """Objects of this class encompass options passed to GnuPG.
    Responsible for determining command-line arguments which
    are based on options.  It can be said that a GnuPGInterface
    object has-a GnuPGInterface.Options object in its options attribute.

    Attributes which correlate directly to GnuPG options:
    
    Each option here defaults to false or None, and is described in
    GnuPG documentation.
    
    Booleans
    
      * armor
      * no_greeting
      * no_verbose
      * quiet
      * batch
      * always_trust
      * rfc1991
      * openpgp
      * force_v3_sigs
      * no_options
      * textmode
    
    Strings
    
      * homedir
      * default_key
      * comment
      * compress_algo
      * options
    
    Lists
    
      * recipients
      * encrypt_to
    
    Meta options
    
    Meta options are options provided by this module that do
    not correlate directly to any GnuPG option by name,
    but are rather bundle of options used to accomplish
    a specific goal, such as obtaining compatibility with PGP 5.
    The actual arguments each of these reflects may change with time.  Each
    defaults to false unless otherwise specified.
    
    meta_pgp_5_compatible -- If true, arguments are generated to try
    to be compatible with PGP 5.x.
      
    meta_pgp_2_compatible -- If true, arguments are generated to try
    to be compatible with PGP 2.x.
    
    meta_interactive -- If false, arguments are generated to try to
    help the using program use GnuPG in a non-interactive
    environment, such as CGI scripts.  Default is true.
    
    extra_args -- Extra option arguments may be passed in
    via the attribute extra_args, a list.

    >>> import GnuPGInterface
    >>> gnupg = GnuPGInterface.GnuPGInterface()
    >>> gnupg.options.armor = 1
    >>> gnupg.options.recipients = ['Alice', 'Bob']
    >>> gnupg.options.extra_args = ['--no-secmem-warning']
    >>> gnupg.options.get_args()
    ['--armor', '--recipient', 'Alice', '--recipient', 'Bob', '--no-secmem-warning']
    """
    
    def __init__(self):
        # booleans
        self.armor = 0
        self.no_greeting = 0
        self.verbose = 0
        self.no_verbose = 0
        self.quiet = 0
        self.batch = 0
        self.always_trust = 0
        self.rfc1991 = 0
        self.openpgp = 0
        self.force_v3_sigs = 0
        self.no_options = 0
        self.textmode = 0

        # meta-option booleans
        self.meta_pgp_5_compatible = 0
        self.meta_pgp_2_compatible = 0
        self.meta_interactive = 1

        # strings
        self.homedir = None
        self.default_key = None
        self.comment = None
        self.compress_algo = None
        self.options = None

        # lists
        self.encrypt_to = []
        self.recipients = []
        
        # miscellaneous arguments
        self.extra_args = []
    
    def get_args( self ):
	"""Generate a list of GnuPG arguments based upon attributes."""
	
        return self.get_meta_args() + self.get_option_args() + self.extra_args

    def get_option_args( self ):
	"""Generate a list of standard, non-meta or extra arguments"""
        args = []
        if self.homedir != None: args.extend( [ '--homedir', self.homedir ] )
        if self.options != None: args.extend( [ '--options', self.options ] )
        if self.comment != None: args.extend( [ '--comment', self.comment ] )
        if self.compress_algo != None: args.extend( [ '--compress-algo', self.compress_algo ] )
        if self.default_key != None: args.extend( [ '--default-key', self.default_key ] )
        
        if self.no_options: args.append( '--no-options' )
        if self.armor: args.append( '--armor' )
        if self.textmode: args.append( '--textmode' )
        if self.no_greeting: args.append( '--no-greeting' )
        if self.verbose: args.append( '--verbose' )
        if self.no_verbose: args.append( '--no-verbose' )
        if self.quiet: args.append( '--quiet' )
        if self.batch: args.append( '--batch' )
        if self.always_trust: args.append( '--always-trust' )
        if self.force_v3_sigs: args.append( '--force-v3-sigs' )
        if self.rfc1991: args.append( '--rfc1991' )
        if self.openpgp: args.append( '--openpgp' )

        for r in self.recipients: args.extend( [ '--recipient',  r ] )
        for r in self.encrypt_to: args.extend( [ '--encrypt-to', r ] )
        
        return args

    def get_meta_args( self ):
	"""Get a list of generated meta-arguments"""
        args = []

        if self.meta_pgp_5_compatible: args.extend( [ '--compress-algo', '1',
                                                      '--force-v3-sigs'
                                                      ] )
        if self.meta_pgp_2_compatible: args.append( '--rfc1991' )
        if not self.meta_interactive: args.extend( [ '--batch', '--no-tty' ] )

        return args


class Process:
    """# gnupg is a GnuPGInterface.GnuPGInterface object
    process = gnupg.run( [ '--decrypt' ], stdout = 1 )
    out = process.handles['stdout'].read()
    ...
    os.waitpid( process.pid, 0 )
    
    Objects of this class encompass properties of a GnuPG
    process spawned by GnuPGInterface's run()
    
    Data Attributes
    
    handles -- This is a map of filehandle-names to
    the file handles, if any, that were requested via run() and hence
    are connected to the running GnuPG process.  Valid names
    of this map are only those handles that were requested.
      
    pid -- The PID of the spawned GnuPG process.
    Useful to know, since once should call
    os.waitpid() to clean up the process, especially
    if multiple calls are made to run().
    """
    
    def __init__(self):
        self._pipes = {}
        self.handles = {}
        self.pid = None


def _test():
    import doctest, GnuPGInterface
    return doctest.testmod(GnuPGInterface)
    
if __name__ == '__main__':
    _test()
