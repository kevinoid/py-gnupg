"""Interface to GNU Privacy Guard (GnuPG).
See class GnuPGInterface and class Options"""

import os
import sys
import types
import fcntl, FCNTL

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
    Attributes of a GnuPGInterface object are:
    
    call: string to call GnuPG with

    passphrase: If set, and no passphrase file object is sent in to run(),
    then GnuPGInterface will take care of sending the passphrase to GnuPG,
    instead of having the user sent it in manually.
    Convience method.

    pid: After run is called, will be set to the pid of the
    running GnuPG process.

    options: Object of type Options.  Attribute-setting in options determines
    the command-line options used when calling GnuPG.
    """

    def __init__(self):
        self.call = 'gpg'
        self.passphrase = None
        self.options = Options()
    
    def run(self, gnupg_commands, **fh_requests):
        """Standard call to a GnuPGInterface object.
	Invokes GnuPG, attaching filehandles as the user desires.
	After calling run(), one should call os.waitpid()
	to clean-up the process.
	
	This is where passphrase-helping comes in.
        """
        
        for std in _stds: fh_requests.setdefault( std, getattr( sys, std ) )
        handle_passphrase = 0
        
        if self.passphrase != None and not fh_requests.has_key( 'passphrase' ):
            handle_passphrase = 1
            fh_requests['passphrase'] = 1

        process = self._attach_fork_exec(gnupg_commands, fh_requests)

        if handle_passphrase:
            passphrase_fh = process.handles['passphrase']
            passphrase_fh.write( self.passphrase )
            passphrase_fh.close()
            del process.handles['passphrase']
        
        return process
    
    
    def _attach_fork_exec(self, gnupg_commands, fh_requests):
        """This is like run(), but without the passphrase-helping
	(note that run() calls this)"""
	
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
        
        if process.pid == 0: self._as_child(process, gnupg_commands)
        return self._as_parent(process)


    def _as_parent(self, process):
        """Stuff run after forking in parent"""
        for p in process._pipes.values():
            if not p[_direct]: os.close( p[_child] )
            
        for k, p in process._pipes.items():
            if not p[_direct]: process.handles[k] = os.fdopen( p[_parent], _fd_modes[k] )

        del process._pipes

        return process


    def _as_child(self, process, gnupg_commands):
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
            
        command = [ self.call ] + fd_args + self.options.get_args() + gnupg_commands
        os.execvp( command[0], command )

        

class Options:
    """Objects which encompass options passed to GnuPG.
    Responsible for determining command-line arguments which
    are based on options."""
    
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
        return self.get_meta_args() + self.get_option_args() + self.extra_args

    def get_option_args( self ):
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
        args = []

        if self.meta_pgp_5_compatible: args.extend( [ '--compress-algo', '1',
                                                      '--force-v3-sigs'
                                                      ] )
        if self.meta_pgp_2_compatible: args.append( '--rfc1991' )
        if not self.meta_interactive: args.extend( [ '--batch', '--no-tty' ] )

        return args


class Process:
    """Used to return information about the spawned GnuPG process"""
    
    def __init__(self):
        self._pipes = {}
        self.handles = {}
        self.pid = None


def _test():
    """Send some test input to GnuPG, get it back out, and see
    if it matches.  We'll use --store since that doesn't
    require a keyring or such."""
    gnupg = GnuPGInterface()
    gnupg.options.armor = 1
    gnupg.options.extra_args.append( '--no-secmem-warning' )
    
    input1 = """To learn what is good and what is to be valued,
    those truths which cannot be shaken or changed"""
    
    process1 = gnupg.run( [ '--store' ], stdin = 1, stdout = 1 )    
    process1.handles['stdin'].write( input1 )
    process1.handles['stdin'].close()

    output1 = process1.handles['stdout'].read()
    process1.handles['stdout'].close()
    assert( os.waitpid( process1.pid, 0 )[1] == 0 )
    
    process2 = gnupg.run( [ '--decrypt' ], stdin = 1, stdout = 1 )
    process2.handles['stdin'].write( output1 )
    process2.handles['stdin'].close()
    
    output2 = process2.handles['stdout'].read()
    process2.handles['stdout'].close()
    assert( os.waitpid( process2.pid, 0 )[1] == 0 )
    
    assert( input1 == output2 )

    print "okay"
    
if __name__ == '__main__':
    _test()
