"""SSH-agent implementation using hardware authentication devices."""
import contextlib
import functools
import io
import logging
import os
import socket
import re
import signal
import subprocess
import sys
import tempfile
import threading

import pkg_resources
import configargparse
import daemon

from pathlib import Path
from sshconf import read_ssh_config, empty_ssh_config
import stat
import shutil

from .. import device, formats, server, util
from . import client, protocol

log = logging.getLogger(__name__)

UNIX_SOCKET_TIMEOUT = 0.1


def ssh_args(conn):
    """Create SSH command for connecting specified server."""
    I, = conn.identities
    identity = I.identity_dict
    pubkey_tempfile, = conn.public_keys_as_files()

    args = []
    if 'port' in identity:
        args += ['-p', identity['port']]
    if 'user' in identity:
        args += ['-l', identity['user']]

    args += ['-o', 'IdentityFile={}'.format(pubkey_tempfile.name)]
    args += ['-o', 'IdentitiesOnly=true']
    return args + [identity['host']]


def mosh_args(conn):
    """Create SSH command for connecting specified server."""
    I, = conn.identities
    identity = I.identity_dict

    args = []
    if 'port' in identity:
        args += ['-p', identity['port']]
    if 'user' in identity:
        args += [identity['user']+'@'+identity['host']]
    else:
        args += [identity['host']]

    return args


def _to_unicode(s):
    try:
        return unicode(s, 'utf-8')
    except NameError:
        return s


def create_agent_parser(device_type):
    """Create an ArgumentParser for this tool."""
    epilog = ('See https://github.com/romanz/trezor-agent/blob/master/'
              'doc/README-SSH.md for usage examples.')
    p = configargparse.ArgParser(default_config_files=['~/.ssh/agent.config'],
                                 epilog=epilog)
    p.add_argument('-v', '--verbose', default=0, action='count')

    agent_package = device_type.package_name()
    resources_map = {r.key: r for r in pkg_resources.require(agent_package)}
    resources = [resources_map[agent_package], resources_map['libagent']]
    versions = '\n'.join('{}={}'.format(r.key, r.version) for r in resources)
    p.add_argument('--version', help='print the version info',
                   action='version', version=versions)

    curve_names = [name for name in formats.SUPPORTED_CURVES]
    curve_names = ', '.join(sorted(curve_names))
    p.add_argument('-e', '--ecdsa-curve-name', metavar='CURVE',
                   default=formats.CURVE_NIST256,
                   help='specify ECDSA curve name: ' + curve_names)
    p.add_argument('--timeout',
                   default=UNIX_SOCKET_TIMEOUT, type=float,
                   help='timeout for accepting SSH client connections')
    p.add_argument('--debug', default=False, action='store_true',
                   help='log SSH protocol messages for debugging.')
    p.add_argument('--log-file', type=str,
                   help='Path to the log file (to be written by the agent).')
    p.add_argument('--sock-path', type=str,
                   help='Path to the UNIX domain socket of the agent.')
    p.add_argument('--save', '-S', default=False, action='store_true',
                   help='Save all pubkeys to ~/.ssh/{hostname}.pub')
    p.add_argument('--create-ssh-config', '-C', type=str, default=None,
                   help='Create ssh config for loaded pubkeys')

    p.add_argument('--pin-entry-binary', type=str, default='pinentry',
                   help='Path to PIN entry UI helper.')
    p.add_argument('--passphrase-entry-binary', type=str, default='pinentry',
                   help='Path to passphrase entry UI helper.')
    p.add_argument('--cache-expiry-seconds', type=float, default=float('inf'),
                   help='Expire passphrase from cache after this duration.')

    g = p.add_mutually_exclusive_group()
    g.add_argument('-d', '--daemonize', default=False, action='store_true',
                   help='Daemonize the agent and print its UNIX socket path')
    g.add_argument('-f', '--foreground', default=False, action='store_true',
                   help='Run agent in foreground with specified UNIX socket path')
    g.add_argument('-s', '--shell', default=False, action='store_true',
                   help=('run ${SHELL} as subprocess under SSH agent, allowing '
                         'regular SSH-based tools to be used in the shell'))
    g.add_argument('-c', '--connect', default=False, action='store_true',
                   help='connect to specified host via SSH')
    g.add_argument('--mosh', default=False, action='store_true',
                   help='connect to specified host via using Mosh')

    p.add_argument('identity', type=_to_unicode, default=None, nargs='?',
                   help='proto://[user@]host[:port][/path]')
    p.add_argument('command', type=str, nargs='*', metavar='ARGUMENT',
                   help='command to run under the SSH agent')

    p.add_argument('-F', '--filter', default=False, action='store_true',
                   help='Send agent filter extension query')
    p.add_argument('-a', '--add', default=False, action='store_true',
                   help='Send agent add extension query')
    p.add_argument('-r', '--remove', default=False, action='store_true',
                   help='Send agent remove extension query')
    p.add_argument('-R', '--removeall', default=False, action='store_true',
                   help='Send agent remove all extension query')
    p.add_argument('-E', '--eager', default=False, action='store_true',
                   help='Set agent to eager mode - use filter messages as add message')

    return p


@contextlib.contextmanager
def serve(handler, sock_path, timeout=UNIX_SOCKET_TIMEOUT):
    """
    Start the ssh-agent server on a UNIX-domain socket.

    If no connection is made during the specified timeout,
    retry until the context is over.
    """
    ssh_version = subprocess.check_output(['ssh', '-V'],
                                          stderr=subprocess.STDOUT)
    log.debug('local SSH version: %r', ssh_version)
    environ = {'SSH_AUTH_SOCK': sock_path, 'SSH_AGENT_PID': str(os.getpid())}
    device_mutex = threading.Lock()
    with server.unix_domain_socket_server(sock_path) as sock:
        sock.settimeout(timeout)
        quit_event = threading.Event()
        handle_conn = functools.partial(server.handle_connection,
                                        handler=handler,
                                        mutex=device_mutex)
        kwargs = dict(sock=sock,
                      handle_conn=handle_conn,
                      quit_event=quit_event)
        with server.spawn(server.server_thread, kwargs):
            try:
                yield environ
            finally:
                log.debug('closing server')
                quit_event.set()


def run_server(conn, command, sock_path, debug, timeout, eager):
    """Common code for run_agent and run_git below."""
    ret = 0
    try:
        handler = protocol.Handler(conn=conn, debug=debug, eager=eager)
        with serve(handler=handler, sock_path=sock_path,
                   timeout=timeout) as env:
            if command:
                ret = server.run_process(command=command, environ=env)
            else:
                signal.pause()  # wait for signal (e.g. SIGINT)
    except KeyboardInterrupt:
        log.info('server stopped')
    return ret


def handle_connection_error(func):
    """Fail with non-zero exit code."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except device.interface.NotFoundError as e:
            log.error('Connection error (try unplugging and replugging your device): %s', e)
            return 1
    return wrapper


def parse_config(contents):
    """Parse config file into a list of Identity objects."""
    for identity_str, curve_name in re.findall(r'\<(.*?)\|(.*?)\>', contents):
        yield device.interface.Identity(identity_str=identity_str,
                                        curve_name=curve_name)

def parse_config_identity_files(contents):
    identities = ""
    for identity_file in re.findall(r'^\s+(?!#+)\s+IdentityFile (.*?\.pub)$', contents, re.MULTILINE):
        identity_file_path = Path(identity_file).expanduser().absolute()
        log.debug('identity_file %s', identity_file_path)
        id_file_contents = open(identity_file_path, 'rb').read().decode('utf-8')
        identities += id_file_contents
    return identities


def import_public_keys(contents):
    """Load (previously exported) SSH public keys from a file's contents."""
    for line in io.StringIO(contents):
        # Verify this line represents valid SSH public key
        formats.import_public_key(line)
        yield line


class JustInTimeConnection:
    """Connect to the device just before the needed operation."""

    def __init__(self, conn_factory, identities, public_keys=None):
        """Create a JIT connection object."""
        self.conn_factory = conn_factory
        self.identities = identities
        self.public_keys_cache = public_keys
        self.public_keys_tempfiles = []
        self.filter = []
        # load identities which are not loadeed from pubkeys
        for i in identities:
            self.add_identity(user=i.identity_dict['user'],
                              host=i.identity_dict['host'],
                              curve=i.curve_name)

    def public_keys(self):
        """Return a list of SSH public keys (in textual format)."""
        if not self.public_keys_cache and self.identities:
            conn = self.conn_factory()
            self.public_keys_cache = conn.export_public_keys(self.identities)
        return self.public_keys_cache

    def parse_public_keys(self):
        """Parse SSH public keys into dictionaries."""
        public_keys = [formats.import_public_key(pk)
                       for pk in self.public_keys()]
        for pk, identity in zip(public_keys, self.identities):
            pk['identity'] = identity
        return public_keys

    def public_keys_as_files(self):
        """Store public keys as temporary SSH identity files."""
        if not self.public_keys_tempfiles:
            for pk in self.public_keys():
                f = tempfile.NamedTemporaryFile(prefix='trezor-ssh-pubkey-', mode='w')
                f.write(pk)
                f.flush()
                self.public_keys_tempfiles.append(f)

        return self.public_keys_tempfiles

    def add_identity(self, user, host, curve=formats.CURVE_NIST256):
        identity_str = user + "@" + host
        identity = device.interface.Identity(
            identity_str=identity_str, curve_name=curve)
        identity.identity_dict['proto'] = u'ssh'

        identity_str = identity.to_string()
        present = [pk for pk in self.public_keys() if identity_str in pk]
        if not present:
            log.debug('Adding identity: %s', identity.to_string())
            #add it to self.identities
            self.identities.append(identity)

            #load it to self.public_keys_cache
            conn = self.conn_factory()
            added_pubkey = conn.export_public_keys([identity])
            self.public_keys_cache.extend(added_pubkey)

    def remove_identity(self, user, host, curve=formats.CURVE_NIST256):
        identity_str = user + "@" + host

        #remove it from self.identities & self.public_keys_cache
        self.identities = [i for i in self.identities if identity_str not in i.to_string()]
        self.public_keys_cache = [i for i in self.public_keys_cache if identity_str not in i]

    def remove_all_identities(self):
        self.identities = []
        self.public_keys_cache = []
        self.public_keys_tempfiles = []
        self.filter = []

    def sign(self, blob, identity):
        """Sign a given blob using the specified identity on the device."""
        conn = self.conn_factory()
        return conn.sign_ssh_challenge(blob=blob, identity=identity)

    def save_public_keys_as_files(self):
        """Store public keys as permanent SSH identity files in ~/ssh/ ."""
        for I in self.identities:
            identity_filename = Path('~/.ssh/' + I.identity_dict['host'] + '.pub').expanduser().absolute()
            if not identity_filename.is_file():
                conn = self.conn_factory()
                f = open(identity_filename, "w")
                pubkey = conn.export_public_keys([I])[0]
                log.debug("pubkeys: %s", pubkey)
                f.write(pubkey)
                f.flush()

    def update_ssh_config(self, filename):
        """Insert host config into ssh config if not present."""
        self.save_public_keys_as_files()
        if filename is None:
            filename = Path('~/.ssh/config').expanduser().absolute()

        backup = str(filename) + ".backup"
        shutil.copy2(filename, backup)
        st = os.stat(filename)
        os.chown(backup, st[stat.ST_UID], st[stat.ST_GID])
        os.chmod(backup, 0o600)

        c = read_ssh_config(filename)
        for I in self.identities:
            identity_filename = Path('~/.ssh/' + I.identity_dict['host'] + '.pub').expanduser().absolute()
            log.debug('ssh config host %s: %s', I.identity_dict['host'], c.host(I.identity_dict['host']))
            if not c.host(I.identity_dict['host']):
                c.add(I.identity_dict['host'], Hostname=I.identity_dict['host'], User=I.identity_dict['user'],
                      IdentityFile=identity_filename)
            else:
                c.set(I.identity_dict['host'], Hostname=I.identity_dict['host'], User=I.identity_dict['user'],
                      IdentityFile=identity_filename)

        c.write(filename)

    def apply_filter(self, user, host):
        self.filter = [user, host]

    def clear_filter(self):
        self.filter = []


@contextlib.contextmanager
def _dummy_context():
    yield


def _get_sock_path(args):
    sock_path = args.sock_path
    if not sock_path:
        if args.foreground:
            log.error('running in foreground mode requires specifying UNIX socket path')
            sys.exit(1)
        else:
            sock_path = tempfile.mktemp(prefix='trezor-ssh-agent-')
    return sock_path


def agent_supports_extension(conn, message_type):
    """Query agetn of support specified extension message"""
    ssh_auth_sock = os.environ['SSH_AUTH_SOCK']
    if not ssh_auth_sock:
        return
    else:
        log.debug('SSH_AUTH_SOCK: %s', ssh_auth_sock)
        agent_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        agent_socket.connect(ssh_auth_sock)

        sender = protocol.Sender(conn=conn, socket=agent_socket)
        messages = sender.send(message='query')

        agent_socket.close()

        return message_type in messages


def send_extension_msg(conn, message, identity=None):
    """Send extension query to agent"""
    ssh_auth_sock = os.environ['SSH_AUTH_SOCK']
    if not ssh_auth_sock:
        return
    else:
        log.debug('SSH_AUTH_SOCK: %s', ssh_auth_sock)
        agent_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        agent_socket.connect(ssh_auth_sock)

        sender = protocol.Sender(conn=conn, socket=agent_socket)
        ret = sender.send(message=message, identity=identity)

        agent_socket.close()
    return ret


@handle_connection_error
def main(device_type):
    """Run ssh-agent using given hardware client factory."""
    args = create_agent_parser(device_type=device_type).parse_args()
    util.setup_logging(verbosity=args.verbose, filename=args.log_file)

    public_keys = []
    identities = []
    filename = None
    if args.identity:
        if args.identity.startswith('/'):
            filename = args.identity
            log.debug('ssh config path: %s', filename)
            contents = open(filename, 'rb').read().decode('utf-8')
            # Allow loading previously exported SSH public keys
            if filename.endswith('.pub'):
                public_keys = list(import_public_keys(contents))
                identities = list(parse_config(contents))
            else:
                identity_files = parse_config_identity_files(contents)
                public_keys = list(import_public_keys(identity_files))
                identities = list(parse_config(identity_files+contents))
        else:
            filename = args.create_ssh_config
            identities = [device.interface.Identity(
                identity_str=args.identity, curve_name=args.ecdsa_curve_name)]
        for index, identity in enumerate(identities):
            identity.identity_dict['proto'] = u'ssh'
            log.info('identity #%d: %s', index, identity.to_string())

    # override default PIN/passphrase entry tools (relevant for TREZOR/Keepkey):
    device_type.ui = device.ui.UI(device_type=device_type, config=vars(args))
    device_type.ui.cached_passphrase_ack = util.ExpiringCache(
        args.cache_expiry_seconds)

    conn = JustInTimeConnection(
        conn_factory=lambda: client.Client(device_type()),
        identities=identities, public_keys=public_keys)

    if args.save:
        conn.save_public_keys_as_files()

    if args.create_ssh_config:
        conn.update_ssh_config(filename)

    sock_path = _get_sock_path(args)
    command = args.command
    context = _dummy_context()
    if args.connect:
        command = ['ssh'] + ssh_args(conn) + args.command
    elif args.mosh:
        command = ['mosh'] + mosh_args(conn) + args.command
    elif args.daemonize:
        out = 'SSH_AUTH_SOCK={0}; export SSH_AUTH_SOCK;\n'.format(sock_path)
        sys.stdout.write(out)
        sys.stdout.flush()
        context = daemon.DaemonContext()
        log.info('running the agent as a daemon on %s', sock_path)
    elif args.foreground:
        log.info('running the agent on %s', sock_path)

    use_shell = bool(args.shell)
    if use_shell:
        command = os.environ['SHELL']
        sys.stdin.close()

    if args.filter:
        if identities and agent_supports_extension(conn, 'filter@trezor.io'):
            send_extension_msg(conn=conn, message='filter', identity=identities[0])
    elif args.add:
        if identities and agent_supports_extension(conn, 'add@trezor.io'):
            [send_extension_msg(conn=conn, message='add', identity=i) for i in identities]
    elif args.remove:
        if identities and agent_supports_extension(conn, 'remove@trezor.io'):
            [send_extension_msg(conn=conn, message='remove', identity=i) for i in identities]
    elif args.removeall:
        if agent_supports_extension(conn, 'removeall@trezor.io'):
            send_extension_msg(conn=conn, message='removeall')
    elif command or args.daemonize or args.foreground:
        with context:
            return run_server(conn=conn, command=command, sock_path=sock_path,
                              debug=args.debug, timeout=args.timeout, eager=args.eager)
    else:
        for pk in conn.public_keys():
            sys.stdout.write(pk)
        return 0  # success exit code
