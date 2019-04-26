"""
SSH-agent protocol implementation library.

See https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent and
http://ptspts.blogspot.co.il/2010/06/how-to-use-ssh-agent-programmatically.html
for more details.
The server's source code can be found here:
https://github.com/openssh/openssh-portable/blob/master/authfd.c
"""
import io
import logging

from . import formats, util

log = logging.getLogger(__name__)


# Taken from https://github.com/openssh/openssh-portable/blob/master/authfd.h
# Added extension mesage types from https://tools.ietf.org/html/draft-miller-ssh-agent-02#page-13
COMMANDS = dict(
    SSH_AGENTC_REQUEST_RSA_IDENTITIES=1,
    SSH_AGENT_RSA_IDENTITIES_ANSWER=2,
    SSH_AGENTC_RSA_CHALLENGE=3,
    SSH_AGENT_RSA_RESPONSE=4,
    SSH_AGENT_FAILURE=5,
    SSH_AGENT_SUCCESS=6,
    SSH_AGENTC_ADD_RSA_IDENTITY=7,
    SSH_AGENTC_REMOVE_RSA_IDENTITY=8,
    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES=9,
    SSH2_AGENTC_REQUEST_IDENTITIES=11,
    SSH2_AGENT_IDENTITIES_ANSWER=12,
    SSH2_AGENTC_SIGN_REQUEST=13,
    SSH2_AGENT_SIGN_RESPONSE=14,
    SSH2_AGENTC_ADD_IDENTITY=17,
    SSH2_AGENTC_REMOVE_IDENTITY=18,
    SSH2_AGENTC_REMOVE_ALL_IDENTITIES=19,
    SSH_AGENTC_ADD_SMARTCARD_KEY=20,
    SSH_AGENTC_REMOVE_SMARTCARD_KEY=21,
    SSH_AGENTC_LOCK=22,
    SSH_AGENTC_UNLOCK=23,
    SSH_AGENTC_ADD_RSA_ID_CONSTRAINED=24,
    SSH2_AGENTC_ADD_ID_CONSTRAINED=25,
    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED=26,
    SSH_AGENTC_EXTENSION=27,
    SSH_AGENT_EXTENSION_FAILURE=28,
)

EXT_MSGS = [
    'query',
    'filter@trezor.io',
    'add@trezor.io',
    'remove@trezor.io',
    'removeall@trezor.io'
]

def msg_code(name):
    """Convert string name into a integer message code."""
    return COMMANDS[name]


def msg_name(code):
    """Convert integer message code into a string name."""
    ids = {v: k for k, v in COMMANDS.items()}
    return ids[code]


def failure():
    """Return error code to SSH binary."""
    error_msg = util.pack('B', msg_code('SSH_AGENT_FAILURE'))
    return util.frame(error_msg)


def _legacy_pubs(buf):
    """SSH v1 public keys are not supported."""
    leftover = buf.read()
    if leftover:
        log.warning('skipping leftover: %r', leftover)
    code = util.pack('B', msg_code('SSH_AGENT_RSA_IDENTITIES_ANSWER'))
    num = util.pack('L', 0)  # no SSH v1 keys
    return util.frame(code, num)


class Handler:
    """ssh-agent protocol handler."""

    def __init__(self, conn, debug=False, promisc=False):
        """
        Create a protocol handler with specified public keys.

        Use specified signer function to sign SSH authentication requests.
        """
        self.conn = conn
        self.debug = debug
        self.promisc = promisc

        self.methods = {
            msg_code('SSH_AGENTC_REQUEST_RSA_IDENTITIES'): _legacy_pubs,
            msg_code('SSH2_AGENTC_REQUEST_IDENTITIES'): self.list_pubs,
            msg_code('SSH2_AGENTC_SIGN_REQUEST'): self.sign_message,
            msg_code('SSH_AGENTC_EXTENSION'): self.process_extension_message,
        }

    def handle(self, msg):
        """Handle SSH message from the SSH client and return the response."""
        debug_msg = ': {!r}'.format(msg) if self.debug else ''
        log.debug('request: %d bytes%s', len(msg), debug_msg)
        buf = io.BytesIO(msg)
        code, = util.recv(buf, '>B')
        log.debug('received code: %d', code)
        if code not in self.methods:
            log.warning('Unsupported command: %s (%d)', msg_name(code), code)
            return failure()

        method = self.methods[code]
        log.debug('calling %s()', method.__name__)
        reply = method(buf=buf)
        debug_reply = ': {!r}'.format(reply) if self.debug else ''
        log.debug('reply: %d bytes%s', len(reply), debug_reply)
        return reply

    def list_pubs(self, buf):
        """SSH v2 public keys are serialized and returned."""
        assert not buf.read()
        keys = self.conn.parse_public_keys()
        code = util.pack('B', msg_code('SSH2_AGENT_IDENTITIES_ANSWER'))
        log.debug('available keys: %s', [k['name'] for k in keys])

        log.debug("Active filter: %s", self.conn.filter)
        if self.conn.filter:
            #apply filter
            keys_filtered = []
            for k in keys:
                if self.conn.filter[1] in k['name'].decode():
                    keys_filtered.append(k)

            keys = keys_filtered
            log.debug('filtered keys: %s', [k['name'] for k in keys])
            self.conn.clear_filter()

        num = util.pack('L', len(keys))
        for i, k in enumerate(keys):
            log.debug('%2d) %s', i+1, k['fingerprint'])
        pubs = [util.frame(k['blob']) + util.frame(k['name']) for k in keys]
        return util.frame(code, num, *pubs)

    def sign_message(self, buf):
        """
        SSH v2 public key authentication is performed.

        If the required key is not supported, raise KeyError
        If the signature is invalid, raise ValueError
        """
        key = formats.parse_pubkey(util.read_frame(buf))
        log.debug('looking for %s', key['fingerprint'])
        blob = util.read_frame(buf)
        assert util.read_frame(buf) == b''
        assert not buf.read()

        for k in self.conn.parse_public_keys():
            if (k['fingerprint']) == (key['fingerprint']):
                log.debug('using key %r (%s)', k['name'], k['fingerprint'])
                key = k
                break
        else:
            raise KeyError('key not found')

        label = key['name'].decode('utf-8')
        log.debug('signing %d-byte blob with "%s" key', len(blob), label)
        try:
            signature = self.conn.sign(blob=blob, identity=key['identity'])
        except IOError:
            return failure()
        log.debug('signature: %r', signature)

        try:
            sig_bytes = key['verifier'](sig=signature, msg=blob)
            log.info('signature status: OK')
        except formats.ecdsa.BadSignatureError:
            log.exception('signature status: ERROR')
            raise ValueError('invalid ECDSA signature')

        log.debug('signature size: %d bytes', len(sig_bytes))

        data = util.frame(util.frame(key['type']), util.frame(sig_bytes))
        code = util.pack('B', msg_code('SSH2_AGENT_SIGN_RESPONSE'))
        return util.frame(code, data)

    def process_extension_message(self, buf):
        """
        SSH agent extension message handler
        Read content of extension message & execute additional actions according to data payload

        Return success message
        """
        # parse received data
        log.debug("extension message received")
 
        type = util.read_frame(buf).decode()
        log.debug('type: "%s"', type)

        if type == 'query':
            # return list of supported extension message types
            log.debug('sending list of supported extension message types')
            code = util.pack('B', msg_code('SSH_AGENT_SUCCESS'))
            data = util.frame(formats.convert_to_bytes(",".join(EXT_MSGS)))
            return util.frame(code, data)

        elif type == 'filter@trezor.io':
            contents = util.read_frame(buf)
            log.debug('raw contents: %s', contents)
            contents = io.BytesIO(contents)
            user = util.read_frame(contents).decode()
            host = util.read_frame(contents).decode()
            log.debug('contents: %s@%s', user, host)

            if self.promisc:
                self.conn.add_identity(user=user, host=host)

            #apply filter
            self.conn.apply_filter(user=user, host=host)

            # return success message
            log.debug("sending success message")
            code = util.pack('B', msg_code('SSH_AGENT_SUCCESS'))
            return util.frame(code)

        elif type == 'add@trezor.io':
            contents = util.read_frame(buf)
            log.debug('raw contents: %s', contents)
            contents = io.BytesIO(contents)
            user = util.read_frame(contents).decode()
            host = util.read_frame(contents).decode()
            log.debug('contents: %s@%s', user, host)

            #add identity
            self.conn.add_identity(user=user, host=host)

            # return success message
            log.debug("sending success message")
            code = util.pack('B', msg_code('SSH_AGENT_SUCCESS'))
            return util.frame(code)

        elif type == 'remove@trezor.io':
            contents = util.read_frame(buf)
            log.debug('raw contents: %s', contents)
            contents = io.BytesIO(contents)
            user = util.read_frame(contents).decode()
            host = util.read_frame(contents).decode()
            log.debug('contents: %s@%s', user, host)

            # remove identity
            self.conn.remove_identity(user=user, host=host)

            # return success message
            log.debug("sending success message")
            code = util.pack('B', msg_code('SSH_AGENT_SUCCESS'))
            return util.frame(code)

        elif type == 'removeall@trezor.io':
            # remove all identities
            self.conn.remove_all_identities()

            # return success message
            log.debug("sending success message")
            code = util.pack('B', msg_code('SSH_AGENT_SUCCESS'))
            return util.frame(code)

        else:
            # return failure due to unknnown message type
            log.debug('unknown extension message type')
            code = util.pack('B', msg_code('SSH_AGENT_FAILURE'))
            return  util.frame(code)


class Sender:
    """ssh-agent protocol sender."""

    def __init__(self, conn, socket):
        """Create a protocol sender"""
        self.conn = conn
        self.socket = socket
        self.identity = None

        self.methods = {
            'query': self.send_extension_query_message,
            'filter': self.send_extension_filter_message,
            'add': self.send_extension_add_identity_message,
            'remove': self.send_extension_remove_identity_message,
            'removeall': self.send_extension_remove_all_identities_message,
        }

    def send(self, message, identity=None):
        """Send SSH extension message to SSH agent and return the response."""
        if message not in self.methods:
            log.warning('Unsupported command: %s', message)
            return failure()

        self.identity = identity
        method = self.methods[message]
        log.debug('calling %s()', method.__name__)
        method()

        msg = util.read_frame(self.socket)

        buf = io.BytesIO(msg)
        code, = util.recv(buf, '>B')
        log.debug('received response code %s', code)

        if message == 'query':
            if code == msg_code('SSH_AGENT_SUCCESS'):
                content = util.read_frame(buf).decode()
                log.debug('supported extension messages: %s', content)
                return content.split(',')
            else:
                return []
        else:
            if code == msg_code('SSH_AGENT_SUCCESS'):
                return 0
            else:
                return 1

    def send_extension_query_message(self):
        """Create SSH agent extension query message and receive reply."""
        log.debug('Request supported extension method list')
        code = util.pack('B', msg_code('SSH_AGENTC_EXTENSION'))
        type = util.frame(formats.convert_to_bytes('query'))
        message = util.frame(code, type)
        util.send(self.socket, message)

    def send_extension_filter_message(self):
        """Create SSH agent extension 'filter' message and receive reply."""
        log.debug('Filter agent available keys')
        code = util.pack('B', msg_code('SSH_AGENTC_EXTENSION'))
        type = util.frame(formats.convert_to_bytes('filter@trezor.io'))
        u = util.frame(formats.convert_to_bytes(self.identity.identity_dict.get('user', '')))
        h = util.frame(formats.convert_to_bytes(self.identity.identity_dict.get('host', '')))
        contents = util.frame(u, h)
        message = util.frame(code, type, contents)
        util.send(self.socket, message)

    def send_extension_add_identity_message(self):
        """Create SSH agent extension 'add identity' message and receive reply."""
        log.debug('Add identity to agent')
        code = util.pack('B', msg_code('SSH_AGENTC_EXTENSION'))
        type = util.frame(formats.convert_to_bytes('add@trezor.io'))
        u = util.frame(formats.convert_to_bytes(self.identity.identity_dict.get('user', '')))
        h = util.frame(formats.convert_to_bytes(self.identity.identity_dict.get('host', '')))
        contents = util.frame(u, h)
        message = util.frame(code, type, contents)
        util.send(self.socket, message)

    def send_extension_remove_identity_message(self):
        """Create SSH agent extension 'remove identity' message and receive reply."""
        log.debug('Remove identity from agent')
        code = util.pack('B', msg_code('SSH_AGENTC_EXTENSION'))
        type = util.frame(formats.convert_to_bytes('remove@trezor.io'))
        u = util.frame(formats.convert_to_bytes(self.identity.identity_dict.get('user', '')))
        h = util.frame(formats.convert_to_bytes(self.identity.identity_dict.get('host', '')))
        contents = util.frame(u, h)
        message = util.frame(code, type, contents)
        util.send(self.socket, message)

    def send_extension_remove_all_identities_message(self):
        """Create SSH agent extension 'remove all identities' message and receive reply."""
        log.debug('Remove identity from agent')
        code = util.pack('B', msg_code('SSH_AGENTC_EXTENSION'))
        type = util.frame(formats.convert_to_bytes('removeall@trezor.io'))
        message = util.frame(code, type)
        util.send(self.socket, message)






