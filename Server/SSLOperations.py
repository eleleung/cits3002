import os
import sys
import socket
import config
from OpenSSL import SSL
import verify

def create_context():
    ctx     = SSL.Context(SSL.SSLv3_METHOD)

    # check we have both a pkey and a cert and if found add them to the context
    try:
        ctx.use_privatekey_file(os.path.join(config.root, 'server.pkey'))
    except SSL.Error as error:
        print('server.pkey could not be found \nPlace in directory: ' + str(config.root) + "\n", file=sys.stderr)
        try:
            ctx.use_certificate_file(os.path.join(config.root, 'server.cert'))
        except SSL.Error as error:
            print('server.cert could not be found \nPlace in directory: ' + str(config.root) + "\n", file=sys.stderr)
            sys.exit()
        sys.exit()
    try:
        ctx.use_certificate_file(os.path.join(config.root, 'server.cert'))
    except SSL.Error as error:
        print('server.cert could not be found \nPlace in directory: ' + str(config.root) + "\n", file=sys.stderr)
        sys.exit()
    ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT | SSL.VERIFY_CLIENT_ONCE, verify.checkcerts)
    return ctx
