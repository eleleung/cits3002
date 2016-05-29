import os
import socket
import config
from OpenSSL import SSL

def createSSL(ctx):
    socketRaw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # wrap socket
    socketSSL = SSL.Connection(ctx, socketRaw)
    socketSSL.set_accept_state()
    # set up the sockets
    host = socket.gethostbyname(socket.gethostname())
    try:
        socketSSL.bind(("localhost", config.port))
    except socket.error as msg:
        print(config.pcolours.WARNING + 'Bind failed, socket error message: ' + str(msg))
        sys.exit()
    socketSSL.listen(config.backlog)

    # courtesy statement
    print(config.pcolours.OKBLUE + "Server running on: \nHost: " + host + "\nPort: " + str(config.port))
    return(socketSSL)
